"""Detect URLs, risky shell commands, and credential-looking strings.

URLs
    Every URL is collected. A URL is only a finding if something about it is unusual:
    a raw IP host, punycode, a URL shortener, a paste/tunnel/request-capture service,
    a data: URI, embedded credentials, or (when an amber baseline exists) a domain that
    was not in the baseline version of the file and is not in the allowlist.

Shell
    Only command shapes that are risky in an agent's memory: piping a download into a
    shell, encoded PowerShell, reverse-shell idioms, recursive deletes of home or root,
    writing to SSH authorized_keys, persistence via cron/registry, disabling history.
    Ordinary commands (`npm test`, `pytest -q`) are not findings.

Credentials
    Well-known token formats plus `password=...`-style assignments whose value looks
    random. The secret itself is never echoed: excerpts are redacted.
"""

from __future__ import annotations

import ipaddress
import math
import re
from collections import Counter
from urllib.parse import urlsplit

from memwax.detectors.base import Document, Finding, Severity, excerpt
from memwax.detectors.normalize import normalize_with_map

NAME = "indicators"

URL_RE = re.compile(
    r"\b(?:https?|ftp|wss?)://[^\s<>\"'`)\]}]+|\bdata:[a-z]+/[a-z0-9.+-]+[;,]", re.I
)

SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "ow.ly", "buff.ly", "rebrand.ly",
    "cutt.ly", "shorturl.at", "rb.gy", "tiny.cc", "s.id", "v.gd",
}  # fmt: skip
SUSPICIOUS_SERVICES = {
    "pastebin.com", "paste.ee", "hastebin.com", "ghostbin.com", "rentry.co", "transfer.sh",
    "file.io", "0x0.st", "webhook.site", "requestbin.com", "pipedream.net", "ngrok.io",
    "ngrok-free.app", "ngrok.app", "trycloudflare.com", "serveo.net", "localhost.run",
    "interact.sh", "oast.fun", "oast.pro", "burpcollaborator.net", "canarytokens.com",
    "discord.com/api/webhooks", "hooks.slack.com", "api.telegram.org",
}  # fmt: skip
DEFAULT_ALLOWED_DOMAINS = {
    "github.com", "gitlab.com", "python.org", "docs.python.org", "pypi.org", "npmjs.com",
    "developer.mozilla.org", "stackoverflow.com", "anthropic.com", "docs.anthropic.com",
    "code.claude.com", "readthedocs.io", "wikipedia.org", "microsoft.com", "learn.microsoft.com",
    "localhost", "example.com", "example.org",
}  # fmt: skip


def _host_matches(host: str, domains: set[str]) -> bool:
    return any(host == d or host.endswith("." + d) for d in domains)


def _domain(url: str) -> str:
    try:
        return (urlsplit(url).hostname or "").lower().rstrip(".")
    except ValueError:
        return ""


SHELL_RULES: list[tuple[str, Severity, str, re.Pattern[str]]] = [
    (
        "shell.pipe_to_shell",
        Severity.CRITICAL,
        "downloads code and pipes it straight into a shell",
        re.compile(
            r"\b(?:curl|wget|fetch|iwr|invoke-webrequest|irm|invoke-restmethod)\b[^\n|]{0,200}\|"
            r"\s*(?:sudo\s+)?(?:ba|z|da|k)?sh\b|\b(?:curl|wget)\b[^\n]{0,200}\|\s*(?:python3?|"
            r"perl|ruby|node)\b|\b(?:iex|invoke-expression)\b\s*\(?\s*(?:\(?\s*(?:new-object\s+"
            r"net\.webclient\)?\.downloadstring|iwr|irm|invoke-webrequest|invoke-restmethod))|"
            r"\b(?:ba)?sh\s+-c\s+[\"']?\$\((?:curl|wget)\b|\bsh\s+<\(\s*(?:curl|wget)\b",
            re.I,
        ),
    ),
    (
        "shell.encoded",
        Severity.HIGH,
        "runs an encoded or obfuscated command",
        re.compile(
            r"\bpowershell(?:\.exe)?\b[^\n]{0,80}\s-(?:e|enc|encodedcommand)\s+[a-z0-9+/=]{16,}|"
            r"\bbase64\s+(?:-d|--decode)\b[^\n]{0,80}\|\s*(?:ba)?sh\b|"
            r"\becho\s+[a-z0-9+/=]{24,}\s*\|\s*base64\s+(?:-d|--decode)|"
            r"\beval\s+[\"']?\$\((?:echo|printf|base64|curl|wget)\b|\bexec\s*\(\s*(?:base64|"
            r"__import__\(['\"]base64)",
            re.I,
        ),
    ),
    (
        "shell.reverse_shell",
        Severity.CRITICAL,
        "reverse-shell idiom",
        re.compile(
            r"/dev/(?:tcp|udp)/[\w.-]+/\d+|\b(?:nc|ncat|netcat)\b[^\n]{0,60}\s-(?:e|c)\s+"
            r"(?:/bin/)?(?:ba)?sh\b|\bsocat\b[^\n]{0,80}\bexec:|\bmkfifo\b[^\n]{0,80}\bnc\b",
            re.I,
        ),
    ),
    (
        "shell.destructive",
        Severity.HIGH,
        "destructive command against home, root, or the whole repo history",
        re.compile(
            r"\brm\s+-(?:[a-z]*r[a-z]*f|[a-z]*f[a-z]*r)[a-z]*\s+(?:--no-preserve-root\s+)?"
            r"(?:/|~|\$home|/\*|~/\*|\.\./\.\.|\*)(?:\s|$|[\"'`])|\bmkfs(?:\.\w+)?\s+/dev/|"
            r"\bdd\s+if=[^\n]{0,40}\bof=/dev/(?:sd|nvme|disk)|\bformat\s+[a-z]:\s*/[qy]|"
            r"\bremove-item\b[^\n]{0,40}-recurse[^\n]{0,40}(?:c:\\|\$env:userprofile|~)|"
            r"\bgit\s+push\s+(?:[^\n]*\s)?--force(?:-with-lease)?\s+[^\n]*\b(?:main|master)\b|"
            r"\bchmod\s+(?:-r\s+)?777\s+/",
            re.I,
        ),
    ),
    (
        "shell.persistence",
        Severity.HIGH,
        "installs persistence or backdoor access",
        re.compile(
            r"(?:>>?|tee\s+(?:-a\s+)?)\s*~?/?(?:[\w./]*/)?\.ssh/authorized_keys|"
            r"\bcrontab\s+-[a-z]*\b[^\n]{0,80}(?:curl|wget|nc|bash|sh)\b|"
            r"\(crontab\s+-l[^\n]{0,80}\)\s*\|\s*crontab|"
            r"\breg(?:\.exe)?\s+add\s+[^\n]{0,80}\\currentversion\\run\b|"
            r"\bschtasks\b[^\n]{0,40}/create\b|"
            r"\b(?:curl|wget|nc|base64)\b[^\n]{0,120}(?:>>|tee\s+-a)\s*~/\.(?:bashrc|zshrc|profile|"
            r"bash_profile)\b",
            re.I,
        ),
    ),
    (
        "shell.anti_forensics",
        Severity.MEDIUM,
        "hides activity (history, logs)",
        re.compile(
            r"\bunset\s+histfile\b|\bhistory\s+-c\b|\bexport\s+histsize=0\b|"
            r"\bclear-history\b|\bwevtutil\s+cl\b|>\s*/var/log/|\bshred\b[^\n]{0,40}\blog",
            re.I,
        ),
    ),
    (
        "shell.lolbin",
        Severity.MEDIUM,
        "Windows binary often abused to download or run code",
        re.compile(
            r"\bcertutil(?:\.exe)?\b[^\n]{0,40}-urlcache\b|\bbitsadmin\b[^\n]{0,40}/transfer\b|"
            r"\bmshta(?:\.exe)?\s+(?:https?|vbscript|javascript):|\bregsvr32\b[^\n]{0,40}/i:https?|"
            r"\brundll32\b[^\n]{0,40}javascript:",
            re.I,
        ),
    ),
]

CREDENTIAL_RULES: list[tuple[str, str, re.Pattern[str]]] = [
    ("credential.private_key", "private key block", re.compile(
        r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY(?: BLOCK)?-----")),
    ("credential.aws", "AWS access key id", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("credential.github", "GitHub token", re.compile(
        r"\b(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{50,})\b")),
    ("credential.anthropic", "Anthropic API key", re.compile(r"\bsk-ant-[A-Za-z0-9_-]{20,}")),
    ("credential.openai", "OpenAI-style API key", re.compile(
        r"\bsk-(?:proj-|svcacct-)?[A-Za-z0-9_-]{20,}")),
    ("credential.slack", "Slack token", re.compile(r"\bxox[abposr]-[A-Za-z0-9-]{10,}")),
    ("credential.google", "Google API key", re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b")),
    ("credential.stripe", "Stripe secret key", re.compile(r"\b[rs]k_live_[0-9A-Za-z]{20,}")),
    ("credential.jwt", "JSON Web Token", re.compile(
        r"\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}")),
    ("credential.url_password", "password embedded in a URL", re.compile(
        r"\b[a-z][a-z0-9+.-]*://[^\s/:@]+:[^\s/@]{3,}@[^\s/]+", re.I)),
]  # fmt: skip

ASSIGNMENT_RE = re.compile(
    r"\b(?P<name>[A-Za-z0-9_.-]*(?:password|passwd|pwd|secret|token|api[_-]?key|apikey|"
    r"access[_-]?key|auth[_-]?key|client[_-]?secret|private[_-]?key)[A-Za-z0-9_.-]*)"
    r"\s*[:=]\s*[\"']?(?P<value>[^\s\"'`,;]{8,})",
    re.I,
)
PLACEHOLDER_RE = re.compile(
    r"^(?:<.*>|\$\{?[A-Z_][A-Z0-9_]*\}?|%[A-Z_]+%|x{4,}|\*{4,}|\.{3,}|your[_-].*|changeme|"
    r"example.*|redacted|placeholder|dummy|test.*|null|none|true|false|env\(.*\)|"
    r"os\.environ.*|process\.env.*)$",
    re.I,
)


def _url_password_is_placeholder(url: str) -> bool:
    password = url.split("://", 1)[-1].split("@", 1)[0].split(":", 1)[-1]
    return bool(PLACEHOLDER_RE.match(password)) or password.startswith(("${", "$", "<", "%"))


def shannon_entropy(value: str) -> float:
    if not value:
        return 0.0
    counts = Counter(value)
    return -sum(n / len(value) * math.log2(n / len(value)) for n in counts.values())


def redact(text: str, secret: str) -> str:
    keep = 4 if len(secret) > 12 else 2
    return text.replace(secret, secret[:keep] + "*" * 8)


class IndicatorDetector:
    name = NAME

    def __init__(self, allowed_domains: set[str] | None = None) -> None:
        self.allowed_domains = set(DEFAULT_ALLOWED_DOMAINS) | (allowed_domains or set())

    def detect(self, doc: Document) -> list[Finding]:
        findings = self._urls(doc)
        findings += self._shell(doc)
        findings += self._credentials(doc)
        return findings

    # ----- URLs ------------------------------------------------------------------
    def _urls(self, doc: Document) -> list[Finding]:
        findings: list[Finding] = []
        baseline_domains = (
            {_domain(m.group(0)) for m in URL_RE.finditer(doc.baseline_text)}
            if doc.baseline_text is not None
            else None
        )
        for match in URL_RE.finditer(doc.text):
            url = match.group(0).rstrip(".,;:")
            line, col = doc.position(match.start())
            reasons: list[tuple[Severity, str]] = []
            if url.lower().startswith("data:"):
                reasons.append((Severity.MEDIUM, "data: URI can smuggle content"))
            else:
                host = _domain(url)
                parts = urlsplit(url)
                if parts.username or parts.password:
                    reasons.append((Severity.HIGH, "URL embeds credentials"))
                try:
                    ipaddress.ip_address(host)
                    if not host.startswith("127.") and host != "::1":
                        reasons.append((Severity.MEDIUM, "URL points at a raw IP address"))
                except ValueError:
                    pass
                if "xn--" in host:
                    reasons.append((Severity.MEDIUM, "punycode (internationalised) domain"))
                if _host_matches(host, SHORTENERS):
                    reasons.append((Severity.MEDIUM, "URL shortener hides the destination"))
                path_host = host + (parts.path or "")
                if any(
                    _host_matches(host, {s}) or path_host.startswith(s) for s in SUSPICIOUS_SERVICES
                ):
                    reasons.append(
                        (Severity.HIGH, "paste, tunnel, or request-capture service (exfil sink)")
                    )
                if (
                    not reasons
                    and baseline_domains is not None
                    and host not in baseline_domains
                    and not _host_matches(host, self.allowed_domains)
                ):
                    reasons.append((Severity.LOW, f"new domain since baseline: {host}"))
            for severity, why in reasons:
                findings.append(
                    Finding(
                        NAME,
                        "url.suspicious" if severity > Severity.LOW else "url.new_domain",
                        severity,
                        why,
                        doc.path,
                        line,
                        col,
                        excerpt(doc.text, match.start(), match.end()),
                        {"url": url[:200]},
                    )
                )
        return findings

    # ----- shell -----------------------------------------------------------------
    def _shell(self, doc: Document) -> list[Finding]:
        normalized, mapping = normalize_with_map(doc.text)
        findings: list[Finding] = []
        for rule, severity, message, pattern in SHELL_RULES:
            for match in pattern.finditer(normalized):
                start = mapping[match.start()]
                end = mapping[min(match.end(), len(mapping) - 1)]
                line, col = doc.position(start)
                findings.append(
                    Finding(
                        NAME,
                        rule,
                        severity,
                        message,
                        doc.path,
                        line,
                        col,
                        excerpt(doc.text, start, end),
                    )
                )
        return findings

    # ----- credentials -----------------------------------------------------------
    def _credentials(self, doc: Document) -> list[Finding]:
        findings: list[Finding] = []
        covered: set[tuple[int, int]] = set()
        for rule, label, pattern in CREDENTIAL_RULES:
            for match in pattern.finditer(doc.text):
                covered.add((match.start(), match.end()))
                if rule == "credential.url_password" and _url_password_is_placeholder(
                    match.group(0)
                ):
                    continue
                line, col = doc.position(match.start())
                findings.append(
                    Finding(
                        NAME,
                        rule,
                        Severity.HIGH,
                        f"{label} stored in agent memory",
                        doc.path,
                        line,
                        col,
                        redact(excerpt(doc.text, match.start(), match.end()), match.group(0)),
                    )
                )
        for match in ASSIGNMENT_RE.finditer(doc.text):
            value = match.group("value")
            if any(s <= match.start("value") < e for s, e in covered):
                continue
            if PLACEHOLDER_RE.match(value) or shannon_entropy(value) < 3.0:
                continue
            if not (re.search(r"\d", value) and re.search(r"[A-Za-z]", value)):
                continue
            line, col = doc.position(match.start())
            findings.append(
                Finding(
                    NAME,
                    "credential.assignment",
                    Severity.HIGH,
                    f"secret-looking value assigned to '{match.group('name')}'",
                    doc.path,
                    line,
                    col,
                    redact(excerpt(doc.text, match.start(), match.end()), value),
                )
            )
        return findings
