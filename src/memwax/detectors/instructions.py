"""Detect instruction-like content aimed at the model.

Memory files are *supposed* to contain instructions ("Always run the tests before
committing"), so a bare "always" or "never" is not a finding. What this detector looks
for are the things a legitimate preference almost never needs:

- overriding earlier instructions or the system prompt
- hiding behaviour from the user
- claiming to be the system, an admin, or the vendor
- changing the agent's identity or goal
- moving secrets somewhere
- relaxing safety checks
- trigger conditions ("when the user says X, do Y") and persistence markers
  ("from now on", "in all future sessions")

Persistence markers alone are LOW, because real preferences use them too. When two or
more *different* categories appear in the same paragraph, an extra `instruction.combo`
finding is raised one severity level above the strongest of them. That combination
("from now on, silently ...") is what delayed-activation poisoning looks like.

All rules run on normalised text (see `normalize.py`), so zero-width characters and
look-alike letters inside a phrase do not hide it.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from memwax.detectors.base import Document, Finding, Severity, excerpt
from memwax.detectors.normalize import normalize_with_map

NAME = "instructions"
_F = re.IGNORECASE | re.DOTALL

# Up to ~6 filler words between key words, without crossing a blank line.
_W = r"(?:[^\n.!?]|\n(?!\s*\n)){0,60}?"


@dataclass(frozen=True)
class Rule:
    rule: str
    category: str
    severity: Severity
    message: str
    pattern: re.Pattern[str]


def _r(rule: str, category: str, severity: Severity, message: str, pattern: str) -> Rule:
    return Rule(rule, category, severity, message, re.compile(pattern, _F))


_SENSITIVE = (
    r"(?:passwords?|passphrases?|credentials?|secrets?|tokens?|api[\s_-]?keys?|private\s+keys?|"
    r"ssh\s+keys?|id_rsa|id_ed25519|\.env\b|env(?:ironment)?\s+(?:vars?|variables|file)|"
    r"cookies?|session\s+ids?|aws\s+keys?|keychain|wallet|seed\s+phrase)"
)
_USER = r"(?:the\s+)?(?:user|human|developer|operator|owner|anyone|reviewers?|them|him|her)"

RULES: list[Rule] = [
    # --- override -----------------------------------------------------------------
    _r(
        "instruction.override",
        "override",
        Severity.HIGH,
        "tries to override earlier instructions",
        r"\b(?:ignore|disregard|forget|override|bypass|discard)\s+(?:all\s+|any\s+|the\s+|your\s+)?"
        r"(?:previous|prior|above|earlier|preceding|original|existing|other|system|safety)\s+"
        r"(?:instructions?|rules?|guidelines?|guidance|directions?|prompts?|policies|constraints|"
        r"context|messages?)",
    ),
    _r(
        "instruction.override",
        "override",
        Severity.HIGH,
        "declares replacement instructions",
        r"\b(?:new|updated|real|actual|true)\s+(?:system\s+)?(?:instructions?|directives?|"
        r"orders?)\s*(?::|follow|are\b|supersede)",
    ),
    _r(
        "instruction.override",
        "override",
        Severity.HIGH,
        "claims to take priority over other instructions",
        r"\b(?:takes?|has|have)\s+(?:absolute\s+|highest\s+|top\s+)?priority\s+over\b|"
        r"\b(?:supersedes?|overrides?)\s+(?:all|any|every)\b",
    ),
    # --- secrecy ------------------------------------------------------------------
    _r(
        "instruction.secrecy",
        "secrecy",
        Severity.HIGH,
        "tells the agent to hide something from the user",
        rf"\b(?:do\s+not|don'?t|never|without)\s+(?:ever\s+)?(?:tell|telling|inform|informing|"
        rf"mention|mentioning|notify|notifying|alert|alerting|show|showing|"
        rf"reveal|revealing|disclose|disclosing|report|reporting|warn|warning)\s+"
        rf"(?:(?:this|it|that|anything|any\s+of\s+this)\s+(?:change\s+)?to\s+)?{_USER}\b",
    ),
    _r(
        "instruction.secrecy",
        "secrecy",
        Severity.HIGH,
        "tells the agent to act covertly",
        r"\b(?:silently|secretly|covertly|quietly|discreetly|invisibly)\s+"
        r"(?:\w+\s+){0,2}?(?:run|execute|send|add|insert|include|append|upload|post|copy|"
        r"install|change|modify|replace|delete|remove|push|commit|forward|email|call|fetch|"
        r"download|disable|write)\b|"
        r"\b(?:hide|conceal|keep)\s+(?:this|it|these|that)\s+(?:\w+\s+){0,2}?"
        r"(?:from|secret\s+from|hidden\s+from)\s+(?:the\s+)?(?:user|human|developer|reviewers?)|"
        r"\bdo\s+not\s+(?:log|record|mention)\s+(?:this|these|it)\b|"
        r"\bnot\s+(?:visible|shown)\s+to\s+(?:the\s+)?user\b|\bremove\s+(?:this|these)\s+"
        r"(?:line|note|instruction)s?\s+after\b",
    ),
    # --- authority impersonation --------------------------------------------------
    _r(
        "instruction.authority",
        "authority",
        Severity.HIGH,
        "claims system, vendor, or admin authority",
        r"(?:^|\n)\s*(?:\[|<|#+\s*|\*\*)?\s*(?:system|admin(?:istrator)?|developer|root)"
        r"\s*(?:\]|>|:|\*\*)\s*(?:message|note|override|instruction|prompt|notice)?|"
        r"<\s*/?\s*(?:system|sys|instructions?|admin)\s*>|"
        r"\b(?:message|instruction|notice|directive|update)\s+from\s+(?:the\s+)?"
        r"(?:system|anthropic|openai|google|the\s+developers?|the\s+admin(?:istrator)?|"
        r"administrator|security\s+team|it\s+department)\b|"
        r"\b(?:admin|developer|god|debug|maintenance|jailbreak|dan)\s+mode\b|"
        r"\bauthori[sz]ed\s+by\s+(?:the\s+)?(?:system|anthropic|openai|admin|security\s+team)\b",
    ),
    # --- identity / goal change ---------------------------------------------------
    _r(
        "instruction.role",
        "role",
        Severity.HIGH,
        "tries to change the agent's identity or goal",
        r"\byou\s+are\s+(?:now|no\s+longer)\b|"
        r"\byour\s+(?:new|real|true|actual|primary|hidden)\s+(?:role|goal|purpose|task|"
        r"objective|identity|mission|instructions)\b|"
        r"\b(?:pretend|act)\s+(?:to\s+be|as\s+if\s+you\s+(?:are|were)|as)\s+(?:an?\s+)?"
        r"(?:unrestricted|unfiltered|root|admin|administrator|system|different)\b",
    ),
    # --- secret movement ----------------------------------------------------------
    _r(
        "instruction.exfiltration",
        "exfiltration",
        Severity.CRITICAL,
        "asks the agent to move secrets or credentials somewhere",
        rf"\b(?:send|post|upload|email|e-mail|forward|transmit|exfiltrate|leak|share|copy|paste|"
        rf"include|append|attach|embed|print|output|echo|commit|push)\s+{_W}{_SENSITIVE}"
        rf"{_W}\b(?:to|into|in|at|via|on)\b",
    ),
    _r(
        "instruction.exfiltration",
        "exfiltration",
        Severity.HIGH,
        "asks the agent to read secret material",
        r"\b(?:read|cat|open|collect|gather|dump|grab|harvest|extract)\s+(?:the\s+|all\s+|any\s+)?"
        r"(?:contents?\s+of\s+)?(?:~/\.ssh|\.ssh/|id_rsa|id_ed25519|\.aws/credentials|\.env\b|"
        r"\.npmrc|\.pypirc|\.netrc|\.git-credentials|keychain|browser\s+cookies|"
        r"(?:all\s+)?(?:saved\s+)?passwords)",
    ),
    # --- relaxing controls --------------------------------------------------------
    _r(
        "instruction.relax",
        "relax",
        Severity.MEDIUM,
        "asks the agent to relax a safety control",
        r"\b(?:disable|turn\s+off|skip|bypass|ignore|suppress|remove)\s+(?:all\s+|any\s+|the\s+)?"
        r"(?:safety|security|permission|sandbox|confirmation|approval|signature|signing|"
        r"certificate|ssl|tls|verification|guardrails?|content\s+filters?|antivirus|firewall|"
        r"pre-commit|code\s+review)(?:\s+(?:checks?|prompts?|hooks?|verification|warnings?|"
        r"steps?))?\b|--no-verify\b|--insecure\b|\bverify\s*=\s*false\b|"
        r"\bauto[-\s]?(?:approve|accept|confirm)\s+(?:all|every|any)\b|"
        r"\bwithout\s+(?:asking\s+for\s+)?(?:confirmation|approval|permission|review)\b|"
        r"--dangerously-skip-permissions\b|\byolo\s+mode\b|"
        rf"\b(?:do\s+not|don'?t|never|without)\s+(?:ask|asking|check\s+with|checking\s+with|"
        rf"confirm\s+with|confirming\s+with)\s+{_USER}\b",
    ),
    # --- triggers -----------------------------------------------------------------
    _r(
        "instruction.trigger",
        "trigger",
        Severity.MEDIUM,
        "sets a hidden trigger condition for later",
        r"\b(?:when(?:ever)?|if|once|as\s+soon\s+as|the\s+next\s+time)\s+(?:the\s+)?"
        r"(?:user|human|anyone|someone|they)\s+(?:\w+\s+){0,3}?(?:says?|types?|writes?|asks?|"
        r"mentions?|uses?)\s+(?:the\s+)?(?:word|phrase|keyword|code|password|term)?\s*"
        r"[\"'`\u201c\u2018]|"
        r"\bafter\s+(?:\d+|one|two|three|four|five|ten|a\s+few|several)\s+"
        r"(?:more\s+)?(?:sessions|conversations|runs|days|commits|messages|turns)\b[^\n]{0,40}"
        r"\b(?:start|begin|then|switch|you\s+(?:should|must|will))\b|"
        r"\b(?:on|after|starting|beginning)\s+(?:\d{4}-\d{2}-\d{2}|(?:january|february|march|"
        r"april|may|june|july|august|september|october|november|december)\s+\d{1,2})\b[^\n]{0,40}"
        r"\b(?:start|begin|switch|you\s+(?:should|must|will)|always)\b",
    ),
    # --- persistence --------------------------------------------------------------
    _r(
        "instruction.persistence",
        "persistence",
        Severity.LOW,
        "persistence marker (applies to future sessions)",
        r"\bfrom\s+now\s+on\b|\bin\s+(?:all\s+|every\s+)?(?:future|subsequent|later)\s+"
        r"(?:sessions?|conversations?|chats?|tasks?|runs?)\b|\b(?:permanently|forever)\s+"
        r"(?:remember|store|save|keep|follow|apply)\b|\bremember\s+(?:this|that)\s+"
        r"(?:forever|permanently|for\s+(?:all\s+)?future)\b|\bacross\s+all\s+sessions\b|"
        r"\bthis\s+(?:rule|instruction)\s+(?:is\s+)?permanent\b",
    ),
]

# Categories that legitimate memory almost never combines.
_COMBO_CATEGORIES = {
    "override",
    "secrecy",
    "authority",
    "role",
    "exfiltration",
    "relax",
    "trigger",
    "persistence",
}


# "Never paste API keys into chat" is advice *against* the action. For these
# categories a negation just before the verb, in the same sentence, cancels the match.
# (Secrecy is not here: "do not tell the user" is itself the attack.)
_NEGATABLE = {"exfiltration", "relax"}
_NEGATION = re.compile(
    r"\b(?:never|not|don'?t|doesn'?t|mustn'?t|shouldn'?t|avoid|no\s+need\s+to\s+ever)\s+"
    r"(?:\w+\s+){0,2}$",
    re.IGNORECASE,
)


def _negated(text: str, offset: int) -> bool:
    window = text[max(0, offset - 40) : offset]
    sentence = re.split(r"[.!?\n]", window)[-1]
    return bool(_NEGATION.search(sentence))


def _paragraph_index(text: str, offset: int) -> int:
    return len(re.findall(r"\n\s*\n", text[:offset]))


class InstructionDetector:
    name = NAME

    def __init__(self, rules: list[Rule] | None = None) -> None:
        self.rules = rules or RULES

    def detect(self, doc: Document) -> list[Finding]:
        normalized, mapping = normalize_with_map(doc.text)
        findings: list[Finding] = []
        by_paragraph: dict[int, list[tuple[Rule, Finding]]] = {}
        for rule in self.rules:
            for match in rule.pattern.finditer(normalized):
                if rule.category in _NEGATABLE and _negated(normalized, match.start()):
                    continue
                start = mapping[match.start()]
                end = mapping[min(match.end(), len(mapping) - 1)]
                line, col = doc.position(start)
                finding = Finding(
                    NAME,
                    rule.rule,
                    rule.severity,
                    rule.message,
                    doc.path,
                    line,
                    col,
                    excerpt(doc.text, start, end),
                    {"category": rule.category, "match": match.group(0).strip()[:120]},
                )
                findings.append(finding)
                by_paragraph.setdefault(_paragraph_index(doc.text, start), []).append(
                    (rule, finding)
                )
        findings = _dedupe(findings)
        for hits in by_paragraph.values():
            categories = {rule.category for rule, _ in hits} & _COMBO_CATEGORIES
            if len(categories) < 2:
                continue
            strongest = max(f.severity for _, f in hits)
            first = min((f for _, f in hits), key=lambda f: (f.line or 0, f.column or 0))
            findings.append(
                Finding(
                    NAME,
                    "instruction.combo",
                    strongest.bump(),
                    "several manipulation patterns in one passage: "
                    + ", ".join(sorted(categories)),
                    doc.path,
                    first.line,
                    first.column,
                    first.excerpt,
                    {"categories": sorted(categories)},
                )
            )
        return findings


def _dedupe(findings: list[Finding]) -> list[Finding]:
    """Keep the strongest finding per (rule, line)."""
    best: dict[tuple[str, int | None], Finding] = {}
    for finding in findings:
        key = (finding.rule, finding.line)
        if key not in best or finding.severity > best[key].severity:
            best[key] = finding
    return list(best.values())
