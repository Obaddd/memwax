# Decisions

This file records research done before writing code and every judgment call made where the spec
was silent or ambiguous. Newest decisions are appended at the bottom of the log.

## Prior art (researched 2026-11-24, before any code was written)

### OWASP Agent Memory Guard (`agent-memory-guard` 0.4.0 on PyPI)

Sources checked: the PyPI README for 0.4.0, and the installed 0.4.0 package source (read in a
separate virtual environment, `.venv-amg`, which is not committed).

What it does:

- An in-process guard (`MemoryGuard.write/read`) that sits between an agent and a key-value memory
  store (in-memory dict, Redis) and runs each write through detectors and a YAML policy
  (allow / redact / quarantine / block).
- Detectors for prompt injection, secret/PII leakage, protected-key changes, size anomalies,
  self-reinforcement loops, tool abuse, privilege escalation, and a "memory persistence injection"
  detector for delayed-activation phrasing.
- SHA-256 baselines for protected/immutable keys (`IntegrityRegistry`), and an in-memory ring buffer
  of snapshots for rollback.
- Framework integrations (LangChain, OpenAI Agents SDK, AutoGen, mem0, CrewAI, LlamaIndex, Agno).
- A simple `scan(text)` API, an `amg check "<text>"` command, and an `amg scan <path>` command.
- Its own benchmarks (`amg-bench`), which grade memory systems on plant / reset / recall.

What it does not do (each point verified in the 0.4.0 source, not just inferred from the README):

- **No file watching.** No watchdog/inotify/polling code. It only sees writes that call
  `guard.write`. An edit made to a memory file by a text editor, a git pull, or another process
  never reaches it.
- **`amg scan` scans Python source code, not memory content.** Its default include pattern is
  `**/*.py` and its rules look for unguarded memory API calls (`.upsert(`, `pickle.loads(` …),
  not for poisoned text inside CLAUDE.md-style files.
- **No signatures.** There is no Ed25519/HMAC/`cryptography` usage. Baselines are bare SHA-256
  digests held in process memory; the snapshot docstring itself says the stored digest is
  "recorded for forensics only" and nothing re-verifies it.
- **No persistent, tamper-evident change log.** Events are emitted as `SecurityEvent` objects;
  there is no on-disk append-only log and no hash chain linking entries. (`receipt_uri` is an
  optional pointer to an *external* receipt chain.)
- **No git awareness.** No code consults git to attribute a change to an author.
- **No hidden-character detection.** No zero-width, bidi-control, or homoglyph handling
  (no `unicodedata` use, no references to U+200B/U+202E etc.).

### ShieldCortex (`shieldcortex` 5.22.1 on npm, TypeScript, by Drakon Systems)

Sources checked: the npm README for 5.22.1 and the GitHub search listing. I did not install it or
read its source, so gaps below are stated as "the README does not describe", not "it cannot".

What it does (per README):

- A memory firewall for writes that go *through* ShieldCortex (its own memory store / MCP
  `remember` tool / Claude Code and OpenClaw hooks), quarantining recognised injection and leaked
  credentials, plus a lexical "memory-directive screen" for standing orders.
- An "Action Guard" tool gate on Claude Code, OpenClaw and Hermes (holds or blocks risky tool calls,
  e.g. reverse shells, malicious packages).
- An agent-config watch that, at Claude Code startup, reports changes to hooks and MCP server
  configs it did not make, and an MCP tool-description change check.
- `scan-skill <file>` / `scan-skills` for instruction files, a security `audit` with SARIF output,
  and a local dashboard, with an optional paid cloud tier.

What the README does not describe:

- Signed (asymmetric-key) baselines of a set of memory files that can be verified later.
- An append-only, hash-chained log of every change to file-based memory with per-change
  provenance (git author / process / unknown).
- Hidden-character (zero-width, bidi, homoglyph) detection.
- A published, reproducible detection benchmark with false-positive numbers.

### Does either already do everything memwax plans?

No. Both overlap with memwax on *content scanning* (injection phrases, credentials), and
ShieldCortex's `scan-skills` overlaps on scanning instruction files. Neither covers the
tamper-evidence half: signed baselines of memory *files*, a hash-chained provenance log, and
git-aware attribution. So the project goes ahead, but the README must not claim content
detection as novel.

### Differentiation (one paragraph)

memwax treats file-based agent memory (CLAUDE.md-style files, memory folders, JSON stores) the way
a security engineer treats configuration: as something you baseline, sign, and audit. It does not
sit in the agent's write path, so it also sees changes made by editors, git pulls, sync tools, or
a compromised process. Every change is recorded with a content hash and best-effort provenance in
an append-only log where each entry commits to the previous one, a known-good state can be frozen
into an Ed25519-signed "amber" baseline, and drift is reported as added/changed/removed files. On
top of that sits a set of small, explainable content detectors (instruction-like text, hidden
characters, URLs/shell/credentials, sudden large changes). OWASP AMG and ShieldCortex are runtime
guards for writes that pass through them; memwax is the out-of-band integrity and audit layer for
the files themselves, and the two approaches are complementary.

## Decision log

1. **Project folder.** The spec says `~/projects/memwax`. The folder this work was actually granted
   on the machine is `~/OneDrive/Documents/VSCODE PROJECTS/memwax`, and I was told to stay inside the
   granted folder, so the project lives there. It can be moved later with no code changes.
2. **GitHub CLI.** `gh` was missing; installed GitHub CLI 2.105.0 with `winget` (normal package
   manager). git 2.46, Python 3.13 and VS Code 1.143 were already present.
3. **Name check.** `memwax` returned 404 on PyPI (JSON and simple index) and GitHub repository search
   returned 0 results on 2026-11-24.
4. **License holder.** Apache-2.0, copyright "Obad" (the name on the request). Change it to a full
   legal name in `LICENSE` and `pyproject.toml` if preferred.
5. **Build backend / layout.** hatchling, `src/memwax`, Python >= 3.11. Only runtime dependency is
   `cryptography` (for Ed25519). CLI uses stdlib `argparse` to keep the dependency surface small.
6. **Polling monitor, not OS events.** `memwax watch` re-hashes every tracked file each interval
   (default 2 s). It is portable, has no dependency, and cannot miss an event when a watcher buffer
   overflows. Every file is fully re-hashed each poll (no size/mtime shortcut), so a same-size edit
   with a restored mtime is still caught.
7. **The log is the only monitor state.** The last-known hash of each file is rebuilt by replaying
   `.memwax/log.jsonl`; there is no cache file that could be edited to hide a change.
8. **Provenance rules.** `MEMWAX_SOURCE` env var (recorded as a *declared* process source) >
   git author of the last commit, but only when the working-tree file equals HEAD > "unknown".
   Uncommitted edits are not attributed to the local git user. Only author name and commit id are
   stored, not email. Removals are always "unknown". Real per-process attribution of file writes
   needs OS auditing (auditd, ETW, Endpoint Security) and is out of scope.
9. **Log truncation.** A hash chain cannot detect deletion of its *last* entries. Amber baselines
   record and sign the log head (seq + hash) to cover that case.
10. **Default targets.** CLAUDE.md, CLAUDE.local.md, nested CLAUDE.md, `.claude/**/*.md`, AGENTS.md,
    `memory/**`, `.memory/**`. Overridable with `memwax init --target GLOB`.
11. **Signing.** Ed25519 via `cryptography`. Keys live in `$MEMWAX_HOME` (default `~/.memwax/keys`),
    never in the project. The private key is PKCS#8 PEM, encrypted only if
    `MEMWAX_KEY_PASSPHRASE` is set (unencrypted by default so the tool works non-interactively;
    the README says so). `memwax amber create` generates a key on first use.
12. **Trust model for verify.** A baseline embeds its public key for information only. Verification
    uses only locally trusted keys: your own key, `~/.memwax/keys/trusted/*.pub`, and `--pubkey`.
    Otherwise an attacker could simply re-sign a poisoned baseline with their own key.
13. **What the signature covers.** The canonical-JSON manifest: per-file sha256/size/line count,
    creation time, note, change-log head (seq + hash), key id and public key. File content copies go
    in a content-addressed object store (`.memwax/amber/objects/`) and are re-hashed on every read,
    so a swapped object is ignored rather than trusted.
14. **Exit codes.** 0 = clean, 1 = findings/drift, 2 = integrity failure (bad signature, untrusted
    key, broken or truncated log), 3 = usage error. Lets CI and hooks branch on severity.
15. **One baseline at a time.** `amber create` replaces the previous baseline; the change log keeps an
    `amber` entry with each baseline's digest, so the history of baselines is still auditable.
16. **Detector philosophy.** Memory files are full of legitimate instructions, so plain
    "always"/"never" is never a finding. Detectors look for signals legitimate preferences rarely
    need (overrides, secrecy, authority claims, identity change, secret movement, relaxed controls,
    trigger conditions). Persistence markers ("from now on") alone are LOW; two or more categories
    in one paragraph produce an `instruction.combo` finding one level above the strongest.
17. **Rules over ML.** Regex rules on normalised text, not a model. They are explainable, fast,
    offline, and easy to review. The trade-off (paraphrases get through) is measured in Phase 5 and
    stated in the README.
18. **Normalisation before matching.** Zero-width/bidi/tag characters are removed and common
    Cyrillic/Greek look-alikes folded before the instruction and shell rules run, with an offset map
    so findings still point at the original line and column.
19. **Credentials are redacted** in every excerpt. Placeholders (`${VAR}`, `<your-key>`, `changeme`)
    and low-entropy values are ignored.
20. **URL policy.** A URL is only a finding when it is unusual (raw IP, punycode, shortener,
    paste/tunnel/webhook service, embedded credentials, data: URI) or, when a baseline exists, its
    domain is new since the baseline and not on the allowlist (LOW).
21. **Drift thresholds.** >=50% of lines changed = MEDIUM, >=80% = HIGH; growth >=3x = MEDIUM,
    >=10x = HIGH; shrinking below 20% = MEDIUM; new file = LOW; files under 200 bytes ignored.
22. **No non-ASCII in Python sources.** Test fixtures with hidden characters use escapes, enforced by
    `tests/test_dogfood.py`, so memwax never ships the characters it warns about.
23. **Adapters own formats, the core owns nothing format-specific.** `scanner.py`, `report.py` and
    the detectors only see `Document`/`Finding`; a test fails if they import a specific adapter.
    Adapters may add format-specific findings and mark documents `hidden_from_render`, a generic
    flag the core honours by raising severity one level.
24. **JSON is scanned decoded.** Escaped characters in JSON string values are invisible in the raw
    file, so the generic adapter scans each decoded string value (path `file.json#/pointer`) plus
    the raw text once; duplicate findings for the same file/line/rule are merged.
25. **Claude Code adapter scope.** Project-level files only (CLAUDE.md, CLAUDE.local.md, nested
    CLAUDE.md, `.claude/**/*.md`, `.claude/settings*.json`, `.mcp.json`). User-level
    `~/.claude/` is outside the project and not scanned by default. Hidden HTML comments,
    out-of-project `@imports`, `bypassPermissions` and blanket `Bash(*)` allow rules are reported.
26. **Report formats.** Text (ANSI colour only on a TTY, honours `NO_COLOR`), JSON (stable keys,
    ASCII-escaped), and a single static HTML file with no scripts and every value escaped.
    `--fail-on` (default `high`) sets the exit-1 threshold so the scan can gate CI or a hook.
27. **Benchmark design.** Each attack payload is embedded in a normal-looking host memory file
    (three hosts, which are themselves checked to be clean for every tool). A file is "detected"
    if memwax reports a finding at or above MEDIUM (primary) or HIGH (stricter), or if AMG's
    `scan()` says unsafe / AMG's own strict or hardened bench adapter does not store the write
    as-is. AMG runs in its own venv and is driven through its own adapters.
28. **No tuning before the first run; history kept.** The detectors were frozen at the Phase 4
    commit for the first run (`lab/results/history/v0.1-frozen/`). Two bugs exposed by that run
    (negated advice treated as exfiltration; `${VAR}` placeholder treated as a URL password) were
    then fixed with regression tests and the benchmark re-run. Both runs are published, and the
    README says the second one is optimistic.
29. **Away game.** To counter home-field bias, memwax is also scored on AMG's own AMSB scenarios.
    Their payload text is only written to gitignored `lab/runs/`; the repo keeps verdicts only.
30. **Inert corpus.** Attacker infrastructure uses `.example` and RFC 5737 IPs. A homoglyph sample
    originally pointed at a look-alike of a real brand's `.com` domain (which someone could own);
    it was changed to `.example`. `tests/test_lab.py` checks every attack URL host.
31. **CI.** GitHub Actions on push and PR, Linux + Windows, Python 3.11 and 3.13. Actions pinned to
    full commit SHAs (checkout v7.0.1, setup-python v7.1.0, resolved through the GitHub API),
    `permissions: contents: read`, `persist-credentials: false`. CI also runs the secret scan.
32. **Secret scan.** `scripts/secret_scan.py` reuses memwax's credential rules on every file git
    would push, plus key-file names, machine-specific home paths, and email addresses. Test
    fixtures build token-shaped strings at runtime so no token-like literal is committed.
33. **Demo.** `demo/demo.py` runs real commands on a throwaway project (with `MEMWAX_HOME` inside
    it) and saves the transcript; `demo/render_gif.py` (Pillow, optional `demo` extra) replays
    that exact transcript as a GIF. Nothing in the GIF is staged.
34. **Install command.** Not published to PyPI (publishing is public and irreversible); the README
    installs from the GitHub repo.
35. **Pushing without changing global git config.** The push used gh as a credential helper for that
    one command (`git -c credential...helper='!gh auth git-credential' push`), so the machine's
    global git settings were not modified.
