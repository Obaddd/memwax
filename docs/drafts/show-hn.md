# Show HN (draft, not posted)

**Title:** Show HN: memwax – tamper-evident change log and scanner for AI agent memory files

**URL:** <repo link>

**Text:**

Coding agents increasingly keep memory in plain files (CLAUDE.md, memory/ folders, JSON stores).
If something gets a line into those files, the agent follows it in every future session. That
could be a dependency README the agent summarized, a PR, or a sync tool.

memwax is a small Python CLI (Apache-2.0, one runtime dependency) that treats those files like
config you want to audit:

- `memwax watch` keeps an append-only, hash-chained log of every change, with best-effort source
  attribution: git author only if the file matches HEAD, a self-declared process, or "unknown".
- `memwax amber create/verify` signs a known-good baseline with an Ed25519 key kept outside the
  project and reports added/changed/removed files. Re-signing with a different key, or truncating
  the log after the baseline, fails verification.
- `memwax scan` runs explainable regex/Unicode detectors: overrides, secrecy toward the user,
  authority claims, trigger conditions, hidden characters (it decodes Unicode tag-character
  smuggling), risky shell/URLs/credentials, and drift. Output is text, JSON, or static HTML.

I benchmarked it against OWASP Agent Memory Guard 0.4.0, in its own venv and through its own
adapters, on two corpora:

- Mine (64 inert attacks, 32 benign files): memwax 76.6% detection / 21.9% FPR at medium+,
  AMG 6.2% / 3.1%. I wrote both the corpus and the rules, so discount this.
- AMG's own scenarios (15 attacks, 6 benign): AMG hardened 14/15, memwax 10/15, both 0 false
  positives. memwax can't do AMG's protected-key checks at all.

Known weaknesses are in the README: paraphrased instructions get through, the false positive rate
on security-team notes and install docs is high, and attribution isn't real process auditing.

Happy to hear about memory files that fool it (inert ones, please), and about better ways to
attribute file writes to a process portably.
