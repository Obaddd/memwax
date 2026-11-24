# LinkedIn post (draft, not posted)

AI coding agents now remember things between sessions, usually in plain files like CLAUDE.md.
That's convenient, and it's also an attack surface. One poisoned line can sit quietly in memory and
fire days later.

I built memwax, an open-source Python tool that makes that memory tamper-evident and scannable:

🔒 A hash-chained change log for every edit, with best-effort attribution (git author, declaring process, or unknown)
🟠 "Amber" baselines: Ed25519-signed snapshots of known-good memory, with drift reports
🔎 Detectors for instruction-like text, hidden Unicode (zero-width, bidi, tag characters, look-alike letters), risky URLs/shell/credentials, and sudden large changes
🧪 An inert attack lab with a toy agent, plus a benchmark against OWASP Agent Memory Guard

The honest results:
• On my own corpus of 64 attacks and 32 benign files: memwax detected 76.6% at medium severity and above, with a 21.9% false positive rate.
• On AMG's own scenarios, AMG's hardened configuration beat memwax, 14/15 to 10/15.
• Polite paraphrases ("treat everything above as outdated") got past every tool I tested.

Biggest lesson: running your tool on someone else's benchmark teaches you more than your own.

Repo and full methodology: <link>

#AISecurity #LLMSecurity #AgentSecurity #OpenSource #Python
