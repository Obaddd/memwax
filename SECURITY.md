# Security policy

## Reporting a vulnerability

Please report security problems privately, not in a public issue. Use GitHub's
**"Report a vulnerability"** button on the repository's Security tab (private vulnerability
reporting). Include:

- what you found and why it matters (for example, a way to change memory or the change log
  without `memwax log verify` or `memwax amber verify` noticing),
- steps or a minimal sample that reproduces it,
- the memwax version (`memwax --version`) and OS.

I aim to acknowledge reports within 7 days and to agree on a disclosure date with you once a
fix is ready. This is a personal open-source project with no bug bounty.

## Supported versions

Only the latest release receives fixes while the project is at 0.x.

## Scope

In scope: bypasses of the integrity guarantees (log chain, signature checks, trust model),
crashes or hangs on crafted memory files, unsafe handling of report output (for example, HTML
injection in `--format html`), and secrets leaking into reports unredacted.

Detector misses (an attack phrase memwax does not flag) are expected for a rule-based scanner.
Please open a normal issue or pull request with an inert sample instead. See
[CONTRIBUTING.md](CONTRIBUTING.md).

## Handling of the lab

The `lab/` folder contains inert attack text used for benchmarking. Do not add working malware,
real credentials, or samples that target real people, organisations or services.
