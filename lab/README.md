# memwax attack lab

A small, local lab for measuring how well memwax (and OWASP Agent Memory Guard) catch
poisoned agent memory. Everything here is inert text and a toy agent we own.

## Safety rules for this folder

- Every attack sample is **text only**. Nothing in the lab fetches a URL or runs a command
  from a sample.
- Attacker hosts use the reserved `.example` TLD or RFC 5737 documentation IPs
  (`203.0.113.0/24`, `198.51.100.0/24`), which cannot route to a real machine. A few samples
  name a real paste/shortener service (`webhook.site`, `bit.ly`) with a made-up path, because
  detecting those services is the point of the sample. They are never contacted.
  `tests/test_lab.py` enforces this list.
- The only "agent" is `toy_agent/memo_agent.py`. It has no model and no network access, only
  reads files inside the workspace you give it, and prints `WOULD RUN: ...` instead of
  executing anything. A test patches `subprocess` and `os.system` to fail if it ever tries.

## Layout

| Path | What it is |
|---|---|
| `corpus/attacks.jsonl` | 64 attack payloads, 16 each: direct, delayed activation, hidden characters, instruction-in-document. ASCII, with placeholders like `{ZWSP}`, `{TAG:...}`, `{CYR:word}` for hidden characters. |
| `corpus/benign.jsonl` | 32 realistic memory files, including deliberately hard cases (a security team discussing injection strings, the official rustup `curl \| sh` installer, a postmortem quoting an attacker command). |
| `build_corpus.py` | Expands placeholders into real characters and writes `samples/`. Each attack is embedded in one of three normal-looking host memory files. |
| `samples/` | The generated files that are actually scanned, plus `manifest.json` labels. |
| `toy_agent/memo_agent.py` | The naive local agent used for the demo. |
| `bench/run_memwax.py` | Scans every sample with memwax (generic adapter, no baseline). |
| `bench/run_amg.py` | Scans every sample with agent-memory-guard 0.4.0 in its own venv: `scan()`, AMG's own strict adapter, and AMG's own hardened adapter. |
| `bench/away_amsb.py` | Runs memwax on AMG's *own* benchmark scenarios, to counter home-field bias. |
| `bench/compare.py` | Computes every number in `results/BENCHMARK.md` from the JSON results. |
| `results/` | Raw results, `summary.json`, `BENCHMARK.md`, and `history/`. |

## Reproduce

```powershell
python -m venv .venv-amg
.venv-amg\Scripts\python -m pip install agent-memory-guard==0.4.0
.venv\Scripts\python lab\run_benchmark.py
```

On macOS/Linux use `.venv-amg/bin/python` and `.venv/bin/python`.

## How to read the results honestly

- **Home-field bias.** The same person wrote memwax's rules and this corpus. memwax was not
  tuned against the corpus before the first run, but the categories are ones memwax was
  designed for. The AMSB "away game" (AMG's own scenarios) is included for that reason, and
  AMG's hardened configuration wins it.
- **Two bugs were fixed after the first run.** The first run (frozen in
  `results/history/v0.1-frozen/`) showed false positives caused by (1) advice *against*
  an action ("Never paste API keys into chat") being read as the action, and (2) a
  `${DB_PASSWORD}` placeholder in a connection URL being read as a password. Both were fixed
  with regression tests. Fixing bugs found with a corpus and re-measuring on the same corpus
  is optimistic, so both runs are published. Detection did not change; the false positive
  rate at `>= medium` went from 28.1% to 21.9%.
- **Whole-file scanning is not how AMG is normally used.** AMG guards individual key-value
  writes. Here each memory file is one write. That is a fair model of file-based memory (an
  agent loads the whole file), but it is not AMG's home turf.
- **Small corpus.** 64 attacks and 32 benign files give wide error bars. Treat percentages
  as a rough comparison, not a precise rate.
