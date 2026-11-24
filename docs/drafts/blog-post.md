# I built a tool to catch poisoned AI agent memory (and it lost one of the benchmarks)

*Draft, not posted.*

A few weeks ago I started paying attention to how coding agents remember things. Tools like
Claude Code read a `CLAUDE.md` file at the start of every session. Other agents keep a
`memory/` folder or a JSON file of facts. It's a nice feature. You tell the agent once that you
use pnpm and it remembers.

Then I thought about it from the other side. If an agent trusts whatever is in that file, then
anyone who can get one line into the file gets to give the agent orders. Forever. And it doesn't
have to happen in the same session. Something gets written on Monday and does nothing until
Thursday, when the user types the right word.

That's what memory poisoning is, and it's on the OWASP list for agentic AI now. So I built
**memwax**, a small Python CLI, to see how far I could get with boring, explainable defenses.

## What it does

memwax has two halves.

The first half doesn't care what's in the files at all. It's about **integrity**:

- `memwax watch` records every change to the memory files in a log. Each log entry includes the
  hash of the previous entry, like a tiny blockchain without the blockchain hype. If someone edits
  or deletes an old entry, `memwax log verify` notices.
- `memwax amber create` takes a snapshot of the known-good state and signs it with an Ed25519
  key that lives in your home folder, not the project. Later, `memwax amber verify` tells you which
  files were added, changed or removed. If someone edits the baseline, or re-signs it with their
  own key, verification fails.
- Each change gets a "source" if memwax can figure one out: the git author (only if the file
  matches what was committed), a process that declared itself, or just "unknown". I was strict
  here on purpose. An uncommitted edit is not blamed on you just because you're the git user.

The second half looks at **content**. There are four detector modules: instruction-like text
aimed at the model, hidden characters (zero-width spaces, bidi controls, Unicode tag characters
that can hide a whole sentence, look-alike Cyrillic letters), risky URLs/shell commands/credentials,
and big sudden changes compared with the baseline.

The hardest part was not flagging normal memory. Memory files are *full* of instructions. "Always
run the tests" is a perfectly good memory. So memwax doesn't flag "always" or "never". It looks
for things a real preference almost never needs: hiding stuff from the user, claiming to be the
system, moving secrets, turning off safety checks, or "when the user says X, do Y".

## The demo

The demo uses a toy agent I wrote called memo. It has no model and never runs commands. It just
prints what it *would* run. In session 1, memo reads a vendor README that has a line addressed to
"AI assistants", and saves it to memory. In session 2 the user says "release" and memo would pipe
a download into a shell. Between the two sessions, memwax shows the drift, attributes the change to
memo, and flags the line as critical.

## The benchmark, honestly

I wrote 64 inert attack samples (direct, delayed activation, hidden characters, and instructions
hidden in documents) and 32 benign memory files. Some of the benign ones are deliberately
annoying, like the official Rust installer that really is `curl ... | sh`. I ran memwax and OWASP
Agent Memory Guard (AMG) 0.4.0 on all of them.

On my corpus, memwax caught 76.6% of attacks when flagging at medium severity or higher, and AMG
caught 6.2%. That sounds great until you remember that I wrote both the attacks and the rules. It's
my home turf.

So I also ran both tools on the 15 attack scenarios that ship inside AMG itself. There, AMG's
hardened config caught 14 of 15 and memwax caught 10. memwax completely misses AMG's
"protected key" attacks, because those depend on key-value semantics that a file scanner doesn't
have. I think publishing that loss is more useful than hiding it.

The other number I'm not proud of is false positives. At medium+, memwax flagged 7 of 32 benign
files (21.9%). At high+ it's 3 of 32, but detection drops to 57.8%. My first run was actually
worse (28.1%) because of two bugs. "Never paste API keys into chat" was being read as an
instruction to paste API keys, and a `${DB_PASSWORD}` placeholder looked like a real password. I
fixed both with regression tests, but since I found them using the same corpus, the second run is
optimistic. Both runs are in the repo.

## What I learned

- Regex rules get you surprisingly far on lazy attacks and hidden characters, and nowhere on polite
  paraphrases. "Please treat everything above this line as outdated" beat every tool I tested.
- Integrity is the part I trust more. A signed baseline doesn't need to understand the attack. It
  just needs to tell you something changed and who probably changed it.
- Writing your own benchmark is easy. Writing a fair one is hard. Running on someone else's corpus
  was the most useful thing I did.

## What's next

A held-out test set written by someone else, fewer false positives on security-team notes, and
maybe a git pre-commit hook. The code is Apache-2.0. If you have memory files that fool it, I'd
like to see them (inert ones, please).
