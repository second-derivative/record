# Second Derivative — the public record

This repository is a scoreboard.

Second Derivative predicts what will happen in the AI economy. Each prediction is committed to as a
hash before its outcome can be known, and opened afterwards with the outcome, the market's own
implied odds on the same question at the same moment, and the score that follows from the two. This
repository holds the commitments, the openings, the running calibration score, and Bitcoin
timestamps bounding when each of them was written.

It is published so that the claim can be checked by someone who assumes we are lying.
[VERIFY.md](VERIFY.md) is how. It takes about twenty lines of Python and no trust.

## What is here

| | |
|---|---|
| `chain.jsonl` | the record: one line per commitment, per opened prediction, and per policy change |
| `reveals.jsonl` | the opened predictions, pulled out of the chain for convenience |
| `scoreboard.json` | every metric, the counts, the refusals, and the worst-case bound |
| `publications.jsonl` | one line per publication, so the sequence can be checked for gaps |
| `anchors/` | each publication's manifest digest, its OpenTimestamps proof, and an index over both |
| `tip.json` | the signed chain tip, and the public half of the key that signed it, which must be this record's publish key |
| `MANIFEST.json` | the SHA-256 of every file above |
| `VERIFY.md` | the verification procedure, normative |
| `verify.py` | a convenience implementation of it, which opens no network connection |
| `canon-vectors.json` | hashing test vectors, so you can check your own implementation |

## Checking it

```
python3 -I verify.py .
```

It needs Python 3.10 or newer. Exit 0 means every check in `VERIFY.md` passed on these files. Exit 1 names the first one that
failed, and is the only exit that says anything against this record. Exit 2 means a check could
not be made on your machine and names it: checking the signature on `tip.json` needs
`cryptography`, the only thing any of this needs beyond the standard library, and a run that
could not make that check says so rather than reporting a pass it did not make. An older
Python exits 2 too, before checking anything. `VERIFY.md` has
the install command and the exit codes, normatively.

A valid signature on its own says only that somebody signed `tip.json`: anybody can make a key
and put its public half beside a signature. So `verify.py` also checks that the key is this
record's publish key, which it carries and prints on its last line, and fails a tip signed under
any other. To check against a key you found yourself rather than the one it carries, run
`python3 -I verify.py . --expect-key <the key>`; `VERIFY.md` shows how to read the key off the
earliest publication a Bitcoin block timestamps.

A pass means the key holder signed this state of the record, not that it is the latest. An
older copy, served whole, passes too. Every pass prints the `entry_hash` of the newest line in
`publications.jsonl`; keep it, and pass it to your next run as `--expect-ledger-prefix <hash>`,
which fails a copy that does not continue the ledger you saw. `--expect-at-least <seq>` is
weaker: ledger lines are not signed, so lines appended to an older copy can reach any `seq`.

`VERIFY.md` is normative and `verify.py` is a convenience. Where the two disagree, `VERIFY.md` is
right and `verify.py` is the bug — and the strongest form of the check is to write your own from
`VERIFY.md` and never run ours at all.

## How to read the scoreboard

- **Misses appear at the same volume as hits.** A prediction past its deadline and still unopened,
  or one whose nonce we cannot produce, is scored as a loss at the worst score available and
  published as one. Do not believe that sentence: `VERIFY.md` shows how to name an overdue
  commitment by hand from `chain.jsonl` alone, and it is the check to make first.
- **The score is against the market, never against zero.** Being right about something the market
  was already right about is worth nothing here, and the arithmetic says so.
- **The headline is tiers A and B only** — traded options and prediction markets. Weaker baselines
  are scored and published in full beside it, never inside it.
- **There is no claim of skill until the sample supports one.** Predictions about the AI economy are
  correlated, so the statistics are computed over clusters of related predictions rather than over
  predictions one at a time, and the scoreboard refuses to print a headline below a pre-registered
  cluster floor. It says so in words instead of printing a number somebody will quote.
- **Until a proof in `anchors/` has confirmed, this record proves order and not time.** A chain
  built in one sitting after the outcomes were known would still verify. The timestamps are what
  close that, and `scoreboard.json` reports the state as it is. A fresh proof is *pending* for
  hours: a calendar's promise to include a digest is not a timestamp, and nothing here counts one
  as one.
- **`confirmed` is the calendar's word, not the chain's.** `verify.py` checks the proofs
  structurally and never asks Bitcoin anything. To ask it, run `ots verify` on the files in
  `anchors/`; that needs a Bitcoin node it can reach and checks nothing without one. Which is the
  whole point of using a format somebody else's tool reads: the last check is yours, on a node we
  are not a party to.
- **What this cannot prove** is the last section of `VERIFY.md`, including the one attack no
  self-published record closes. It is worth reading before believing any of the rest.

Nothing here is investment advice, an offer, or a solicitation. No real money is managed.
