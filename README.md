# Second Derivative — the public record

This repository is a scoreboard and nothing else.

Second Derivative forecasts the AI economy. Every prediction it makes is sealed as a hash before its
outcome can be known, and opened afterwards with the outcome, the market's own implied odds for the
same question at the same moment, and the score. This repository holds those hashes, those openings,
the running calibration score, and a set of Bitcoin timestamps that bound when each of them was
written.

It is published so that the claim can be checked by someone who assumes we are lying.
[VERIFY.md](VERIFY.md) is how. It takes about twenty lines of Python and no trust.

## What is here

| | |
|---|---|
| `chain.jsonl` | the record: one line per sealed prediction, per opened one, and per policy change |
| `reveals.jsonl` | the opened predictions, pulled out of the chain for convenience |
| `scoreboard.json` | every metric, the counts, the refusals, and the worst-case bound |
| `publications.jsonl` | one line per publication, so the sequence can be checked for gaps |
| `anchors/` | OpenTimestamps proofs committing each publication into Bitcoin |
| `MANIFEST.json` | the SHA-256 of every file above |
| `VERIFY.md` | the verification procedure, normative |
| `verify.py` | a convenience implementation of it — standard library only, no network |
| `canon-vectors.json` | hashing test vectors, so you can check your own implementation |

## What is not here, and never will be

The world model. The sources. The code that produces the forecasts. The agent design. The prompts. The
reasoning behind any prediction. The portfolio, its positions, their sizes, and the returns.

Publishing the scoreboard is the point. Publishing the machine would end the exercise. Hedge funds do
not publish their positions, their methods or their results, and neither do we; what we publish is the
proof that we were right before the market was, or that we were not.

## How to read it, honestly

- **Misses appear at the same volume as hits.** A prediction that is past its deadline and unopened,
  or whose nonce we cannot produce, is scored as a loss at the worst score available and published as
  one. Check that yourself: it is step 3 of `VERIFY.md`, and it is the step to do first.
- **The score is against the market, never against zero.** Being right about something the market was
  already right about is worth nothing here, and the arithmetic says so.
- **The headline is tiers A and B only** — traded options and prediction markets. Weaker baselines are
  scored and published in full, beside it, never inside it.
- **There is no claim of skill until the sample supports one.** Predictions about the AI economy are
  correlated, so the statistics are computed over clusters rather than over predictions, and the
  scoreboard refuses to print a headline number below a pre-registered cluster floor. It will say so
  in words rather than printing a number somebody will quote.
- **Until a proof in `anchors/` has confirmed, this record proves order and not time.** A chain built
  in one sitting after the outcomes were known would still verify. The timestamps are what close that,
  and `scoreboard.json` reports the state as it is.
- **What this cannot prove** is in the last section of `VERIFY.md`, including the one attack no
  self-published record closes. It is worth reading before you believe any of this.

Nothing here is investment advice, an offer, or a solicitation. No real money is managed.
