# Verifying this record

Everything here can be checked without our code and without trusting us.

## What the record claims

Each line of `chain.jsonl` is one entry. Each carries `prev_hash`, the previous entry's
`entry_hash`. Editing a line breaks that line's own digest; repairing that digest breaks
the next line's `prev_hash`. Hiding an edit means rewriting every entry after it, and the
anchoring proofs below are what stop that.

A `seal` entry says a prediction was committed to on a stated day. It carries three
commitments — one to the prediction, one to its three numbers on their own
(`numbers_commitment`), one to material that is never opened — a cluster
pseudonym, the day, the quarter the prediction comes due, and the hash of the policy it was
sealed under. It carries nothing about the claim, not even its category: a prediction can
stay sealed for a year, and a few hundred categories and resolution dates would describe
everything still outstanding.

A `reveal` entry opens one: the full prediction, the nonce, the outcome, the citation that
settled it, and the category, tier and dates the seal entry withheld.

A reveal marked `"withheld": true` is the one exception, and it is a narrow one. Where the
claim's own wording cannot be published, the text and its nonce stay unpublished — but the
outcome, the category, the tier, the dates and the cluster are published exactly as usual,
and so are the probability, the market's baseline and `baseline_visible_to_forecaster`
(whether the market's number was shown before the prediction was made), so the prediction is
counted in every statistic on the scoreboard and you can count it yourself. Those three
numbers are the ones sealed: every reveal, withheld or not, opens the seal's
`numbers_commitment` (below). Withholding removes the words; it never removes a result. The
count of withheld reveals is published under `accounting.text_withheld`, so you can see how
often it is used.

Two things are deliberately **not** in this file. Entries carry an `actor_digest` in place
of a signature: the digest tells you which entries share a signer and nothing else, and a
signature is only worth checking against a key you have some reason to trust, which is not
the case for any key that signs an entry as it is written. The signature that is worth
checking is the one on `tip.json`, whose key is published; it is covered below. And seal and
reveal times are days, not instants; `scoreboard.json` carries `seals_by_day` so you can
still see whether this record was built steadily or assembled in one sitting.

## Check the chain

For every entry, with `entry_hash` removed and the rest serialised as JSON with sorted
keys and the separators `(",", ":")`:

    entry_hash == sha256(
        b"sd/record/entry/v1" + b"\x00" + canonical_json(entry_without_entry_hash)
    ).hexdigest()

and `prev_hash` equals the previous line's `entry_hash`, with the first line's `prev_hash`
being the literal string `genesis`. `seq` counts from zero with no gaps.

## Check a revealed prediction against what was sealed months earlier

Take the `prediction` and `nonce` from a `reveal` entry:

    commitment == sha256(
        b"sd/record/commit/v1" + b"\x00"
        + canonical_json(prediction) + b"\x00"
        + bytes.fromhex(nonce)
    ).hexdigest()

and that commitment appears in an earlier `seal` entry with an earlier `sealed_on`. If it
does, the prediction you are reading is exactly the one committed to on that day, and it
was committed to before its outcome was knowable.

The `seal_seq` on the reveal names where that entry sits, so you can find it in one step —
but check the commitment rather than trusting the pointer.

The nonce is why a commitment cannot be brute-forced: without it, anyone could grid over
plausible claims, hash each one, and read every unopened prediction straight off this file.

## Check a reveal's numbers against what was sealed

Every score and count on the scoreboard is computed from three values per prediction: its
`probability`, its `baseline` and `baseline_visible_to_forecaster`. Each `seal` entry
commits to those three on their own, under a nonce of their own, and every `reveal` entry
publishes that nonce as `numbers_nonce`. Take the three values — from the reveal's top level
when it is withheld, from its `prediction` when it is open — exactly as the file spells them:

    numbers = {
        "probability": ...,
        "baseline": ...,
        "baseline_visible_to_forecaster": ...,
    }
    numbers_commitment == sha256(
        b"sd/record/numbers/v1" + b"\x00"
        + canonical_json(numbers) + b"\x00"
        + bytes.fromhex(numbers_nonce)
    ).hexdigest()

where `numbers_commitment` is the one on the seal entry the reveal names. Numbers travel as
exact decimal strings, never as JSON floats: `"0.62"` and `"0.620"` are the same number and not
the same commitment, and the sealed spelling is the only one that opens it.

On a withheld reveal this is the only thing that ties its published numbers to the day it was
sealed; without it they could have been written after the outcome was known. On an open
reveal the prediction's own commitment already covers them, and this checks that the seal's two
commitments agree. `numbers_nonce` opens nothing else: it is independent of the nonce that
blinds the text, so a withheld reveal's words stay as closed as before. `verify.py` fails a seal
with no `numbers_commitment`, a reveal with no `numbers_nonce`, and any reveal whose numbers do
not open it.

The domain tag is its own, not the prediction's, so a digest made for one commitment can never
stand for the other. And a seal is opened once: `verify.py` fails a second reveal naming a seal
another reveal already opened, which could otherwise borrow that seal's numbers and nonce whole,
and a reveal whose `cluster_pseudonym` is not its seal's.

## Check that the claim's quantity meant this when it was sealed

A prediction is about a named quantity — "advanced packaging capacity", in some unit — and
what that name *means* is a definition we hold and do not publish. A record
that published the claim and kept the meaning adjustable would be a record you cannot check:
we could decide after the fact that the quantity had always meant something the outcome
suited.

So every `seal` entry carries a `registry_root`: one digest over the whole registry of
quantities its claim was checked against, salted with a value fresh to that seal. On its own
it says nothing, which is the point — it names no quantity, no count and no definition, and
two seals made under one registry do not share a value.

Every `reveal` that publishes its text carries `quantity_proof`, which opens that digest on
the one entry the claim used: the entry itself (`id`, its dimension family, the unit ids it
admitted, and a digest of its definition), the seal's `salt`, and a `path` of sibling
hashes. Fold it back:

    leaf = sha256(b"sd/record/registry/v1" + b"\x00" + bytes.fromhex(salt) + b"\x00" + canonical_json(entry)).hexdigest()

then for each step in `path`, with `h` the running value,

    h = sha256(b"sd/record/registry/v1" + b"\x01" + (sibling + h if side == "left" else h + sibling)).hexdigest()

over the raw 32 bytes of each digest. The result must equal the `registry_root` on the seal
this reveal names, the entry's `id` must be the claim's `quantity`, and the claim's `unit`
must be one of the entry's `units`. If all three hold, that quantity existed and meant
exactly this on the day the prediction was sealed.

What you do not get is the rest of the registry. The path is sibling hashes, the definition
is a digest rather than its text, and the salt opens only the leaf it came with, so a proof
tells you about the quantity the reveal already names and about no other. A reveal with its
text withheld carries no proof either, because the proof would name what the withholding is
withholding.

## Check that we did not hide our misses

**Name an overdue commitment yourself.** This is the sharpest check in this file and it needs
nothing but `chain.jsonl`:

1. Collect every `seal` entry's `commitment` and its `deadline_quarter`.
2. Collect every `reveal` entry's `commitment`.
3. Anything in the first set, absent from the second, whose quarter ended before today, is a
   commitment we have not answered for. There should be none.

You do not have to take our word for the count, and you do not have to accept an aggregate. You can
point at one line of this file and ask about it.

`scoreboard.json` carries a three-way count under `accounting`: **sealed**, **revealed**,
**resolved**. Compare them yourself against `chain.jsonl`. Every sealed commitment must
eventually be revealed. A commitment that is past its deadline, never revealed, or whose
nonce we cannot produce is scored as a miss at the worst possible score — so losing a
nonce costs us more than revealing whatever it hid.

`scoreboard.json` also carries `worst_case`, in which every void and every overdue
prediction is charged as maximally wrong. If the headline only survives when those are
excluded, you will see it in the same file.

## Check what review removed before anything was sealed

Every forecast is read by the firm's owner before it can be sealed. The owner releases a batch
whole, or discards a forecast for a named defect, and never for its probability. So that a
reader can see what was removed, each decided batch is one `review` entry in `chain.jsonl`:

- `batch`: the batch number; batches run 1, 2, 3 in the order they were decided, with no gap.
- `decided_on`: the day the batch was decided.
- `held`: how many forecasts the batch held.
- `released`: how many were released to be sealed.
- `discarded`: how many were discarded, by defect: `question` (the question was malformed or
  could not be resolved as written), `data` (a number read or computed was wrong), `duplicate`,
  and `program` (a fault in the code that produced the batch, only ever for a whole batch).
- `batch_discarded_as`: the defect named when the whole batch was discarded at once, or null.
- `lapsed`: how many could no longer be sealed in time when the batch was released.
- `batch_fingerprint`: a salted sha256 over every forecast in the batch and what happened to it.

An `awaiting_review` entry says how many forecasts were held and not yet decided:

- `on`: the day of the count.
- `held_ever`: how many forecasts had been held for review since the record began.
- `waiting`: how many forecasts were held and undecided.
- `oldest_waiting_days`: how many days the oldest of them had waited.
- `batches_decided`: the last batch decided before the count was taken.

Check, in chain order:

1. `held` equals `released` plus every `discarded` count plus `lapsed`.
2. A batch counting any `program` discard has `batch_discarded_as` of `program`; a batch
   discarded whole released nothing and lapsed nothing.
3. Batch numbers run 1, 2, 3 with no gap, and `decided_on` never goes backwards.
4. Each `awaiting_review` entry's `batches_decided` is the number of `review` entries before it.
5. Each `awaiting_review` entry's `waiting` is exactly its `held_ever` minus the `held` of every
   `review` entry before it, and `held_ever` and `on` never fall from one to the next. A forecast
   leaves the waiting count by being decided in a batch you can see, or not at all.
6. `scoreboard.json`'s `review` block is the sum of these entries, with `waiting` copied from
   the newest `awaiting_review` entry, and no track's board carries one.

What you cannot check from these files is that every forecast was counted; the count is the
owner's own statement, fixed on the chain on the day it was made. The fingerprint is what makes
it auditable later: given a batch's salt and its forecasts, an auditor recomputes

    sha256(b"sd/record/review/v1" + b"\x00" + salt + b"\x00" + canonical_json(rows))

where `rows` is one `[sha256(canonical_json(forecast)), disposition, defect or ""]` per
forecast, sorted (`review_fingerprint` in `verify.py`). The salts are never published here.

## Tracks: one board per policy, never pooled

A record may seal under more than one registered policy. Each `policy` entry in `chain.jsonl`
is one set of rules — its thresholds, and for a track its `track` block — and every `seal`
and `reveal` names the `policy_hash` it was made under. That hash, and the policy version a
`reveal` and a board carry with it, are the only markers of which track an entry is in; there
is no separate field and no track name anywhere in this record.

`scoreboard.json` therefore has one board per policy under `tracks`, keyed by policy version,
each carrying its own `policy_hash`, `accounting`, `headline`, `by_tier`, `by_batch`,
`calibration` and `power`, and no `anchoring` block: that is stated once, at the top level,
for the whole record. The counts at the top level (`accounting`, `seals_by_day`) are over
the whole chain, because the chain does not partition; they are entry counts about the chain
and never about skill, which is why `charged_as_miss` and `scorable` sit inside each track's
`accounting` and are never summed. Every *statistic* is inside a track.
**No number anywhere combines two tracks.** A skill number pooled across a policy with a
42-day minimum horizon and one with a one-day minimum would report the first's independence
over the second's rows. If you find such a number, this record is wrong.

Each track publishes `resampling_unit`, which says what its `correlation_groups` count is
counting. A unit of `correlation_group` means the correlation group pseudonym. A unit of
`correlation_group_by_resolution_block` with a `block_days` of N means the pair of that
pseudonym and `resolution_date.toordinal() // N`, both of which every reveal publishes, so you
can recount the blocks from `reveals.jsonl`. That blocking is an assumption, stated in the
track's `assumptions` in words, and it is never applied to a policy whose `track` block does
not carry `resampling_block_days`.

A track's `batch_id` is the seal quarter (`2026Q3`) or the seal month (`2026M09`), as its
policy's `track.batch_grain` says; the two spellings never collide.

## Recompute the smallest market error the record could detect

Each board's `power.detectable_market_error` is arithmetic on a count you can make yourself:

    D = sqrt( (z(1 - alpha/2) + z(power))^2 * 4 * q * (1 - q) / n ),  q = 0.5

`z` is the standard normal quantile (`statistics.NormalDist().inv_cdf` in Python), `alpha` and
`power` are the `thresholds` on the `policy` entry whose `policy_hash` the board names, and `n`
is `power.correlation_groups`, which must equal `headline.correlation_groups`. Round `D` to four
places. At alpha 0.05 and 80% power, 87 groups give 0.3004 and 150 give 0.2287.

It is what predictions equal to the true probabilities could detect across `n` resampling
units if the market were off by `D` on every one of them. Our own forecast errors, and a market
wrong on only some groups, both make the real figure larger. The board says so in its
`assumptions`.

The key is **absent** until `D` is at most 0.5, the largest error a market can make at a 50%
base rate: 32 groups at the thresholds above. Absent means "too few groups", never "not
computed", so check both directions: a board or stage carrying the key must carry the formula's
value at its own `correlation_groups`, and one leaving it out must count fewer than 32.

To recount `n`, take the `reveal` entries under the board's `policy_hash` with `outcome` TRUE or
FALSE, `baseline_tier` `A_traded` or `B_prediction_market`, `contamination_risk` false, and a
baseline probability inside the policy's `trivial_band`, and count their distinct resampling
units (see "Tracks" above). The headline also leaves out the arm that saw the market's number,
which an open reveal states in `prediction.baseline_visible_to_forecaster` and a withheld one
in its own top-level `baseline_visible_to_forecaster`. A withheld reveal must state it, as
`true` or `false`; an open one must not state it a second time outside its prediction, where
the commitment does not cover it. So every count is a count, never a range.

Every count is checked, not only the headline's. Each stage's `correlation_groups` (the power
block, the headline, each tier, each batch, the visible arm) must be an integer, never `150.0`
or `true`, and must equal the count of that stage's units in the reveals. A
stage that states a figure must state the count it was computed on, and a board with reveals
under its policy must have a power block.

## Check a publication, where `tip.json` is present

This is the one check that needs something beyond the Python standard library: Ed25519
verification.

    python3 -m pip install cryptography

If you would rather not take a package on trust either, pin it: put the version you want and
its SHA-256 hashes from PyPI in a requirements file and install with
`python3 -m pip install --require-hashes -r <that file>`. It is the same package this record
is signed with.

`verify.py` makes every other check without it, and names the one it could not make rather
than printing a pass it did not earn. Its three exit codes are normative, so a script can
tell a broken record from a broken machine:

    0   every check below passed on these files
    1   a check FAILED — something about this record does not hold
    2   a check could not be MADE on this machine; nothing failed

Only exit 1 is a statement about the record. `verify.py` needs Python 3.10 or newer; on an
older one it exits 2 before checking anything and says so.

`tip.json` carries the chain's tip digest, the number of entries it covers, the day it was
exported, the signing envelope under `actor`, and under `public_keys` the public half of the
key that made it. Reconstruct the signed bytes as

    b"sd/core/actor/v1" + b"\x00" + canonical_json({
        "actor": <the envelope in this file, minus its signature>,
        "payload": {"tip": ..., "entries": ..., "exported_at": ...},
    })

and verify the signature against that public key. It tells you this exact file came from
us. It is deliberately not the key that signs an entry as it is written: this one is
published and therefore under study, and losing it would let somebody forge a publication
you can detect, not a commitment you cannot.

## Check the timestamps

`anchors/` holds, for each publication, three things: `<digest>.txt`, which contains that
publication's `MANIFEST.json` digest as 64 hex characters; `<digest>.txt.ots`, an
OpenTimestamps proof **of that file**; and a line in `anchors/index.jsonl` tying the pair to
a publication sequence number.

`verify.py` reads the proofs and checks both links offline: that the proof really is a proof
of the bytes in the `.txt` beside it, and that those bytes are the manifest digest its row
claims. That check is structural. It says the proof is over what we claim it is over; it
says nothing about Bitcoin, and it cannot, because that takes a node. For that:

    python3 -m pip install opentimestamps-client
    ots verify anchors/<digest>.txt.ots

That command needs a Bitcoin node it can reach — the reference client queries one over RPC,
using your local configuration or `--bitcoin-node <url>` — and exits without checking
anything if it has none. It does not fall back to a block explorer. So the strong form of
this check is one only you can make, on a node you trust, which is the point: we are not a
party to it.

Run against a node, `ots verify` prints the block **time**. We do not publish one. A Bitcoin
attestation carries a height and nothing else, the block's time is in its header, and we will
not add a block explorer to this system to fetch a number you can read off the chain
yourself — so `block_time` in the index is always `null`, deliberately, and `block_height` is
what we record.

`confirmed` in the index and in `scoreboard.json` means the calendar returned a proof
carrying a Bitcoin attestation. It does **not** mean we checked that block. That is why this
section exists and why `ots verify` is the last word.

`anchors/index.jsonl` is the one file in a publication that changes. A row only ever goes
from pending to confirmed, and the digest it names is fixed by the proof the calendar holds.
It is outside `MANIFEST.json` on purpose: the manifest covers the record, the anchor index
points at the manifest, and nothing hashes itself.

## What this does and does not prove

The chain proves **order** and makes silent edits evident.

It does not, on its own, prove **when** entries were written — a chain built in one sitting
after the outcomes were known would still verify. That requires the anchoring proofs above.
Where `scoreboard.json` reports `anchoring.anchored` as false, this record proves ordering
only, and says so rather than implying more.

Anchoring is a property of the whole record, not of a track. It is stated once, in the
`anchoring` block at the top level of `scoreboard.json`, and no board under `tracks` carries
one: a track's rows are timestamped by the same chain and the same anchors as every other
row. `verify.py` fails a board that carries its own.

A publication is stamped as it is delivered, which is after the files you are reading were
built. `anchors/` is outside `MANIFEST.json`, so that row is committed with this publication
and you are looking at it — but `scoreboard.json` was written before it existed and cannot
count it. A row missing for the newest publication is the other legal state and not a fault;
two behind is a record that stopped anchoring, and `verify.py` fails on it.

The counts under `anchoring` are counts of **anchor attempts**, one per publication that has
been stamped, and they are not the count of publications: that is the length of
`publications.jsonl`. `attempted` is how many publications have an anchor row at all,
and it splits exactly into `confirmed` (a proof in a Bitcoin block), `pending` (submitted,
not yet in a block) and `failed` (the calendar could not be reached, recorded rather than
retried into silence). A publication with no row at all is counted in none of them, and
`contiguous` is false with `first_gap_at_seq` naming the first one missing.

`excludes_publication_seq` names the one publication those counts leave out, which is this
one. Its row stamps the digest of the `MANIFEST.json` that covers `scoreboard.json`, so a
count inside that file cannot include the row that names it — there is no order in which it
could, and the same acyclicity is why `anchors/` is outside the manifest at all. In a record
you fetched, that row is in `anchors/index.jsonl` beside it. The check is:

    attempted  ==  the number of rows in anchors/index.jsonl whose publication_seq
                   is not excludes_publication_seq

When `excludes_publication_seq` is null, that is every row. It names the newest publication in
`publications.jsonl` or nothing: a scoreboard that leaves out any older publication's row is
not describing its own record. `verify.py` makes both checks for you.

It does not check `confirmed` the same way, and that is deliberate: a row goes from pending
to confirmed hours after the publication carrying it was built, so `confirmed` in an older
`scoreboard.json` can be behind the index — understating the evidence this record holds,
never overstating it. Publications 0 to 4 carry no
`excludes_publication_seq` at all; they were published before the field existed. In 0 and 2
that changes nothing, because no publication had been stamped yet and their indexes are empty.
In 3 and 4, `attempted` is one behind the rows beside it for the reason above.

`anchored_from_seq` names the first publication that has a row. It is not zero on this
record and never will be: the first publications were made before this record was anchored
at all, and a timestamp taken today would say today. That is the honest thing to publish,
and it is why a run starting above zero is not read as a gap.
