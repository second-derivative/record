# Verifying this record

Everything here can be checked without our code and without trusting us.

## What the record claims

Each line of `chain.jsonl` is one entry. Each carries `prev_hash`, the previous entry's
`entry_hash`. Editing a line breaks that line's own digest; repairing that digest breaks
the next line's `prev_hash`. Hiding an edit means rewriting every entry after it, and the
anchoring proofs below are what stop that.

A `seal` entry says a prediction was committed to on a stated day. It carries two
commitments — one to the prediction, one to material that is never opened — a cluster
pseudonym, the day, the quarter the prediction comes due, and the hash of the policy it was
sealed under. It carries nothing about the claim, not even its category: a prediction can
stay sealed for a year, and a few hundred categories and resolution dates would describe
everything still outstanding.

A `reveal` entry opens one: the full prediction, the nonce, the outcome, the citation that
settled it, and the category, tier and dates the seal entry withheld.

A reveal marked `"withheld": true` is the one exception, and it is a narrow one. Where the
claim's own wording cannot be published, the text and its nonce stay unpublished — but the
outcome, the category, the tier, the dates and the cluster are published exactly as usual,
and the prediction is counted in every statistic on the scoreboard. Withholding removes the
words; it never removes a result. The count of withheld reveals is published under
`accounting.text_withheld`, so you can see how often it is used.

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

## Tracks: one board per policy, never pooled

A record may seal under more than one registered policy. Each `policy` entry in `chain.jsonl`
is one set of rules — its thresholds, and for a track its `track` block — and every `seal`
and `reveal` names the `policy_hash` it was made under. That hash, and the policy version a
`reveal` and a board carry with it, are the only markers of which track an entry is in; there
is no separate field and no track name anywhere in this record.

`scoreboard.json` therefore has one board per policy under `tracks`, keyed by policy version,
each carrying its own `policy_hash`, `accounting`, `headline`, `by_tier`, `by_batch`,
`calibration` and `power`. The counts at the top level (`accounting`, `seals_by_day`) are over
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

Only exit 1 is a statement about the record.

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

A publication is stamped as it is delivered, which is after the files you are reading were
built, so the newest publication's row travels with the *next* publication. One behind is
the normal state; two behind is a record that stopped anchoring, and `verify.py` fails on it.

The counts under `anchoring` are counts of **anchor attempts**, one per publication that has
been stamped, and they are not the count of publications: that is the length of
`publications.jsonl`. `attempted` is how many publications have an anchor row at all,
and it splits exactly into `confirmed` (a proof in a Bitcoin block), `pending` (submitted,
not yet in a block) and `failed` (the calendar could not be reached, recorded rather than
retried into silence). A publication with no row at all is counted in none of them, and
`contiguous` is false with `first_gap_at_seq` naming the first one missing.

`anchored_from_seq` names the first publication that has a row. It is not zero on this
record and never will be: the first publications were made before this record was anchored
at all, and a timestamp taken today would say today. That is the honest thing to publish,
and it is why a run starting above zero is not read as a gap.
