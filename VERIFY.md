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

## What this does and does not prove

The chain proves **order** and makes silent edits evident.

It does not, on its own, prove **when** entries were written — a chain built in one sitting
after the outcomes were known would still verify. That requires the anchoring proofs, which
commit the chain's tip into Bitcoin through OpenTimestamps. Where those proofs are present,
verify them with `ots verify`, and the tip they cover existed before the block they name.
Where `scoreboard.json` reports `anchoring.anchored` as false, this record proves ordering
only, and says so rather than implying more.

The counts under `anchoring` are counts of **anchor attempts**, one per publication that has
been stamped, and they are not the count of publications: that is the length of
`publications.jsonl`. `attempted` is how many publications have an anchor row at all,
and it splits exactly into `confirmed` (a proof in a Bitcoin block), `pending` (submitted,
not yet in a block) and `failed` (the calendar could not be reached, recorded rather than
retried into silence). A publication with no row at all is counted in none of them, and
`contiguous` is false with `first_gap_at_seq` naming the first one missing.
