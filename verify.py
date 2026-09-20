#!/usr/bin/env python3
"""Verify Second Derivative's public record.

    python3 verify.py [directory]

Three exit codes, so a script can tell them apart:

    0   every check in VERIFY.md passed on these files
    1   a check FAILED — something about this record does not hold
    2   a check could not be MADE on this machine; nothing failed

This file is published alongside the record. It opens no network connection and imports no
code of ours. That is deliberate: a record that can only be verified by running its author's
application is not a public record.

One check needs one package. Verifying the Ed25519 signature on tip.json needs
`cryptography`, which is not in the standard library; everything else here is. A run that
cannot make that check exits 2 and names it, rather than printing a pass it did not earn.
Exit 2 is not an accusation against the record; exit 1 is.

VERIFY.md is the normative version of these checks and is written so that you can
reimplement them yourself in about twenty lines. If this script and VERIFY.md ever disagree,
VERIFY.md is right and this script is the bug. If you want the strongest form of the check,
write your own from VERIFY.md and do not run this at all.

One thing this script does not do at all. It does not check the Bitcoin timestamps. Its
anchor checks are structural: that each proof is a proof of the bytes beside it and that
those bytes are the manifest digest the row claims. Whether the block it names exists, and
what is in it, this script never asks, because asking means a Bitcoin node and this script
is twenty lines of standard library you can read in one sitting.

To make that check, run `ots verify` on the proofs in anchors/. It needs a Bitcoin node --
the OpenTimestamps reference client talks to one over RPC (`--bitcoin-node <url>`, or your
local configuration) and exits without checking anything if it cannot reach one. It does not
consult a block explorer, and neither does anything we run.
"""

from __future__ import annotations

import hashlib
import json
import sys
from decimal import Decimal, InvalidOperation
from pathlib import Path
from typing import Any

COMMIT_DOMAIN = b"sd/record/commit/v1"
ENTRY_DOMAIN = b"sd/record/entry/v1"
SIGNATURE_DOMAIN = b"sd/core/actor/v1"
GENESIS = "genesis"


def canonical(value: Any) -> bytes:
    """The one serialisation this record hashes: sorted keys, tight separators, strict."""
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False
    ).encode("utf-8")


def entry_hash(entry: dict[str, Any]) -> str:
    body = {k: v for k, v in entry.items() if k != "entry_hash"}
    return hashlib.sha256(ENTRY_DOMAIN + b"\x00" + canonical(body)).hexdigest()


def commitment(prediction: Any, nonce_hex: str) -> str:
    return hashlib.sha256(
        COMMIT_DOMAIN + b"\x00" + canonical(prediction) + b"\x00" + bytes.fromhex(nonce_hex)
    ).hexdigest()


def quarter_ended_before(quarter: str, day: str) -> bool:
    """Has ``2027Q2`` finished by ``2027-07-01``? Seal entries date deadlines by quarter."""
    try:
        year, _, index = str(quarter).partition("Q")
        month = int(index) * 3
    except ValueError:
        return False
    # The first day of the following month is a safe upper bound on the quarter's last day,
    # and avoids a calendar lookup for the sake of one comparison.
    following = f"{int(year) + (1 if month == 12 else 0)}-{(month % 12) + 1:02d}-01"
    return day >= following


def number(value: Any) -> Decimal | None:
    """Exact numbers travel as decimal strings. Read them as decimals, never as floats."""
    if value is None:
        return None
    try:
        return Decimal(str(value))
    except InvalidOperation:
        return None


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    if not path.exists():
        return rows
    for lineno, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        text = line.strip()
        if not text:
            continue
        try:
            rows.append(json.loads(text))
        except json.JSONDecodeError as error:
            raise SystemExit(f"FAIL {path.name}:{lineno} is not valid JSON ({error})") from None
    return rows


class Report:
    def __init__(self) -> None:
        self.failures: list[str] = []
        self.unmade: list[str] = []
        self.notes: list[str] = []

    def check(self, ok: bool, message: str) -> bool:
        if not ok:
            self.failures.append(message)
        return ok

    def cannot_check(self, message: str) -> None:
        """A check this run could not make. Not a pass, and not a failure of the record.

        Kept apart from ``failures`` on purpose. "The signature is wrong" and "I could not
        check the signature" are different statements about the record and only one of them
        is an accusation, so they exit 1 and 2 respectively. Both are non-zero, because the
        alternative is a green run that quietly skipped a step.
        """
        self.unmade.append(message)

    def note(self, message: str) -> None:
        self.notes.append(message)


def verify_chain(chain: list[dict[str, Any]], report: Report) -> None:
    """Step 1: every digest, every link, every sequence number."""
    previous = GENESIS
    for index, entry in enumerate(chain):
        stated = str(entry.get("entry_hash", ""))
        recomputed = entry_hash(entry)
        if not report.check(
            stated == recomputed,
            f"entry {index}: entry_hash is {stated or 'missing'}, recomputes to {recomputed}",
        ):
            return
        if not report.check(
            str(entry.get("prev_hash", "")) == previous,
            f"entry {index}: prev_hash is {entry.get('prev_hash')!r}, expected {previous!r}",
        ):
            return
        if not report.check(
            entry.get("seq") == index,
            f"entry {index}: seq is {entry.get('seq')!r} (an entry was deleted or reordered)",
        ):
            return
        previous = stated
    report.note(f"chain: {len(chain)} entries, intact, tip {previous[:16]}…")


def verify_reveals(chain: list[dict[str, Any]], report: Report) -> None:
    """Step 2: every opened prediction is the one committed to, months earlier."""
    seals = {int(e["seq"]): e for e in chain if e.get("kind") == "seal"}
    opened = withheld = 0
    for entry in chain:
        if entry.get("kind") != "reveal":
            continue
        seal = seals.get(int(entry.get("seal_seq", -1)))
        if not report.check(
            seal is not None,
            f"reveal at seq {entry.get('seq')} points at seal {entry.get('seal_seq')}, "
            "which is not in this chain",
        ):
            continue
        assert seal is not None
        report.check(
            entry.get("commitment") == seal.get("commitment"),
            f"reveal at seq {entry.get('seq')}: commitment does not match the seal it names. "
            "Check the commitment rather than the pointer; this is the pointer lying.",
        )
        report.check(
            str(seal.get("sealed_on", "")) <= str(entry.get("resolved_on", "")),
            f"reveal at seq {entry.get('seq')}: resolved before it was sealed",
        )
        if entry.get("withheld"):
            withheld += 1
            report.check(
                "nonce" not in entry and "prediction" not in entry,
                f"reveal at seq {entry.get('seq')} is marked withheld but carries its text; "
                "one of the two is wrong",
            )
            report.check(
                entry.get("probability") is not None and entry.get("baseline") is not None,
                f"reveal at seq {entry.get('seq')} is withheld and publishes no probability "
                "or baseline, so its contribution to the scoreboard cannot be recomputed",
            )
            continue
        opened += 1
        recomputed = commitment(entry.get("prediction"), str(entry.get("nonce", "")))
        report.check(
            recomputed == entry.get("commitment"),
            f"reveal at seq {entry.get('seq')}: the published prediction and nonce hash to "
            f"{recomputed}, not to the sealed commitment {entry.get('commitment')}. This is "
            "the whole point of the record and it does not check out.",
        )
    report.note(f"reveals: {opened} opened in full and verified, {withheld} with the text withheld")
    if withheld:
        report.note(
            "  a withheld reveal publishes the probability, the baseline, the outcome, the "
            "category and both pseudonyms, and counts in every statistic. What is withheld "
            "is the claim's wording and its nonce."
        )


def verify_accounting(
    chain: list[dict[str, Any]], scoreboard: dict[str, Any], report: Report
) -> None:
    """Step 3: nobody hid a loser. Do this one first if you only do one."""
    seals = [e for e in chain if e.get("kind") == "seal"]
    reveals = [e for e in chain if e.get("kind") == "reveal"]
    revealed = {r.get("commitment") for r in reveals}
    accounting = scoreboard.get("accounting", {})

    if "sealed" in accounting:
        report.check(
            int(accounting["sealed"]) == len(seals),
            f"scoreboard says {accounting.get('sealed')} sealed; the chain has {len(seals)}",
        )
    if "revealed" in accounting:
        report.check(
            int(accounting["revealed"]) == len(reveals),
            f"scoreboard says {accounting.get('revealed')} revealed; the chain has {len(reveals)}",
        )
    if "text_withheld" in accounting:
        report.check(
            int(accounting["text_withheld"]) == sum(1 for r in reveals if r.get("withheld")),
            "scoreboard's withheld count does not match the chain's",
        )

    # The sharpest check in VERIFY.md, and it needs only chain.jsonl: name an overdue
    # commitment yourself, by its quarter, and ask about that one line.
    as_of = str(scoreboard.get("as_of", ""))[:10]
    charged = int(accounting.get("charged_as_miss", 0))
    overdue = [
        s
        for s in seals
        if s.get("commitment") not in revealed
        and as_of
        and quarter_ended_before(str(s.get("deadline_quarter", "")), as_of)
    ]
    report.check(
        len(overdue) <= charged,
        f"{len(overdue)} sealed prediction(s) are past their deadline quarter with no "
        f"reveal, but the scoreboard charges only {charged} as a miss. Every sealed "
        "commitment must resolve publicly.",
    )
    report.note(
        f"accounting: {len(seals)} sealed, {len(reveals)} revealed, "
        f"{len(overdue)} past their deadline quarter and unrevealed, {charged} charged as a miss"
    )


def verify_sample_size(
    chain: list[dict[str, Any]], scoreboard: dict[str, Any], report: Report
) -> None:
    """Step 4: the effective sample size is the group count, so check the group count.

    Two counts, and the second is the one that matters. Clusters say how many distinct claims
    were made; correlation groups say how many independent ones those amount to, and every
    interval on the scoreboard is resampled over groups. A record that inflates either is
    claiming a larger sample than it has.
    """
    clusters = {e["cluster_pseudonym"] for e in chain if e.get("cluster_pseudonym")}
    groups = {
        e["correlation_group_pseudonym"] for e in chain if e.get("correlation_group_pseudonym")
    }
    headline = scoreboard.get("headline") or {}
    for name, seen, claimed in (
        ("clusters", clusters, headline.get("clusters")),
        ("correlation groups", groups, headline.get("correlation_groups")),
    ):
        if claimed is None or not seen:
            continue
        report.check(
            int(claimed) <= len(seen),
            f"the scoreboard resamples over {claimed} {name}; the chain contains only "
            f"{len(seen)} distinct. A larger count is a larger effective sample size than "
            "the record supports.",
        )
    report.note(
        f"sample size: {len(clusters)} distinct cluster(s) and {len(groups)} correlation "
        f"group(s) in the chain"
    )


def verify_scores(chain: list[dict[str, Any]], report: Report) -> None:
    """Step 5: recompute the scores yourself. No published number should need trusting."""
    ours = theirs = Decimal(0)
    scored = skipped = 0
    for entry in chain:
        if entry.get("kind") != "reveal" or entry.get("outcome") not in ("TRUE", "FALSE"):
            continue
        if entry.get("withheld"):
            p = number(entry.get("probability"))
            q = number((entry.get("baseline") or {}).get("probability"))
        else:
            prediction = entry.get("prediction") or {}
            p = number(prediction.get("probability"))
            q = number((prediction.get("baseline") or {}).get("probability"))
        if p is None or q is None:
            skipped += 1
            continue
        outcome = Decimal(1) if entry["outcome"] == "TRUE" else Decimal(0)
        ours += (p - outcome) ** 2
        theirs += (q - outcome) ** 2
        scored += 1
    report.check(
        skipped == 0,
        f"{skipped} resolved reveal(s) publish no probability or no baseline, so their "
        "contribution to the scoreboard cannot be recomputed from this file",
    )
    if scored:
        report.note(
            f"scores: {scored} settled prediction(s) recomputed from this file — mean Brier "
            f"{ours / scored:.4f} for us against {theirs / scored:.4f} for the market. Lower "
            "is better; the scoreboard's own headline is computed over correlation groups "
            "rather than over predictions, which is why it will not equal this."
        )


def verify_policies(chain: list[dict[str, Any]], report: Report) -> None:
    """Step 6: catch a quiet change to the rules the record is scored under.

    Two things. A version that appears with two different hashes means the rules were edited
    without the version moving — the quiet rescoring of an old record under new rules. And
    every entry sealed or revealed under a policy must name a hash that was actually
    registered in this chain, because a policy nobody can see is a policy nobody can check.
    """
    hashes: dict[str, set[str]] = {}
    for entry in chain:
        version = entry.get("policy_version")
        digest = entry.get("policy_hash")
        if version is None or digest is None:
            continue
        hashes.setdefault(str(version), set()).add(str(digest))
    for version, digests in sorted(hashes.items()):
        report.check(
            len(digests) == 1,
            f"policy {version!r} appears with {len(digests)} different hashes; the rules "
            "changed without the version changing",
        )
    registered = {str(e["policy_hash"]) for e in chain if e.get("kind") == "policy"}
    if registered:
        for entry in chain:
            digest = entry.get("policy_hash")
            if digest is None or str(digest) in registered:
                continue
            report.check(
                False,
                f"entry {entry.get('seq')} was sealed under policy {digest}, which this "
                "chain never registered. The rules it was scored under are not published.",
            )
            break
    if hashes:
        report.note(f"policies: {len(hashes)} version(s) — {', '.join(sorted(hashes))}")


def verify_publications(directory: Path, chain: list[dict[str, Any]], report: Report) -> None:
    """Step 7: the publication ledger is itself a chain, and its counts must fit the record."""
    rows = read_jsonl(directory / "publications.jsonl")
    if not rows:
        return
    previous = GENESIS
    sealed_so_far = 0
    for index, row in enumerate(rows):
        stated = str(row.get("entry_hash", ""))
        if not report.check(
            stated == entry_hash(row), f"publications.jsonl line {index}: entry_hash is wrong"
        ):
            return
        if not report.check(
            str(row.get("prev_hash", "")) == previous,
            f"publications.jsonl line {index}: prev_hash does not link to the line before it",
        ):
            return
        if not report.check(
            row.get("seq") == index,
            f"publications.jsonl line {index}: seq is {row.get('seq')!r}. Publication is "
            "unconditional, so a gap is an outage or a lie, not a quiet week.",
        ):
            return
        if not report.check(
            int(row.get("sealed_total", 0)) >= sealed_so_far,
            f"publications.jsonl line {index}: the running count of sealed commitments went "
            "down. Commitments are never unsealed.",
        ):
            return
        sealed_so_far = int(row.get("sealed_total", 0))
        previous = stated
    seals = sum(1 for e in chain if e.get("kind") == "seal")
    report.check(
        sealed_so_far == seals,
        f"the newest publication claims {sealed_so_far} sealed commitments; chain.jsonl "
        f"holds {seals}",
    )
    report.check(
        str(rows[-1].get("chain_tip", "")) == (chain[-1]["entry_hash"] if chain else GENESIS),
        "the newest publication names a chain tip that is not this chain's tip",
    )
    report.note(
        f"publications: {len(rows)} in an unbroken ledger, newest claiming {sealed_so_far} "
        "sealed commitment(s)"
    )


def verify_manifest(directory: Path, report: Report) -> None:
    """Step 8: the files are the files."""
    manifest_path = directory / "MANIFEST.json"
    if not manifest_path.exists():
        report.check(False, "MANIFEST.json is missing")
        return
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    for name, expected in sorted(manifest.get("files", {}).items()):
        path = directory / name
        if not report.check(path.exists(), f"{name} is listed in MANIFEST.json but missing"):
            continue
        actual = hashlib.sha256(path.read_bytes()).hexdigest()
        report.check(actual == expected, f"{name}: sha256 is {actual}, manifest says {expected}")
    report.note(f"manifest: {len(manifest.get('files', {}))} files, digests match")


def verify_tip(directory: Path, chain: list[dict[str, Any]], report: Report) -> None:
    """Step 9: the publication signature, where one is present."""
    path = directory / "tip.json"
    if not path.exists():
        report.note(
            "tip.json: absent. Nobody has signed this publication, so it proves nothing about "
            "who produced it beyond the hashes themselves."
        )
        return
    tip = json.loads(path.read_text(encoding="utf-8"))
    expected = chain[-1]["entry_hash"] if chain else None
    report.check(
        tip.get("tip") == expected,
        f"tip.json signs the digest {tip.get('tip')}, but chain.jsonl ends at {expected}",
    )
    report.check(
        int(tip.get("entries", -1)) == len(chain),
        f"tip.json covers {tip.get('entries')} entries; chain.jsonl has {len(chain)}",
    )
    actor = tip.get("actor")
    public_keys = tip.get("public_keys") or {}
    if not isinstance(actor, dict) or not public_keys:
        report.check(False, "tip.json carries no actor envelope or no public key to check it")
        return
    # A broken install is caught as widely as a missing one. An import of `cryptography`
    # whose native half is unusable does not raise ImportError: it can abort inside the Rust
    # extension and surface as a panic, which does not inherit from Exception, and a reader
    # checking a record should get one plain line rather than somebody else's traceback.
    try:
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    except (KeyboardInterrupt, SystemExit):
        raise
    except BaseException as error:  # noqa: BLE001
        report.cannot_check(
            "tip.json: its tip and entry count match this chain, but the Ed25519 signature "
            "was NOT checked. That needs the `cryptography` package, which is the only thing "
            f"here outside the standard library, and importing it failed: {type(error).__name__}. "
            "Install it with `python3 -m pip install cryptography` and run this again; "
            "VERIFY.md gives the bytes to check the signature against by hand."
        )
        return
    signed = {
        "actor": {k: v for k, v in actor.items() if k != "signature"},
        "payload": {
            "tip": tip.get("tip"),
            "entries": tip.get("entries"),
            "exported_at": tip.get("exported_at"),
        },
    }
    message = SIGNATURE_DOMAIN + b"\x00" + canonical(signed)
    key_id = str(actor.get("key_id", ""))
    if not report.check(
        key_id in public_keys,
        f"tip.json is signed by key {key_id!r}, whose public half it does not publish",
    ):
        return
    try:
        Ed25519PublicKey.from_public_bytes(bytes.fromhex(public_keys[key_id])).verify(
            bytes.fromhex(str(actor.get("signature", ""))), message
        )
    except (InvalidSignature, ValueError) as error:
        report.check(False, f"tip.json: the signature does not check out ({error})")
        return
    report.note(f"tip.json: signed by {key_id} over this exact tip, signature valid")


# -- OpenTimestamps, enough of it to read a proof without leaving this machine ---------
#
# A proof is a tree: a root digest, edges that transform the message, leaves that attest
# something about the transformed message. Reading one needs no cryptography and no network,
# so this script reads one — what it cannot do is check the Bitcoin chain, which is `ots
# verify`'s job and which this script says out loud it is not doing.

OTS_MAGIC = b"\x00OpenTimestamps\x00\x00Proof\x00\xbf\x89\xe2\xe8\x84\xe8\x92\x94"
OTS_PENDING = bytes.fromhex("83dfe30d2ef90c8e")
OTS_BITCOIN = bytes.fromhex("0588960d73d71901")
OTS_BINARY_OPS = frozenset({0xF0, 0xF1})
OTS_UNARY_OPS = frozenset({0x02, 0x03, 0x08, 0x67, 0xF2, 0xF3})
OTS_MAX_DEPTH = 256
OTS_MAX_BYTES = 1 << 20


class OtsBroken(ValueError):
    """These bytes are not an OpenTimestamps proof, or not all of one."""


def read_ots(data: bytes) -> tuple[str, set[str], list[int]]:
    """The proof's root digest, the kinds of attestation in it, and the Bitcoin heights.

    Every length is checked before it is believed and every byte has to be accounted for:
    these files come from a calendar we do not control, and trailing bytes are how a second
    structure would ride along inside a file we publish.
    """
    if len(data) > OTS_MAX_BYTES:
        raise OtsBroken(f"{len(data)} bytes is larger than any proof this record makes")
    pos = 0

    def take(count: int) -> bytes:
        nonlocal pos
        if pos + count > len(data):
            raise OtsBroken(f"truncated at offset {pos}")
        pos += count
        return data[pos - count : pos]

    def varuint() -> int:
        value = 0
        shift = 0
        while True:
            byte = take(1)[0]
            value |= (byte & 0x7F) << shift
            if not byte & 0x80:
                return value
            shift += 7
            if shift > 63:
                raise OtsBroken("a varuint longer than 64 bits")

    def varbytes() -> bytes:
        length = varuint()
        if length > 4096:
            raise OtsBroken(f"a {length}-byte string inside a proof")
        return take(length)

    if take(len(OTS_MAGIC)) != OTS_MAGIC:
        raise OtsBroken("the magic header is not OpenTimestamps'")
    version = varuint()
    if version != 1:
        raise OtsBroken(f"proof version {version}")
    if take(1)[0] != 0x08:
        raise OtsBroken("the file hash is not SHA-256")
    digest = take(32)

    kinds: set[str] = set()
    heights: list[int] = []

    def node(depth: int) -> None:
        if depth > OTS_MAX_DEPTH:
            raise OtsBroken("nested deeper than any real proof")
        while True:
            tag = take(1)[0]
            more = tag == 0xFF
            if more:
                tag = take(1)[0]
            if tag == 0x00:
                attestation, payload = take(8), varbytes()
                if attestation == OTS_BITCOIN:
                    kinds.add("bitcoin")
                    heights.append(_ots_varuint(payload))
                elif attestation == OTS_PENDING:
                    kinds.add("pending")
                else:
                    kinds.add(attestation.hex())
            elif tag in OTS_BINARY_OPS:
                varbytes()
                node(depth + 1)
            elif tag in OTS_UNARY_OPS:
                node(depth + 1)
            else:
                raise OtsBroken(f"unknown operation 0x{tag:02x}")
            if not more:
                return

    node(0)
    if pos != len(data):
        raise OtsBroken(f"{len(data) - pos} byte(s) after the end of the proof")
    return digest.hex(), kinds, sorted(heights)


def _ots_varuint(payload: bytes) -> int:
    value = 0
    shift = 0
    for index, byte in enumerate(payload):
        value |= (byte & 0x7F) << shift
        if not byte & 0x80:
            if index != len(payload) - 1:
                raise OtsBroken("a Bitcoin attestation with bytes after its height")
            return value
        shift += 7
        if shift > 63:
            raise OtsBroken("a block height longer than 64 bits")
    raise OtsBroken("a Bitcoin attestation with no height")


def verify_anchors(directory: Path, report: Report) -> None:
    """Step 10: the timestamps, as far as this script can go without Bitcoin.

    Four things, all offline. The anchored run has no gap in it. It reaches the publication
    you are looking at, or is exactly one behind it. Every proof named is here, parses, and
    is a proof of the little file beside it — whose contents are the manifest digest its row
    claims. And a row that says "confirmed" names a proof that really carries a Bitcoin
    attestation at the height the row states.

    What is left is the part that needs the chain: whether that block really contains that
    commitment. Run `ots verify` on the files in `anchors/`, ideally against your own node.
    Nothing here checks it and nothing here pretends to.
    """
    rows = read_jsonl(directory / "anchors" / "index.jsonl")
    if not rows:
        report.note(
            "anchors: none. This record proves ORDER and not TIME — a chain built in one "
            "sitting after the outcomes were known would still pass every check above."
        )
        return

    seqs = sorted(int(r["publication_seq"]) for r in rows)
    for previous, seq in zip(seqs, seqs[1:], strict=False):
        if not report.check(
            seq == previous + 1,
            f"anchors: publication {previous + 1} is missing from the index. Publication is "
            "unconditional, so a gap is an outage or a lie, not a quiet week.",
        ):
            break

    _verify_anchor_tail(directory, rows, seqs, report)
    _verify_anchor_proofs(directory, rows, report)


def _verify_anchor_tail(
    directory: Path, rows: list[dict[str, Any]], seqs: list[int], report: Report
) -> None:
    """The newest row against the publication in front of you.

    One publication behind is the normal state and not a fault: a publication is stamped as
    it is delivered, which is after the files you are reading were built, so its row travels
    with the *next* publication. Two behind is a record that stopped anchoring, which is what
    somebody would do to leave an inconvenient day unstamped.
    """
    ledger = read_jsonl(directory / "publications.jsonl")
    if not ledger:
        return
    current = len(ledger) - 1
    manifest_path = directory / "MANIFEST.json"
    manifest_digest = (
        hashlib.sha256(manifest_path.read_bytes()).hexdigest() if manifest_path.exists() else None
    )
    newest = max(seqs)
    if seqs[0] > 0:
        report.note(
            f"anchors: the anchored run starts at publication {seqs[0]}. Publications before "
            "it were made before this record was anchored at all and can never be stamped: a "
            "timestamp taken today would say today."
        )
    if newest > current:
        report.check(
            False,
            f"anchors: there is a row for publication {newest}, but publications.jsonl ends "
            f"at {current}. An anchor row for a publication nobody has is evidence for a file "
            "that is not in this record.",
        )
    elif newest == current:
        row = next(r for r in rows if int(r["publication_seq"]) == current)
        if manifest_digest is not None:
            report.check(
                str(row.get("manifest_sha256")) == manifest_digest,
                f"anchors: the row for publication {current} stamps a digest that is not "
                "this publication's MANIFEST.json",
            )
    elif newest == current - 1:
        report.note(
            f"anchors: publication {current} has no row yet. A publication is stamped as it "
            "is delivered, so its row arrives with the next one; every publication before it "
            "is anchored."
        )
    else:
        report.check(
            False,
            f"anchors: publications {newest + 1} to {current} carry no anchor row, and only "
            "the newest may. A record that stops anchoring is one that chooses which days to "
            "timestamp.",
        )


def _verify_anchor_proofs(directory: Path, rows: list[dict[str, Any]], report: Report) -> None:
    """Every row against the bytes it names, and every claim of confirmation against a proof."""
    confirmed = 0
    pending: list[int] = []
    unstamped: list[int] = []
    heights: list[int] = []
    for row in rows:
        seq = int(row["publication_seq"])
        proof = row.get("proof")
        if not proof:
            if not report.check(
                not row.get("anchored") and not row.get("confirmed"),
                f"anchors: publication {seq} is marked anchored but names no proof file",
            ):
                continue
            unstamped.append(seq)
            continue
        path = directory / str(proof)
        if not report.check(
            path.is_file(),
            f"anchors: publication {seq} names {proof}, which is not in this record",
        ):
            continue
        try:
            digest, kinds, found = read_ots(path.read_bytes())
        except (OtsBroken, OSError) as error:
            report.check(False, f"anchors: {proof} is not a readable proof ({error})")
            continue
        target = directory / str(proof)[: -len(".ots")]
        if not report.check(
            target.is_file(),
            f"anchors: {proof} is a proof of {target.name}, which is not in this record",
        ):
            continue
        if not report.check(
            digest == hashlib.sha256(target.read_bytes()).hexdigest(),
            f"anchors: {proof} is a proof of bytes that are not {target.name}. A row cannot "
            "borrow another publication's evidence.",
        ):
            continue
        if not report.check(
            target.read_text(encoding="utf-8").strip() == str(row.get("manifest_sha256")),
            f"anchors: {target.name} holds a digest that is not the one publication {seq}'s "
            "row names",
        ):
            continue
        if row.get("confirmed"):
            if not report.check(
                "bitcoin" in kinds,
                f"anchors: publication {seq} is marked confirmed, but {proof} carries no "
                "Bitcoin attestation. Confirmed means a proof in a block, never a calendar's "
                "promise.",
            ):
                continue
            stated = row.get("block_height")
            if not report.check(
                stated in found,
                f"anchors: publication {seq} claims Bitcoin block {stated}; {proof} attests "
                f"{found}",
            ):
                continue
            confirmed += 1
            heights.extend(found)
        else:
            pending.append(seq)

    report.note(
        f"anchors: {len(rows)} publication(s) stamped, {confirmed} with a Bitcoin attestation"
        + (f", {len(pending)} still pending" if pending else "")
        + (f", {len(unstamped)} that no calendar answered for" if unstamped else "")
        + (f". The earliest block attested is {min(heights)}" if heights else "")
        + ". This script read the proofs structurally and did NOT check Bitcoin: run `ots "
        "verify` on the files in anchors/, which needs a Bitcoin node it can reach "
        "(`--bitcoin-node <url>`, or your local configuration) and checks nothing without one."
    )


def main(argv: list[str]) -> int:
    directory = Path(argv[1] if len(argv) > 1 else ".")
    chain = read_jsonl(directory / "chain.jsonl")
    reveals = read_jsonl(directory / "reveals.jsonl")
    scoreboard_path = directory / "scoreboard.json"
    scoreboard: dict[str, Any] = {}
    if scoreboard_path.exists():
        scoreboard = json.loads(scoreboard_path.read_text(encoding="utf-8"))

    report = Report()
    verify_chain(chain, report)
    if not report.failures:
        in_chain = [e for e in chain if e.get("kind") == "reveal"]
        report.check(
            [e.get("entry_hash") for e in in_chain] == [e.get("entry_hash") for e in reveals],
            "reveals.jsonl does not match the reveal entries in chain.jsonl",
        )
        verify_reveals(chain, report)
        verify_accounting(chain, scoreboard, report)
        verify_sample_size(chain, scoreboard, report)
        verify_scores(chain, report)
        verify_policies(chain, report)
        verify_publications(directory, chain, report)
    verify_manifest(directory, report)
    verify_tip(directory, chain, report)
    verify_anchors(directory, report)

    for note in report.notes:
        print(note)
    if report.failures:
        print()
        print(f"FAILED: {len(report.failures)} problem(s). The first one:")
        print(f"  {report.failures[0]}")
        for extra in report.failures[1:]:
            print(f"  (also) {extra}")
        return 1
    if report.unmade:
        print()
        print(f"INCOMPLETE: {len(report.unmade)} check(s) could not be made on this machine.")
        print("Nothing here failed — that is exit 1. This is exit 2. What was not checked:")
        for message in report.unmade:
            print(f"  {message}")
        return 2
    print()
    print("OK. Every check in VERIFY.md passes on these files.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
