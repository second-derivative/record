#!/usr/bin/env python3
"""Verify Second Derivative's public record.

    python3 verify.py [directory]

It needs Python 3.10 or newer. An older Python exits 2 before checking anything, because
exit 1 is an accusation against the record and a reader's Python is not the record's fault.

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

import datetime as dt
import hashlib
import json
import math
import sys
from decimal import Decimal, InvalidOperation
from pathlib import Path
from statistics import NormalDist
from typing import Any

#: The oldest Python this runs on: `zip(..., strict=)` and an `int | None` isinstance are 3.10.
MINIMUM_PYTHON = (3, 10)

if sys.version_info < MINIMUM_PYTHON:
    # Checked before anything else runs. Left to fail on its own, an older Python raised a
    # TypeError halfway through step 10 and exited 1 -- the one exit that says something
    # against the record -- over the reader's interpreter. The file stays parseable by 3.8
    # so this line is reached at all.
    print(
        f"INCOMPLETE: this script needs Python {MINIMUM_PYTHON[0]}.{MINIMUM_PYTHON[1]} or newer "
        f"and this is {sys.version.split()[0]}; nothing was checked and nothing failed."
    )
    raise SystemExit(2)

COMMIT_DOMAIN = b"sd/record/commit/v1"
NUMBERS_DOMAIN = b"sd/record/numbers/v1"
ENTRY_DOMAIN = b"sd/record/entry/v1"
SIGNATURE_DOMAIN = b"sd/core/actor/v1"
REGISTRY_DOMAIN = b"sd/record/registry/v1"
REVIEW_DOMAIN = b"sd/record/review/v1"
GENESIS = "genesis"

REVIEW_CLASSES = ("question", "data", "duplicate", "program")
WHOLE_BATCH_ONLY = ("program",)
REVIEW_FIELDS = frozenset(
    {
        "batch",
        "decided_on",
        "held",
        "released",
        "discarded",
        "batch_discarded_as",
        "lapsed",
        "batch_fingerprint",
    }
)
AWAITING_FIELDS = frozenset(
    {"on", "held_ever", "waiting", "oldest_waiting_days", "batches_decided"}
)
ENTRY_FRAME = frozenset({"kind", "seq", "prev_hash", "entry_hash", "actor_digest"})


def canonical(value: Any) -> bytes:
    """The one serialisation this record hashes: sorted keys, tight separators, strict."""
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False
    ).encode("utf-8")


def entry_hash(entry: dict[str, Any]) -> str:
    body = {k: v for k, v in entry.items() if k != "entry_hash"}
    return hashlib.sha256(ENTRY_DOMAIN + b"\x00" + canonical(body)).hexdigest()


NUMBERS_FIELDS = ("probability", "baseline", "baseline_visible_to_forecaster")
"""What a seal's ``numbers_commitment`` covers, in the payload ``{field: value}``."""


def is_digest(value: Any) -> bool:
    """64 lowercase hex characters: a SHA-256 digest, or a 32-byte nonce."""
    return (
        isinstance(value, str) and len(value) == 64 and all(c in "0123456789abcdef" for c in value)
    )


def commitment(prediction: Any, nonce_hex: str, domain: bytes = COMMIT_DOMAIN) -> str:
    return hashlib.sha256(
        domain + b"\x00" + canonical(prediction) + b"\x00" + bytes.fromhex(nonce_hex)
    ).hexdigest()


def registry_leaf(entry: Any, salt_hex: str) -> str:
    """One leaf of the quantity-registry tree: a salted digest of one entry."""
    return hashlib.sha256(
        REGISTRY_DOMAIN + b"\x00" + bytes.fromhex(salt_hex) + b"\x00" + canonical(entry)
    ).hexdigest()


def registry_root_from(proof: dict[str, Any]) -> str:
    """Fold a quantity proof back to the root the seal published.

    Twelve lines, and they are the whole of it: hash the entry with the salt, then walk up,
    hashing each sibling on the side the step names. The leaf and the interior node are
    tagged with different bytes, so a leaf cannot be passed off as an interior node.
    """
    running = registry_leaf(proof["entry"], str(proof["salt"]))
    for step in proof.get("path", []):
        sibling = bytes.fromhex(str(step["hash"]))
        mine = bytes.fromhex(running)
        pair = sibling + mine if step["side"] == "left" else mine + sibling
        running = hashlib.sha256(REGISTRY_DOMAIN + b"\x01" + pair).hexdigest()
    return running


def review_fingerprint(salt_hex: str, rows: list[list[str]]) -> str:
    """The batch fingerprint, for an auditor handed a batch's salt and its forecasts.

    ``rows`` is one ``[sha256(canonical(forecast)), disposition, class]`` per forecast, the
    class empty unless the disposition is ``discarded``, sorted. Not run by :func:`main`: the
    salt is never published, and opening a fingerprint is an audit, not a public check."""
    return hashlib.sha256(
        REVIEW_DOMAIN + b"\x00" + bytes.fromhex(salt_hex) + b"\x00" + canonical(sorted(rows))
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


class _RepeatedKey(ValueError):
    pass


def _no_repeated_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    """A JSON object whose keys are all different. ``json`` keeps the last of two silently."""
    seen: dict[str, Any] = {}
    for key, value in pairs:
        if key in seen:
            raise _RepeatedKey(f"the key {key!r} appears twice in one object")
        seen[key] = value
    return seen


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    """Every line of a JSONL file, each an object with no key given twice.

    Two copies of one key would let a line say two things, and a reader would see whichever
    their JSON library kept. Refused, so every reader reads the same line.
    """
    rows: list[dict[str, Any]] = []
    if not path.exists():
        return rows
    for lineno, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        text = line.strip()
        if not text:
            continue
        try:
            rows.append(json.loads(text, object_pairs_hook=_no_repeated_keys))
        except json.JSONDecodeError as error:
            raise SystemExit(f"FAIL {path.name}:{lineno} is not valid JSON ({error})") from None
        except _RepeatedKey as error:
            raise SystemExit(f"FAIL {path.name}:{lineno} is not one reading: {error}") from None
    return rows


def read_json(path: Path) -> Any:
    """One JSON file, with no key given twice in any object, as :func:`read_jsonl` reads a
    line. A scoreboard saying ``"correlation_groups": 99, "correlation_groups": 36`` is two
    boards at once, and which one a reader sees would depend on their library."""
    try:
        return json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=_no_repeated_keys)
    except json.JSONDecodeError as error:
        raise SystemExit(f"FAIL {path.name} is not valid JSON ({error})") from None
    except _RepeatedKey as error:
        raise SystemExit(f"FAIL {path.name} is not one reading: {error}") from None


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
        if entry.get("kind") == "seal":
            root = str(entry.get("registry_root", ""))
            # Structural at the seal and checkable at the reveal. A root on its own is
            # opaque by design -- one salted digest over the registry the claim's quantity
            # was checked against, published before the outcome so the definition cannot be
            # adjusted afterwards. What it must be is present and the right shape; what it
            # means is settled by ``verify_reveals`` when the proof that opens it arrives.
            if not report.check(
                len(root) == 64 and all(c in "0123456789abcdef" for c in root),
                f"entry {index}: seal carries registry_root {root or 'missing'!r}, which is "
                "not a digest; nothing published later could be opened against it",
            ):
                return
            report.check(
                is_digest(entry.get("numbers_commitment")),
                f"entry {index}: seal carries numbers_commitment "
                f"{entry.get('numbers_commitment', 'missing')!r}, which is not a digest; the "
                "probability, baseline and arm its reveal publishes could not be held to it",
            )
        previous = stated
    report.note(f"chain: {len(chain)} entries, intact, tip {previous[:16]}…")


def verify_reveals(chain: list[dict[str, Any]], report: Report) -> None:
    """Step 2: every opened prediction is the one committed to, months earlier."""
    seals = {int(e["seq"]): e for e in chain if e.get("kind") == "seal"}
    opened = withheld = 0
    revealed: dict[int, Any] = {}
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
        # A seal is opened once. A second reveal naming the same seal could borrow its
        # commitment, its numbers and its nonce, and check out on every other line here.
        seal_seq = int(entry["seal_seq"])
        report.check(
            seal_seq not in revealed,
            f"reveal at seq {entry.get('seq')} opens seal {seal_seq}, which the reveal at seq "
            f"{revealed.get(seal_seq)} already opened; a seal is opened once",
        )
        revealed.setdefault(seal_seq, entry.get("seq"))
        report.check(
            entry.get("cluster_pseudonym") == seal.get("cluster_pseudonym"),
            f"reveal at seq {entry.get('seq')} is in cluster {entry.get('cluster_pseudonym')!r} "
            f"and the seal it names in {seal.get('cluster_pseudonym')!r}; one of the two is "
            "not this prediction's",
        )
        report.check(
            entry.get("commitment") == seal.get("commitment"),
            f"reveal at seq {entry.get('seq')}: commitment does not match the seal it names. "
            "Check the commitment rather than the pointer; this is the pointer lying.",
        )
        report.check(
            str(seal.get("sealed_on", "")) <= str(entry.get("resolved_on", "")),
            f"reveal at seq {entry.get('seq')}: resolved before it was sealed",
        )
        # The numbers every score is computed from, opened against the seal's own commitment
        # to them. On a withheld reveal this is the only thing that binds them to the seal;
        # on an open one it checks the seal's two commitments agree.
        source = entry if entry.get("withheld") else (entry.get("prediction") or {})
        numbers_nonce = entry.get("numbers_nonce")
        if report.check(
            is_digest(numbers_nonce),
            f"reveal at seq {entry.get('seq')} gives its numbers_nonce as "
            f"{entry.get('numbers_nonce', 'nothing')!r}; without it the probability, baseline "
            "and arm it publishes cannot be checked against its seal",
        ):
            numbers = {field: source.get(field) for field in NUMBERS_FIELDS}
            opened_numbers = commitment(numbers, str(numbers_nonce), NUMBERS_DOMAIN)
            report.check(
                opened_numbers == seal.get("numbers_commitment"),
                f"reveal at seq {entry.get('seq')}: its probability, baseline and arm with its "
                f"numbers_nonce hash to {opened_numbers}, not to the numbers_commitment its seal "
                f"published, {seal.get('numbers_commitment')}. The numbers it is scored on are "
                "not the ones sealed.",
            )
        if entry.get("withheld"):
            withheld += 1
            report.check(
                "nonce" not in entry and "prediction" not in entry,
                f"reveal at seq {entry.get('seq')} is marked withheld but carries its text; "
                "one of the two is wrong",
            )
            report.check(
                "quantity_proof" not in entry,
                f"reveal at seq {entry.get('seq')} is marked withheld and carries its "
                "quantity proof, which names the quantity the withholding is withholding",
            )
            report.check(
                entry.get("probability") is not None and entry.get("baseline") is not None,
                f"reveal at seq {entry.get('seq')} is withheld and publishes no probability "
                "or baseline, so its contribution to the scoreboard cannot be recomputed",
            )
            report.check(
                type(entry.get("baseline_visible_to_forecaster")) is bool,
                f"reveal at seq {entry.get('seq')} is withheld and gives which arm it was in "
                f"as {entry.get('baseline_visible_to_forecaster', 'nothing')!r}; it must say "
                "true or false, or no stage of the scoreboard can be counted",
            )
            continue
        # An open reveal states its arm inside its prediction, where the commitment covers
        # it. A second copy beside it is covered by nothing and could contradict it.
        report.check(
            "baseline_visible_to_forecaster" not in entry,
            f"reveal at seq {entry.get('seq')} is open and also carries "
            "baseline_visible_to_forecaster outside its prediction, where the commitment does "
            "not cover it; only a withheld reveal carries it there",
        )
        opened += 1
        verify_quantity_proof(entry, seal, report)
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
            "  a withheld reveal publishes the probability, the baseline, which arm it was in, "
            "the outcome, the category and both pseudonyms, and counts in every statistic. "
            "What is withheld "
            "is the claim's wording and its nonce."
        )


def verify_quantity_proof(entry: dict[str, Any], seal: dict[str, Any], report: Report) -> None:
    """Step 2b: the claim's quantity existed, and meant this, on the day it was sealed.

    The seal published one salted digest over the registry its quantity was checked against.
    This opens that digest on the one entry the claim used: fold the proof back to a root and
    compare. It proves three things at once -- the quantity was in the registry, its
    definition digest and admissible units were what the reveal now says they were, and both
    were fixed before the outcome was known.

    What it does not hand over is the rest of the registry. The path is sibling *hashes*, the
    definition is a digest rather than the text, and the salt only opens the leaf it came
    with, so a reader learns exactly the entry this prediction already names and no other.
    """
    proof = entry.get("quantity_proof")
    where = f"reveal at seq {entry.get('seq')}"
    if not report.check(
        isinstance(proof, dict),
        f"{where} publishes its text and no quantity_proof, so the registry root its seal "
        "committed to can never be opened",
    ):
        return
    assert isinstance(proof, dict)
    try:
        recomputed = registry_root_from(proof)
    except (KeyError, TypeError, ValueError) as exc:
        report.check(False, f"{where}: the quantity proof is malformed ({exc})")
        return
    report.check(
        recomputed == seal.get("registry_root"),
        f"{where}: the quantity proof folds to {recomputed}, not to the registry root "
        f"{seal.get('registry_root')} its seal published. The claim's quantity was not the "
        "one the registry held when this was sealed.",
    )
    prediction = entry.get("prediction")
    if isinstance(prediction, dict):
        form = prediction.get("operational_form")
        if isinstance(form, dict):
            claimed = proof.get("entry", {})
            report.check(
                claimed.get("id") == form.get("quantity"),
                f"{where}: the proof opens {claimed.get('id')!r} and the claim is about "
                f"{form.get('quantity')!r}",
            )
            report.check(
                form.get("unit") in (claimed.get("units") or []),
                f"{where}: the claim's unit {form.get('unit')!r} is not one the registry "
                f"admitted for {claimed.get('id')!r} when this was sealed",
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
    # commitment yourself, by its quarter, and ask about that one line. Per track: the
    # charge lives inside each board, never summed across tracks, so each board answers for
    # the seals under its own policy hash. A scoreboard with no boards charges nothing, and
    # then no sealed commitment may be past its quarter unrevealed.
    as_of = str(scoreboard.get("as_of", ""))[:10]
    boards = scoreboard.get("tracks") or {}
    if not boards and scoreboard.get("headline") is not None:
        boards = {str(scoreboard.get("policy_version")): scoreboard}
    if not boards:
        boards = {"(no board)": {"accounting": {}, "policy_hash": None}}
    overdue_total = charged_total = 0
    for version, board in sorted(boards.items()):
        digest = board.get("policy_hash")
        charged = int((board.get("accounting") or {}).get("charged_as_miss", 0))
        overdue = [
            s
            for s in seals
            if s.get("commitment") not in revealed
            and (digest is None or s.get("policy_hash") == digest)
            and as_of
            and quarter_ended_before(str(s.get("deadline_quarter", "")), as_of)
        ]
        report.check(
            len(overdue) <= charged,
            f"{len(overdue)} sealed prediction(s) under the {version} board are past their "
            f"deadline quarter with no reveal, but that board charges only {charged} as a "
            "miss. Every sealed commitment must resolve publicly.",
        )
        overdue_total += len(overdue)
        charged_total += charged
    report.note(
        f"accounting: {len(seals)} sealed, {len(reveals)} revealed, {overdue_total} past "
        f"their deadline quarter and unrevealed, {charged_total} charged as a miss across "
        f"{len(boards)} board(s), each charged inside its own track"
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
    # One board per track since the fast track, each checked against the reveals sealed
    # under its own policy hash; a scoreboard from before that has one board at the top.
    boards = scoreboard.get("tracks") or {}
    if not boards and scoreboard.get("headline") is not None:
        boards = {str(scoreboard.get("policy_version")): scoreboard}
    for version, board in sorted(boards.items()):
        headline = board.get("headline") or {}
        digest = board.get("policy_hash")
        reveals = [
            e
            for e in chain
            if e.get("kind") == "reveal" and (digest is None or e.get("policy_hash") == digest)
        ]
        track_clusters = {e["cluster_pseudonym"] for e in reveals if e.get("cluster_pseudonym")}
        unit = board.get("resampling_unit") or {}
        block_days = unit.get("block_days")
        blocks: set[Any] = set()
        for e in reveals:
            pseudonym = e.get("correlation_group_pseudonym")
            if not pseudonym:
                continue
            if block_days and e.get("resolution_date"):
                blocks.add((pseudonym, day_ordinal(e["resolution_date"]) // int(block_days)))
            elif not block_days:
                blocks.add(pseudonym)
        track_groups = blocks
        unit_name = (
            f"correlation group x {block_days}-day block" if block_days else "correlation groups"
        )
        for name, seen, claimed in (
            ("clusters", track_clusters, headline.get("clusters")),
            (unit_name, track_groups, headline.get("correlation_groups")),
        ):
            if claimed is None or not seen:
                continue
            report.check(
                int(claimed) <= len(seen),
                f"the scoreboard's {version} board resamples over {claimed} {name}; the chain "
                f"contains only {len(seen)} distinct. A larger count is a larger effective "
                "sample size than the record supports.",
            )
    report.note(
        f"sample size: {len(clusters)} distinct cluster(s) and {len(groups)} correlation "
        f"group(s) in the chain"
    )


HEADLINE_TIERS = ("A_traded", "B_prediction_market")
"""The tiers the headline is computed over. Nothing else enters it."""

REFERENCE_BASE_RATE = 0.5
LARGEST_MARKET_ERROR = 0.5


def detectable_market_error(groups: int, alpha: float, power: float) -> float | None:
    """``sqrt((z_{1-a/2} + z_power)^2 * 4q(1-q) / n)`` at q = 0.5, to four places.

    None when nothing has resolved, and when the answer would exceed 0.5, the largest error a
    market can make at a 50% base rate: below that many groups no error is detectable.
    """
    if groups < 1:
        return None
    unit = NormalDist()
    bracket = (unit.inv_cdf(1.0 - alpha / 2.0) + unit.inv_cdf(power)) ** 2
    q = REFERENCE_BASE_RATE
    delta = math.sqrt(bracket * 4.0 * q * (1.0 - q) / groups)
    return None if delta > LARGEST_MARKET_ERROR else round(delta, 4)


def _is_count(value: Any) -> bool:
    """A group count is an int and nothing else: not 150.0, not True, not "150"."""
    return type(value) is int


def _stage_units(
    reveals: list[dict[str, Any]], policy: dict[str, Any], block_days: Any
) -> dict[str, set[Any]]:
    """Each stage's resampling units, counted from the reveals alone.

    ``headline`` and each ``by_batch.<batch>`` take a reveal that settled TRUE or FALSE in tier
    A or B, is not flagged for contamination, has a baseline inside the policy's
    ``trivial_band``, and was made blind to the market's number; ``baseline_visible_arm`` takes
    the same with the number shown. Every reveal says which arm it was in: an open one inside
    its prediction, a withheld one in its own ``baseline_visible_to_forecaster`` (step 3 fails
    one that does not). Each ``by_tier.<tier>`` takes every settled reveal of that tier.
    """
    band = (policy.get("thresholds") or {}).get("trivial_band") or ["0", "1"]
    low, high = number(band[0]), number(band[1])
    stages: dict[str, set[Any]] = {}
    for entry in reveals:
        if entry.get("outcome") not in ("TRUE", "FALSE"):
            continue
        pseudonym = entry.get("correlation_group_pseudonym")
        if not pseudonym:
            continue
        unit: Any = pseudonym
        if block_days:
            if not entry.get("resolution_date"):
                continue
            unit = (pseudonym, day_ordinal(entry["resolution_date"]) // int(block_days))
        tier = entry.get("baseline_tier")
        stages.setdefault(f"by_tier.{tier}", set()).add(unit)
        if tier not in HEADLINE_TIERS or entry.get("contamination_risk"):
            continue
        prediction = entry.get("prediction") or {}
        baseline = (entry.get("baseline") if entry.get("withheld") else None) or (
            prediction.get("baseline") or {}
        )
        q = number(baseline.get("probability"))
        if q is None or low is None or high is None or not (low <= q <= high):
            continue
        arm = (entry if entry.get("withheld") else prediction).get("baseline_visible_to_forecaster")
        if arm is False:
            stages.setdefault("headline", set()).add(unit)
            stages.setdefault(f"by_batch.{entry.get('batch_id')}", set()).add(unit)
        elif arm is True:
            stages.setdefault("baseline_visible_arm", set()).add(unit)
    return stages


def _figure(groups: int | None, alpha: float, power: float) -> str:
    value = None if groups is None else detectable_market_error(groups, alpha, power)
    return "no figure yet" if value is None else f"{value}"


def verify_detectable_error(
    chain: list[dict[str, Any]], scoreboard: dict[str, Any], report: Report
) -> None:
    """Step 4b: the smallest detectable market error is arithmetic on a count you can make.

    Every count a board states for a stage is the count of that stage's units in the reveals,
    and every figure it states is the formula in VERIFY.md at that count, with alpha and power
    from the policy entry the board names. The figure is absent until it has a value (32
    groups at alpha 0.05 and 80% power), so an absence is checked too: it must mean the count
    is too small, never that a figure was left out. A board with resolved reveals must say how
    many groups it computed on, in an int.
    """
    boards = scoreboard.get("tracks") or {}
    if not boards and scoreboard.get("headline") is not None:
        boards = {str(scoreboard.get("policy_version")): scoreboard}
    policies = {str(e["policy_hash"]): e for e in chain if e.get("kind") == "policy"}
    for version, board in sorted(boards.items()):
        policy = policies.get(str(board.get("policy_hash")))
        if policy is None:
            continue  # step 6b fails a board naming an unregistered policy
        thresholds = policy.get("thresholds") or {}
        alpha, power = number(thresholds.get("alpha")), number(thresholds.get("power"))
        if alpha is None or power is None:
            report.check(
                False,
                f"the {version} policy publishes no alpha or power, so no detectable market "
                "error on its board can be checked",
            )
            continue
        a, b = float(alpha), float(power)
        block_days = (board.get("resampling_unit") or {}).get("block_days")
        reveals = [
            e
            for e in chain
            if e.get("kind") == "reveal" and e.get("policy_hash") == board.get("policy_hash")
        ]
        units = _stage_units(reveals, policy, block_days)
        in_headline = len(units.get("headline", set()))

        # The power block. Absent only on a board with nothing resolved; the note-only block
        # every board had before #111 only while the headline holds fewer than two groups.
        power_block = board.get("power")
        headline = board.get("headline") or {}
        if power_block is not None and not isinstance(power_block, dict):
            report.check(False, f"the {version} board's power block is not an object")
            continue
        if not power_block:
            report.check(
                not reveals,
                f"the {version} board has {len(reveals)} reveal(s) under its policy and no "
                "power block, so it states no detectable market error and no count to check "
                "one against",
            )
        elif "correlation_groups" not in power_block and "detectable_market_error" not in (
            power_block
        ):
            report.check(
                in_headline <= 1,
                f"the {version} board's power block counts no groups; the chain holds "
                f"{in_headline} headline groups, so it must",
            )
        else:
            groups: Any = power_block.get("correlation_groups")
            if report.check(
                _is_count(groups),
                f"the {version} board's power block gives its group count as {groups!r}; a "
                "count is an integer, and the figure beside it is checked against it",
            ):
                report.check(
                    groups == headline.get("correlation_groups"),
                    f"the {version} board's power block counts {groups} groups and its headline "
                    f"{headline.get('correlation_groups')!r}; the figure must be computed on "
                    "the headline's own count",
                )
                report.note(
                    f"detectable market error ({version}): {groups} headline group(s), "
                    f"{_figure(groups, a, b)}"
                )

        # Every stage: its count the chain's, its figure the formula at it.
        stages = [("power", power_block or {}), ("headline", headline)]
        stages += [(f"by_tier.{k}", v) for k, v in sorted((board.get("by_tier") or {}).items())]
        stages += [(f"by_batch.{k}", v) for k, v in sorted((board.get("by_batch") or {}).items())]
        stages.append(("baseline_visible_arm", board.get("baseline_visible_arm") or {}))
        for name, stage in stages:
            if not isinstance(stage, dict):
                continue
            has_count = "correlation_groups" in stage
            count: Any = stage.get("correlation_groups")
            if not has_count:
                report.check(
                    "detectable_market_error" not in stage,
                    f"the {version} board's {name} states a detectable market error and no "
                    "group count it was computed on",
                )
                continue
            if not report.check(
                _is_count(count),
                f"the {version} board's {name} gives its group count as {count!r}; a count is "
                "an integer",
            ):
                continue
            held = len(units.get("headline" if name == "power" else name, set()))
            report.check(
                count == held,
                f"the {version} board's {name} counts {count} groups; the chain holds {held}. "
                "A larger count claims to see a smaller market error than the record can.",
            )
            expected = detectable_market_error(count, a, b)
            if "detectable_market_error" in stage:
                claimed = stage["detectable_market_error"]
                report.check(
                    expected is not None
                    and type(claimed) in (int, float)
                    and round(float(claimed), 4) == expected,
                    f"the {version} board's {name} says the smallest detectable market error "
                    f"is {claimed!r} at {count} groups; the formula gives {expected!r}",
                )
            else:
                report.check(
                    expected is None,
                    f"the {version} board's {name} counts {count} groups, enough for a "
                    f"detectable market error of {expected}, and does not publish one",
                )


def day_ordinal(text: Any) -> int:
    """A ``YYYY-MM-DD`` string as a proleptic-Gregorian ordinal, as the scorer computes it."""
    return dt.date.fromisoformat(str(text)[:10]).toordinal()


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


def verify_tracks(chain: list[dict[str, Any]], scoreboard: dict[str, Any], report: Report) -> None:
    """Step 6b: every board names a registered policy, and nothing pools two of them.

    A board keyed by a version whose hash the chain never registered is a statistic under
    rules nobody can read. And the top level may carry counts over the whole chain but no
    statistic: a headline, a calibration or a power block outside ``tracks`` would be a
    number over rows sealed under different floors, which is the pooling the design forbids.
    The converse holds for anchoring: it is a fact about the whole record, stated once at the
    top level, and a board carrying its own could say the opposite of the record's.
    """
    boards = scoreboard.get("tracks")
    if not isinstance(boards, dict):
        return
    registered = {str(e["policy_hash"]) for e in chain if e.get("kind") == "policy"}
    for version, board in sorted(boards.items()):
        digest = board.get("policy_hash")
        report.check(
            bool(digest) and (not registered or str(digest) in registered),
            f"the scoreboard's {version} board names policy {digest!r}, which this chain "
            "never registered. Its statistics are under rules nobody can read.",
        )
        report.check(
            str(board.get("policy_version")) == str(version),
            f"the board keyed {version!r} says it is {board.get('policy_version')!r}",
        )
        report.check(
            "anchoring" not in board,
            f"the scoreboard's {version} board carries its own `anchoring`. Anchoring is "
            "stated once, at the top level, for the whole record; a track's copy can only "
            "repeat it or contradict it.",
        )
    pooled = {"headline", "by_tier", "by_batch", "calibration", "power", "improvement"} & set(
        scoreboard
    )
    report.check(
        not pooled,
        f"the scoreboard carries {sorted(pooled)} outside `tracks`; a statistic over rows "
        "sealed under different policies pools tracks the record says are never pooled",
    )
    report.note(f"tracks: {len(boards)} board(s) — {', '.join(sorted(boards))}; none pooled")


def _whole(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value >= 0


def _day(value: Any) -> bool:
    try:
        return bool(dt.date.fromisoformat(str(value)).isoformat() == value)
    except ValueError:
        return False


def _review_entry_holds(index: int, entry: dict[str, Any], report: Report) -> bool:
    fields = set(entry) - ENTRY_FRAME
    if not report.check(
        fields == REVIEW_FIELDS,
        f"entry {index}: a review entry carries {sorted(fields)}, not exactly "
        f"{sorted(REVIEW_FIELDS)}",
    ):
        return False
    raw = entry.get("discarded")
    discarded: dict[str, Any] = raw if isinstance(raw, dict) else {}
    counts = [entry.get(k) for k in ("batch", "held", "released", "lapsed")]
    if not report.check(
        isinstance(raw, dict)
        and set(discarded) == set(REVIEW_CLASSES)
        and all(_whole(v) for v in discarded.values())
        and all(_whole(v) for v in counts)
        and _day(entry.get("decided_on")),
        f"entry {index}: a review entry's counts are not whole numbers over exactly the "
        f"classes {list(REVIEW_CLASSES)}, or its day is not a day",
    ):
        return False
    total = entry["released"] + sum(discarded.values()) + entry["lapsed"]
    if not report.check(
        entry["held"] >= 1 and total == entry["held"],
        f"entry {index}: batch {entry['batch']} held {entry['held']} forecasts but released "
        f"+ discarded + lapsed is {total}. Every forecast in a decided batch is one of those.",
    ):
        return False
    whole = entry.get("batch_discarded_as")
    if whole is not None and not report.check(
        whole in REVIEW_CLASSES
        and entry["released"] == 0
        and entry["lapsed"] == 0
        and discarded[whole] >= 1,
        f"entry {index}: batch {entry['batch']} says it was discarded whole as {whole!r}, but "
        "its counts say otherwise",
    ):
        return False
    for cls in WHOLE_BATCH_ONLY:
        if discarded[cls] and not report.check(
            whole == cls,
            f"entry {index}: batch {entry['batch']} counts {discarded[cls]} forecast(s) "
            f"discarded as {cls!r}, which is a whole-batch class, and the batch was not "
            f"discarded whole as {cls!r}. No single forecast is discarded for that reason.",
        ):
            return False
    fingerprint = str(entry.get("batch_fingerprint", ""))
    return report.check(
        len(fingerprint) == 64 and all(c in "0123456789abcdef" for c in fingerprint),
        f"entry {index}: batch {entry['batch']}'s batch_fingerprint is not a digest",
    )


def _awaiting_entry_holds(index: int, entry: dict[str, Any], report: Report) -> bool:
    fields = set(entry) - ENTRY_FRAME
    if not report.check(
        fields == AWAITING_FIELDS,
        f"entry {index}: an awaiting_review entry carries {sorted(fields)}, not exactly "
        f"{sorted(AWAITING_FIELDS)}",
    ):
        return False
    counts = ("held_ever", "waiting", "oldest_waiting_days", "batches_decided")
    return report.check(
        all(_whole(entry.get(k)) for k in counts)
        and _day(entry.get("on"))
        and (entry["waiting"] > 0 or entry["oldest_waiting_days"] == 0),
        f"entry {index}: an awaiting_review entry's counts are not whole numbers, its day is "
        "not a day, or it says nothing waits and something has waited",
    )


def awaiting_complaint(before: list[dict[str, Any]], entry: dict[str, Any]) -> str | None:
    """Why a waiting count could not follow ``before`` on the chain, or ``None``.

    ``batches_decided`` is the number of ``review`` entries before it; ``waiting`` is exactly
    ``held_ever`` minus the ``held`` of those batches; ``held_ever`` and ``on`` never fall from
    one waiting count to the next. The record refuses to append a count this refuses, by the
    same rule."""
    reviews = [e for e in before if e.get("kind") == "review"]
    counts = [e for e in before if e.get("kind") == "awaiting_review"]
    if int(entry["batches_decided"]) != len(reviews):
        return (
            f"the waiting count says {entry['batches_decided']} batch(es) were decided when it "
            f"was taken; the chain before it holds {len(reviews)}"
        )
    decided = sum(int(e["held"]) for e in reviews)
    if int(entry["waiting"]) != int(entry["held_ever"]) - decided:
        return (
            f"{entry['held_ever']} forecast(s) were ever held and the {len(reviews)} decided "
            f"batch(es) took {decided}, so {int(entry['held_ever']) - decided} must be waiting; "
            f"the count says {entry['waiting']}. A forecast leaves the waiting count by being "
            "decided in a batch on the record, or not at all."
        )
    if counts:
        last = counts[-1]
        if int(entry["held_ever"]) < int(last["held_ever"]):
            return (
                f"held_ever fell from {last['held_ever']} to {entry['held_ever']}; a forecast "
                "once held is held for good"
            )
        if str(entry["on"]) < str(last["on"]):
            return f"the waiting count is dated {entry['on']}, before the last one ({last['on']})"
    return None


def review_totals(chain: list[dict[str, Any]]) -> dict[str, Any]:
    """The scoreboard's ``review`` block, recomputed from the chain alone."""
    reviews = [e for e in chain if e.get("kind") == "review"]
    awaiting = [e for e in chain if e.get("kind") == "awaiting_review"]
    discarded = {c: sum(int(e["discarded"][c]) for e in reviews) for c in REVIEW_CLASSES}
    latest = awaiting[-1] if awaiting else None
    return {
        "batches": len(reviews),
        "held": sum(int(e["held"]) for e in reviews),
        "released": sum(int(e["released"]) for e in reviews),
        "discarded": discarded,
        "discarded_total": sum(discarded.values()),
        "lapsed": sum(int(e["lapsed"]) for e in reviews),
        "waiting": None
        if latest is None
        else {
            "on": latest["on"],
            "held_ever": int(latest["held_ever"]),
            "waiting": int(latest["waiting"]),
            "oldest_waiting_days": int(latest["oldest_waiting_days"]),
        },
    }


def verify_review(chain: list[dict[str, Any]], scoreboard: dict[str, Any], report: Report) -> None:
    """Step 6c: what the owner's review removed, and that nothing sits undecided unseen.

    Each ``review`` entry is one decided batch; batches run 1, 2, 3 in chain order and their
    counts add up. Each ``awaiting_review`` entry says how many forecasts were ever held and how
    many wait undecided, and the second is exactly the first less every batch decided before
    it (:func:`awaiting_complaint`): a forecast leaves the waiting count by being decided, in
    public, or not at all.
    """
    decided = 0
    decided_on = ""
    for index, entry in enumerate(chain):
        kind = entry.get("kind")
        if kind == "review":
            if not _review_entry_holds(index, entry, report):
                return
            if not report.check(
                entry["batch"] == decided + 1,
                f"entry {index}: batch {entry['batch']} follows batch {decided}. Batches are "
                "numbered 1, 2, 3 in the order they were decided; a gap is a batch the record "
                "does not show.",
            ):
                return
            if not report.check(
                entry["decided_on"] >= decided_on,
                f"entry {index}: batch {entry['batch']} was decided on {entry['decided_on']}, "
                f"before the batch ahead of it ({decided_on})",
            ):
                return
            decided = entry["batch"]
            decided_on = entry["decided_on"]
        elif kind == "awaiting_review":
            if not _awaiting_entry_holds(index, entry, report):
                return
            complaint = awaiting_complaint(chain[:index], entry)
            if not report.check(complaint is None, f"entry {index}: {complaint}"):
                return
    boards = scoreboard.get("tracks") or {}
    for version, board in sorted(boards.items()):
        report.check(
            "review" not in board,
            f"the scoreboard's {version} board carries its own `review`. The owner's review "
            "is stated once, at the top level, for the whole record.",
        )
    totals = review_totals(chain)
    stated = scoreboard.get("review")
    if stated is None:
        report.check(
            totals["batches"] == 0 and totals["waiting"] is None,
            "the chain carries the owner's review counts and the scoreboard shows none",
        )
        return
    report.check(
        stated == totals,
        f"the scoreboard's `review` says {stated}; the chain's entries add up to {totals}",
    )
    waiting = totals["waiting"]
    report.note(
        f"review: {totals['batches']} batch(es) decided, {totals['held']} held, "
        f"{totals['released']} released, {totals['discarded_total']} discarded, "
        f"{totals['lapsed']} lapsed; "
        + (
            "no waiting count yet"
            if waiting is None
            else f"{waiting['waiting']} waiting on {waiting['on']}, oldest "
            f"{waiting['oldest_waiting_days']} day(s)"
        )
    )


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
    manifest = read_json(manifest_path)
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
    tip = read_json(path)
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


def verify_anchors(directory: Path, scoreboard: dict[str, Any], report: Report) -> None:
    """Step 10: the timestamps, as far as this script can go without Bitcoin.

    Five things, all offline. The anchored run has no gap in it. It reaches the publication
    you are looking at, or is exactly one behind it. Every proof named is here, parses, and
    is a proof of the little file beside it — whose contents are the manifest digest its row
    claims. A row that says "confirmed" names a proof that really carries a Bitcoin
    attestation at the height the row states. And the rows here add up to what
    `scoreboard.json` says about them, which is the check you would make by hand.

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
    _verify_anchor_counts(directory, scoreboard, seqs, report)


def _verify_anchor_counts(
    directory: Path, scoreboard: dict[str, Any], seqs: list[int], report: Report
) -> None:
    """`scoreboard.json`'s `attempted` against the rows, allowing the one row it cannot count.

    This publication is stamped as it is delivered, which is after `scoreboard.json` was
    written and hashed into the `MANIFEST.json` that the row stamps — so the counts in that
    file cannot include the row that names it, and `anchors/` sits outside the manifest, so
    the row reaches you in the same commit anyway. The file says which publication it leaves
    out, under `excludes_publication_seq`, and this is the arithmetic that uses it: every row
    but that one is counted in `attempted`, exactly.

    The publication it leaves out can only be the newest one in `publications.jsonl`, the one
    whose files these are. Without that, a scoreboard could leave out an *older* row that is
    sitting right there, set `attempted` one short to match, and pass the arithmetic while
    describing a different record from the one in front of you.

    Only `attempted` is checked and the other counts deliberately are not. A row goes from
    pending to confirmed after the publication that carries it was built, so `confirmed` here
    can be behind the index by a proof or two, in the direction of claiming *less* evidence
    than the record holds. `attempted` has no such slack: rows are added one per publication
    and never otherwise.

    A record published before this field existed is not failed for lacking it. That is a
    statement about when it was published, not about whether it is honest.
    """
    stated = scoreboard.get("anchoring")
    if not isinstance(stated, dict) or "attempted" not in stated:
        return
    if "excludes_publication_seq" not in stated:
        report.note(
            "anchors: this publication predates the field that says which publication its "
            "counts leave out, so `attempted` here may be one behind the rows in "
            "anchors/index.jsonl. Later publications say so in the file."
        )
        return
    excluded = stated.get("excludes_publication_seq")
    attempted = stated.get("attempted")
    # Read defensively and fail rather than raise. This script is published and run against
    # records somebody may have edited, and a traceback out of `int()` is a reader being told
    # nothing about a file that is, in fact, wrong.
    if not isinstance(attempted, int) or not isinstance(excluded, int | None):
        report.check(
            False,
            "anchors: scoreboard.json's anchor counts are not numbers "
            f"(attempted={attempted!r}, excludes_publication_seq={excluded!r}), so there is "
            "nothing here to check them against the rows with.",
        )
        return
    ledger = read_jsonl(directory / "publications.jsonl")
    if excluded is not None and ledger:
        newest = len(ledger) - 1
        if not report.check(
            excluded == newest,
            f"anchors: scoreboard.json leaves publication {excluded} out of its counts, but "
            f"these files are publication {newest}. The only row a scoreboard cannot count is "
            "its own publication's; leaving out any other is counting a different record.",
        ):
            return
    counted = [seq for seq in seqs if seq != excluded]
    report.check(
        len(counted) == attempted,
        f"anchors: scoreboard.json counts {attempted} attempt(s); anchors/index.jsonl holds "
        f"{len(seqs)} row(s) and the scoreboard leaves out publication {excluded!r}. Those "
        "do not add up, and a published record has to.",
    )


def _verify_anchor_tail(
    directory: Path, rows: list[dict[str, Any]], seqs: list[int], report: Report
) -> None:
    """The newest row against the publication in front of you.

    A publication is stamped as it is delivered, which is after the files you are reading were
    built. `anchors/` is outside `MANIFEST.json`, so that row is committed with this same
    publication, and in a record you fetched the newest row is normally this publication's
    own. One behind is the other legal state and not a fault: it is what a publication looks
    like before it has been delivered. Two behind is a record that stopped anchoring, which is
    what somebody would do to leave an inconvenient day unstamped.
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
            "is delivered, and these files have not been delivered yet or the stamp has not "
            "been written; every publication before it is anchored."
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
        scoreboard = read_json(scoreboard_path)

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
        verify_detectable_error(chain, scoreboard, report)
        verify_scores(chain, report)
        verify_policies(chain, report)
        verify_tracks(chain, scoreboard, report)
        verify_review(chain, scoreboard, report)
        verify_publications(directory, chain, report)
    verify_manifest(directory, report)
    verify_tip(directory, chain, report)
    verify_anchors(directory, scoreboard, report)

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
        print(
            f"INCOMPLETE: {len(report.unmade)} check(s) could not be made, "
            "on this machine or from these files."
        )
        print("Nothing here failed — that is exit 1. This is exit 2. What was not checked:")
        for message in report.unmade:
            print(f"  {message}")
        return 2
    print()
    print("OK. Every check in VERIFY.md passes on these files.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
