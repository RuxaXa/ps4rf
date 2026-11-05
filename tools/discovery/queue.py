"""Candidate queue for the primary firmware.

A candidate is only admitted with all nine required fields present.  The queue
is ordered by a score that is *derived*, not asserted: reachability depth from a
real entry, the detector's rank, whether the finding survives its own
counter-evidence checks, and whether a chain can be composed at all.

The point of the queue is to be falsifiable, so every entry carries the test
that would kill it.  Candidates that cannot name such a test are dropped with a
reason instead of being listed.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Dict, Iterable, List, Optional

from . import chains as chains_mod

REQUIRED_FIELDS = (
    "id",
    "function",
    "entry_path",
    "root_cause_hypothesis",
    "controllability",
    "evidence",
    "counter_evidence",
    "falsification_test",
    "chain",
)


@dataclass
class Candidate:
    id: str
    function: dict
    entry_path: dict
    root_cause_hypothesis: str
    controllability: dict
    evidence: dict
    counter_evidence: List[dict]
    falsification_test: str
    chain: dict
    score: float = 0.0
    priority: int = 0

    def as_dict(self) -> dict:
        return {
            "id": self.id,
            "function": self.function,
            "entry_path": self.entry_path,
            "root_cause_hypothesis": self.root_cause_hypothesis,
            "controllability": self.controllability,
            "evidence": self.evidence,
            "counter_evidence": self.counter_evidence,
            "falsification_test": self.falsification_test,
            "chain": self.chain,
            "score": round(self.score, 3),
            "priority": self.priority,
        }

    def complete(self) -> bool:
        return all(getattr(self, f) for f in REQUIRED_FIELDS)


def load_negative_results(path: str) -> List[dict]:
    with open(path, "rt", encoding="utf-8") as fh:
        return json.load(fh)["results"]


def _subsystem_counter_evidence(negative: List[dict], subsystem: str) -> List[dict]:
    out = []
    for entry in negative:
        if subsystem and subsystem in entry.get("subsystems", []):
            out.append(
                {
                    "source": entry["id"],
                    "refuted": entry["refuted"],
                    "reopen_if": entry["reopen_if"],
                    "artifact": entry.get("artifact"),
                }
            )
    return out


def _controllability(finding: dict, entry: dict) -> dict:
    """How much of the bug's input is attacker-controlled, from what we can see."""
    basis = []
    score = 0
    if entry.get("kind") == "syscall":
        basis.append(f"reachable from syscall {entry.get('syscall')} (narg {entry.get('narg')})")
        score += 2 if (entry.get("narg") or 0) > 0 else 1
    elif entry.get("kind") == "cdevsw":
        basis.append(f"reachable from device node {entry.get('name')}")
        score += 2
    else:
        basis.append("entry not resolved")
    claims = finding.get("claims") or {}
    if claims.get("post_release_uses"):
        basis.append("a post-release use exists (the strongest form of the class)")
        score += 2
    if claims.get("path_between_without_kill"):
        basis.append("two release sites are reachable without a kill between them")
        score += 2
    if finding.get("rank") == 1:
        basis.append("detector rank 1")
        score += 2
    elif finding.get("rank") == 2:
        basis.append("detector rank 2 (one precondition unproven)")
        score += 1
    return {"score": score, "basis": basis}


def _entry_for_function(entry_map: Dict[str, dict], rva_hex: str) -> dict:
    return entry_map.get(rva_hex) or {"kind": "unresolved"}


def _record_key(finding: dict) -> tuple:
    """Total order over findings of one (detector, function) group.

    A merge must not depend on the order the scan happened to emit findings in.  The
    key prefers a record that can be falsified, then the strongest rank, then a
    canonical dump of the evidence itself, so two permutations of the same input
    produce the same representative and the same output bytes.
    """
    return (
        0 if finding.get("falsification") else 1,
        finding.get("rank", 9),
        json.dumps({k: finding.get(k) for k in
                    ("bug_class", "claims", "window", "slot", "sites",
                     "counter_evidence", "falsification", "subsystem")},
                   sort_keys=True, default=str),
    )


def _site_record(finding: dict) -> dict:
    """One finding's own rank, claims and provenance -- never mixed with another's."""
    return {
        "slot": finding.get("slot"),
        "sites": list(finding.get("sites") or []),
        "rank": finding.get("rank"),
        "claims": dict(finding.get("claims") or {}),
        "window": finding.get("window"),
        "counter_evidence": finding.get("counter_evidence") or {},
        "falsification": finding.get("falsification"),
    }


def build(
    findings: Iterable[dict],
    entry_map: Dict[str, dict],
    facts: dict,
    negative: List[dict],
    limit: int = 10,
    min_rank: int = 2,
) -> dict:
    findings = list(findings)
    candidates: List[Candidate] = []
    dropped = []
    # One candidate per (detector, function): a function with four vulnerable
    # slots is one candidate with four slot claims, not four candidates.  The
    # candidate's own hypothesis, rank and window come from ONE record -- the
    # canonical representative -- and every other record keeps its own rank and
    # claims beside it.  Taking the minimum rank from one finding while keeping the
    # evidence of another produced a rank-1 candidate whose proof described a
    # rank-3 observation, and made the output depend on input order.
    grouped: Dict[tuple, List[dict]] = {}
    for finding in findings:
        key = (finding["detector"], finding["function"]["rva"])
        grouped.setdefault(key, []).append(finding)
    merged: Dict[tuple, dict] = {}
    for key, group in grouped.items():
        ordered = sorted(group, key=_record_key)
        representative = dict(ordered[0])
        representative["_sites_records"] = [_site_record(f) for f in ordered]
        representative["_slots"] = {f.get("slot") for f in ordered}
        representative["_sites"] = [s for f in ordered for s in (f.get("sites") or [])]
        representative["_rank_of_hypothesis"] = ordered[0].get("rank")
        merged[key] = representative
    for finding in merged.values():
        if finding.get("rank", 9) > min_rank:
            # Dropping this silently made a queue with zero candidates indistinguishable
            # from a scan that found nothing; the floor has to be visible in the output.
            dropped.append(
                {"function": finding["function"]["rva"], "detector": finding["detector"],
                 "why": f"rank {finding.get('rank')} is above the floor {min_rank}"}
            )
            continue
        if not finding.get("falsification"):
            dropped.append(
                {"function": finding["function"]["rva"], "detector": finding["detector"],
                 "why": "no falsification test"}
            )
            continue
        rva_hex = finding["function"]["rva"]
        entry = _entry_for_function(entry_map, rva_hex)
        chain = chains_mod.compose(finding, entry.get("label", "UNKNOWN_ENTRY"), facts,
                                   entry_kind=entry.get("kind", ""),
                                   entry_evidence=entry)
        controllability = _controllability(finding, entry)
        subsystem = entry.get("subsystem") or finding.get("subsystem") or ""
        counter = [
            {"source": "detector", "checked": finding.get("counter_evidence") or {}},
        ]
        counter.extend(_subsystem_counter_evidence(negative, subsystem))
        score = controllability["score"]
        if chain.complete:
            score += 3
        score -= 0.5 * len([b for b in chain.blockers if b.status == chains_mod.OPEN])
        cand = Candidate(
            id=f"C-{finding['detector'].split('_')[0]}-{rva_hex}",
            function=finding["function"],
            entry_path=entry,
            root_cause_hypothesis=(
                f"{finding['bug_class']}: {finding['detector']} at {rva_hex} -- "
                + "; ".join(f"{k}={v}" for k, v in (finding.get("claims") or {}).items())[:400]
            ),
            controllability=controllability,
            evidence={
                "window": finding.get("window"),
                "slots": sorted(s for s in finding.get("_slots") or [] if s),
                "slot_count": len([s for s in finding.get("_slots") or [] if s]),
                "site_rvas": finding.get("_sites"),
                "detector": finding["detector"],
                # the rank that belongs to THIS hypothesis, and every other
                # record's own rank/claims, so a reader can see the difference
                "rank": finding.get("rank"),
                "rank_of_hypothesis": finding.get("_rank_of_hypothesis"),
                "sites": finding.get("_sites_records"),
            },
            counter_evidence=counter,
            falsification_test=finding["falsification"],
            chain=chain.as_dict(),
            score=score,
        )
        if not cand.complete():
            dropped.append({"function": rva_hex, "detector": finding["detector"],
                            "why": "incomplete field set"})
            continue
        candidates.append(cand)
    candidates.sort(key=lambda c: (-c.score, c.id))
    # Diversify: a queue of ten findings from one detector says nothing about the
    # other bug classes.  At most three per detector, in score order.
    per_detector: Dict[str, int] = {}
    selected: List[Candidate] = []
    for cand in candidates:
        det = cand.evidence["detector"]
        if per_detector.get(det, 0) >= 3:
            continue
        per_detector[det] = per_detector.get(det, 0) + 1
        selected.append(cand)
        if len(selected) >= limit:
            break
    for idx, cand in enumerate(selected, 1):
        cand.priority = idx
    return {
        "queue": [c.as_dict() for c in selected],
        "dropped": dropped[:50],
        "counts": {"considered": len(findings), "admitted": len(selected),
                   "dropped": len(dropped),
                   "per_detector": per_detector},
    }
