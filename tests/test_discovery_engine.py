"""Regression for the Sprint-1 exploit-discovery engine.

These tests pin the *engine*, not the discovery outcome:

* hard facts from published offsets must keep resolving in our images,
* the scanner's measured score must be reported (and it is deliberately pinned
  to today's numbers, so a rule change has to be a conscious decision),
* every candidate must carry all nine required fields and at least one open
  blocker -- nothing may read as exploitable while a physical precondition is
  missing,
* the rule set must not regress into address literals in code.

Scanner labels are *measurements*: the Lapse negative label currently fails
(D2 fires on the fixed function too).  That failure is recorded here as an
expected value rather than silently fixed, because hiding it would be
overfitting to the label.
"""

from __future__ import annotations

import json
import os
import re
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from tools.discovery import (  # noqa: E402
    chains,
    graph,
    patterns,
    queue as queue_mod,
    validate,
)
from tools.discovery.image import KernelImage, FirmwareFacts  # noqa: E402

DATA = os.path.join(ROOT, "tools", "discovery", "data")


@pytest.fixture(scope="module")
def env():
    pytest.importorskip("capstone")
    return validate.Environment.load(DATA, only=["13.52", "9.00"])


@pytest.fixture(scope="module")
def families():
    with open(os.path.join(DATA, "families", "families.json"), "rt", encoding="utf-8") as fh:
        return json.load(fh)


@pytest.fixture(scope="module")
def references():
    with open(os.path.join(DATA, "families", "references.json"), "rt", encoding="utf-8") as fh:
        return json.load(fh)


# ------------------------------------------------------------------ image facts


def test_image_identity(env):
    for fw, image in env.images.items():
        assert image.sha256 == env.facts[fw].sha256, f"{fw} hash does not match the pinned facts"
        assert image.base == env.facts[fw].base
        assert image.executable_ranges(), f"{fw} has no executable range"


def test_flat_rva_convention(env):
    """The dump's own program headers are misleading; sysent proves the flat reading."""
    image = env.images["13.52"]
    facts = env.facts["13.52"]
    entry = env.sysent["13.52"].get(11)
    assert entry is not None and entry.valid
    rva = facts.rva("sysent") + 11 * 48
    assert image.u64(rva + 8) == image.va(entry.handler_rva)
    assert image.read(entry.handler_rva, 2).hex() == "ff26"


def test_purity_is_reported_not_assumed(env):
    report = validate.purity_report(env)
    for fw, entry in report.items():
        assert entry["verdict"] in ("NOT_PRISTINE", "NO_KEXEC_PATCH_SEEN")
        if entry["kexec_patch_shape"]:
            assert entry["sysent11_narg"] == 2 and entry["sysent11_thrcnt"] == 1


def test_hard_facts_have_no_failures(env, references):
    report = validate.run(env, references)
    hard = [a for a in report["assertions"] if a["kind"] != "detector"]
    failed = [a for a in hard if a["status"] == "FAIL"]
    assert not failed, f"hard facts failed: {[(a['id'], a['observed']) for a in failed]}"
    assert report["summary"]["hard_facts_pass"] >= 14


def test_scanner_score_is_reported_and_pinned(env, references):
    score = validate.run(env, references)["scanner_score"]
    assert score["positives"] == 1 and score["negatives"] == 1
    # Pinned deliberately, at both levels.  A change here must be a conscious
    # decision with a new measurement -- never a label tuned to a rule.
    # name level: the rule notices both versions of the Lapse pair -> no
    # discrimination at all (precision 0.5 on n=2).
    assert score["name_level"]["recall"] == 1.0
    assert score["name_level"]["false_positive_rate"] == 1.0
    assert score["name_level"]["precision"] == 0.5
    # actionable level (rank <= 2).  Re-pinned in S1.8 with a new measurement, not by tuning:
    # release call sites are now labelled with the argument the release actually consumes (its
    # first one) instead of the last argument register written in the block.  Before that the
    # `fdrop_release` sites carried `rsi` — a context pointer — so the slot that was really freed
    # stayed invisible.
    #   S1.7: recall 0.0, false_positive_rate 0.0, precision None   (nothing actionable at all)
    #   S1.8: recall 1.0 (D1_use_after_release at rank 1 on the vulnerable 9.00 body),
    #         false_positive_rate 0.0 (the fixed 13.52 body stays at rank 3),
    #         precision 1.0
    # A further change here must be a new measurement again.
    assert score["actionable_level"]["recall"] == 1.0
    assert score["actionable_level"]["false_positive_rate"] == 0.0
    assert score["actionable_level"]["precision"] == 1.0


# --------------------------------------------------------------------- patterns


def test_double_release_shape_on_vulnerable_aio(env):
    """D2 notices the vulnerable body but does not claim an actionable path.

    After the kill-aware CFG walk replaced the reachable-block over-approximation,
    D2 fires at rank 3 here: two release sites on one slot exist, but no path
    between them is kill-free.  That is the honest state of the rule on the one
    labelled positive, and the pinned rank below keeps a future improvement from
    silently changing the measurement.
    """
    image = env.images["9.00"]
    named = dict(env.indexes["9.00"].named())
    for name, rva_hex in (env.facts["9.00"].doc.get("anchors") or {}).items():
        named.setdefault(int(rva_hex, 16), name)
    ctx = patterns.ScanContext.from_names(named)
    findings = patterns.scan_function(image, 0x410870, 0x8F0, "", ctx)
    d2 = [f for f in findings if f.detector == "D2_double_release"]
    assert d2, "D2 must fire on the vulnerable aio_multi_delete body"
    assert min(f.rank for f in d2) == 3
    assert all(f.claims["path_between_without_kill"] is False for f in d2)
    assert d2[0].falsification


def test_detectors_never_raise(env):
    """A broken rule must degrade to a DETECTOR_ERROR finding, not kill the sweep."""
    image = env.images["13.52"]
    ctx = patterns.ScanContext(frozenset(), frozenset(), frozenset(), "")
    findings = patterns.scan_function(image, 0x11F710, 0x7F0, "sys_662", ctx)
    assert all(f.bug_class != "DETECTOR_ERROR" for f in findings)


def test_no_address_literals_in_code():
    """Firmware addresses belong in data files, not in the engine."""
    allowed = {"0xFFFF800000000000", "0xFFFFFFFFFFFFFFFF",  # canonical-VA bounds
               "0x1000010"}  # ELF LOOS+ segment type, not an address
    offenders = []
    for name in sorted(os.listdir(os.path.join(ROOT, "tools", "discovery"))):
        if not name.endswith(".py"):
            continue
        path = os.path.join(ROOT, "tools", "discovery", name)
        with open(path, "rt", encoding="utf-8") as fh:
            for lineno, line in enumerate(fh, 1):
                for literal in re.findall(r"0x[0-9A-Fa-f]{5,}", line):
                    if literal.lower() in {a.lower() for a in allowed}:
                        continue
                    offenders.append((name, lineno, literal))
    assert not offenders, f"address literals in engine code: {offenders}"


# ------------------------------------------------------------- families, chains


def test_at_least_three_families_integrated(families):
    fams = families["families"]
    assert len(fams) >= 3
    for fam in fams:
        assert fam["source"]["commit"], f"{fam['id']} has no pinned commit"
        assert fam["source"]["files"], f"{fam['id']} has no pinned file hashes"
        assert fam["labels"], f"{fam['id']} has no reference labels"
        assert fam["falsification"], f"{fam['id']} has no falsification test"
        assert fam["root_cause"]["grade"] in ("B", "A", "K", "H", "X", "BLOCKED")


def test_blind_family_is_held_out(families):
    afterglow = next(f for f in families["families"] if f["id"] == "afterglow")
    assert set(afterglow["labels"].values()) == {"HELD_OUT"}


def test_chain_without_offline_proof_stays_blocked(env):
    finding = {
        "detector": "D2_double_release",
        "bug_class": "OWNERSHIP_DOUBLE_FREE",
        "function": {"rva": "0x107340", "size": 1, "name": "x"},
        "claims": {"path_between_without_kill": True},
        "rank": 1,
        "falsification": "n/a",
        "window": [],
        "slot": "rbp-0x8",
        "sites": [],
    }
    chain = chains.compose(finding, "sysent[534]", env.facts["13.52"].doc, entry_kind="syscall")
    assert chain.complete is False, "a spray-dependent chain must never be complete offline"
    open_ids = {b.id for b in chain.blockers if b.status == chains.OPEN}
    assert "BLOCK_REQ_SPRAY" in open_ids


# ---------------------------------------------------------------- queue contract


@pytest.fixture(scope="module")
def sprint_report():
    pytest.importorskip("capstone")
    from tools.discovery import cli as cli_mod

    args = type("A", (), {
        "outdir": "/tmp/ps4rf-sprint1-test",
        "fw": "13.52",
        "depth": 2,
        "max_functions": 600,
        "queue_limit": 10,
        "sources": None,
        "blind": False,
    })()
    return cli_mod.run_all(args)


def test_queue_contract(sprint_report):
    q = sprint_report["queue"]
    assert 5 <= len(q["queue"]) <= 10, f"queue has {len(q['queue'])} candidates"
    required = ("id", "function", "entry_path", "root_cause_hypothesis", "controllability",
                "evidence", "counter_evidence", "falsification_test", "chain")
    seen = set()
    for cand in q["queue"]:
        for field in required:
            assert cand.get(field), f"{cand['id']} is missing {field}"
        key = (cand["evidence"]["detector"], cand["function"]["rva"])
        assert key not in seen, f"duplicate candidate for {key}"
        seen.add(key)
        assert cand["chain"]["complete"] is False
        assert cand["chain"]["open_blockers"] >= 1


def test_findings_are_deterministic(sprint_report):
    from tools.discovery import cli as cli_mod

    env = validate.Environment.load(DATA, only=["13.52", "9.00"])
    entries = cli_mod.build_entry_index(env, "13.52", depth=2)
    first = cli_mod.scan(env, "13.52", entries["entry_map"], depth=2, max_functions=150)
    second = cli_mod.scan(env, "13.52", entries["entry_map"], depth=2, max_functions=150)
    # wall-clock time is not a property of a finding: hash the analysis, not the stopwatch
    strip = lambda r: {k: v for k, v in r.items() if k != "elapsed_s"}
    assert cli_mod._sha(strip(first)) == cli_mod._sha(strip(second))


def test_cross_subsystem_graph(sprint_report):
    g = sprint_report["graph"]
    assert g["nodes"] and g["edges"]
    kinds = {n["kind"] for n in g["nodes"]}
    for expected in ("family", "subsystem", "entry", "candidate"):
        assert expected in kinds, f"graph lacks {expected} nodes"
    dot = graph.to_dot(g)
    assert dot.startswith("digraph") and dot.count("->") == len(g["edges"])
