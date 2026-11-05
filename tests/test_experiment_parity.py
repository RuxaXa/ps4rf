"""Oracle parity: the PS4RF experiment layer vs the frozen payload harnesses.

The standalone payloads Q6LIVE/OWN1LIVE are frozen reference implementations.
Their harness outcomes are the expected classifications here; the PS4RF
experiment layer must reproduce them for the same simulated state, driving only
the two generic primitives (bounded snapshot recipe, policy checked ioctl).
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from tools.experiments import contracts as C
from tools.experiments import gen_vectors, own1, q6
from tools.experiments.device import (BMP_BASE, BMP_DYNAMIC_FIRST_WORD, PT_BASE,
                                      PT_DYNAMIC_FIRST_SLOT, SimulatedConsole, load_policy,
                                      load_recipe)

FIXTURES = Path(__file__).resolve().parent / "fixtures" / "experiments"
VECTORS = json.loads((FIXTURES / "vectors-v1.json").read_text())
BY_SCENARIO = {v["scenario"]: v for v in VECTORS["vectors"]}


def _console(scenario: str) -> SimulatedConsole:
    buffers = q6.host_buffers() if BY_SCENARIO[scenario]["experiment"] == "q6" else {}
    return SimulatedConsole(scenario, buffers)


def _run(scenario: str):
    dev = _console(scenario)
    if BY_SCENARIO[scenario]["experiment"] == "q6":
        return q6.run(dev), dev
    return own1.run(dev), dev


@pytest.mark.parametrize("scenario", [s for s in BY_SCENARIO if s.startswith("q6")])
def test_q6_parity_with_frozen_oracle(scenario):
    rep, dev = _run(scenario)
    assert rep.classification == BY_SCENARIO[scenario]["expected_classification"]
    assert dev.calls == 2, "Q6 must submit two requests (A and B)"


@pytest.mark.parametrize("scenario", [s for s in BY_SCENARIO if s.startswith("on1")])
def test_own1_parity_with_frozen_oracle(scenario):
    rep, dev = _run(scenario)
    assert rep.classification == BY_SCENARIO[scenario]["expected_classification"]
    assert dev.calls == 1, "OWN-1 must submit exactly one trigger"


def test_identity_rule_is_not_weakened():
    rep, _ = _run("q6_noid")
    assert "TOCTOU" not in rep.classification
    assert rep.classification.startswith("STATUS_OWNERSHIP_UNPROVABLE")
    assert rep.id_a == 0


def test_stale_rows_never_reported():
    for scenario in BY_SCENARIO:
        rep, _ = _run(scenario)
        assert "stale_rows" not in json.dumps(rep.as_dict(), sort_keys=True)


def test_own1_stale_translation_needs_measured_authority():
    rollback, _ = _run("on1_rollback")
    stale, _ = _run("on1_stale")
    assert rollback.classification == own1.FULL_ROLLBACK
    assert stale.classification == own1.STALE_TRANSLATION
    assert stale.pt_new > 0 and stale.bits_delta > 0
    assert rollback.pt_new == 0 and rollback.bits_delta == 0


def test_own1_recipe_indices_are_bounded():
    dev = _console("on1_rollback")
    with pytest.raises(C.ContractError):
        dev.policy.validate(0xC0184404, b"\x00" * 24, mode=2)
    assert own1.INDICES["idx_bitmap_word"] <= 3028
    assert own1.INDICES["idx_ptslot"] <= 378
    snap = dev.run_recipe(own1.RECIPE, own1.INDICES)
    assert snap.get(own1.CELL_BITS).addr == BMP_BASE + own1.INDICES["idx_bitmap_word"] * 8
    assert own1.INDICES["idx_bitmap_word"] == BMP_DYNAMIC_FIRST_WORD, \
        "the bitmap window must sit on the first dynamically allocatable word"
    assert snap.get(own1.CELL_PT).addr == PT_BASE + own1.INDICES["idx_ptslot"] * 8
    assert own1.INDICES["idx_ptslot"] == PT_DYNAMIC_FIRST_SLOT, \
        "the PT window must sit on the first dynamically allocatable 8 MiB block"


def test_canonical_bounds_exact():
    assert C.canonical(0xFFFF800000000000) is True
    assert C.canonical(0xFFFF7FFFFFFFFFFF) is False
    assert C.canonical(0xFFFFFFFFFFFFFFFF) is True
    assert C.canonical(0x0000FFFF80000000) is False
    assert C.KVA_TRUNCATION_44BIT == 0x0000FFFF80000000
    assert C.canonical(C.KVA_TRUNCATION_44BIT) is False


def test_follow_guards():
    C.check_follow(0xFFFF82DA052C6000, 0x280, 0x400)
    for bad in ((0, 0, 0x10), (0x0000FFFF80000000, 0, 0x10), (0xFFFF82DA052C6001, 0, 0x10),
                (0xFFFFFFFFFFFFFFF0, 0x10, 0x8), (0xFFFF82DA052C6000, 0x2000, 0x10)):
        with pytest.raises(C.ContractError):
            C.check_follow(*bad)


def test_recipe_limits():
    for name in ("q6-recipe-v3", "own1-recipe-v2"):
        doc = load_recipe(name)
        assert len(doc["entries"]) <= C.MAX_ENTRIES
        assert all(int(e["length"]) <= C.MAX_ENTRY_LEN for e in doc["entries"])
        for i, e in enumerate(doc["entries"]):
            if e["type"] == "FOLLOW_ONCE":
                assert e["root_index"] < i
    with pytest.raises(C.ContractError):
        C.RecipeEntry("big", C.RVA_READ, 0x100, C.MAX_ENTRY_LEN + 1).validate(0, 1)
    with pytest.raises(C.ContractError):
        C.RecipeEntry("fwd", C.FOLLOW_ONCE, 0, 8, root_index=5).validate(0, 16)
    with pytest.raises(C.ContractError):
        C.RecipeEntry("far", C.FOLLOW_ONCE, 0, 8, root_index=0, disp=C.MAX_DISP + 1).validate(1, 16)


def test_q6_recipe_reads_the_state_block_addresses():
    """The window roots live at the pup_update state block, not in the 0x2686xxx page.

    Static (FW13.52 kernel image): the driver's state block is the static object at RVA 0x2684810
    (cdev->si_drv1), its window pointers are state+0x30 (0x2684840) and state+0x38 (0x2684848),
    written by the attach at 0x637537 / 0x63753e and NULLed by the detach at 0x637578 / 0x63758f.
    Nothing in the image references 0x2686xxx, so a recipe reading that page can only see zero.
    """
    doc = load_recipe("q6-recipe-v3")
    roots = {e["name"]: e.get("rva") for e in doc["entries"] if e["type"] == "RVA_READ"}
    assert roots["CDEV_SLOT"] == "0x2684810"
    assert roots["SOFTC_A_ROOT"] == "0x2684840"     # state + 0x30
    assert roots["SOFTC_B_ROOT"] == "0x2684848"     # state + 0x38
    assert [e["name"] for e in doc["entries"]] == ["CDEV_SLOT", "SOFTC_A_ROOT", "SOFTC_B_ROOT",
                                                   "A_HEAD", "A_STATUS", "A_CHUNK", "B_HEAD", "B_STATUS"]
    assert not any("2688" in json.dumps(e) for e in doc["entries"])


def test_ioctl_policy_is_the_only_way_in():
    policy = load_policy()
    assert sorted(C.command_allowlist(policy)) == [0xC010440A, 0xC0184401, 0xC0184404]
    assert policy.device == "/dev/pup_update0"
    for bad_command, bad_blob, bad_mode in ((0xC0184402, b"\x00" * 24, None),
                                            (0xC0184401, b"\x00" * 8, None),
                                            (0xC0184404, b"\x00" * 24, 2)):
        with pytest.raises(C.ContractError):
            policy.validate(bad_command, bad_blob, bad_mode)
    with pytest.raises(C.ContractError):
        C.assert_no_raw_address({"operation": "kernel.snapshot", "addr": 0xFFFFFF8000000000})


def test_vectors_fixture_is_pinned():
    data = (FIXTURES / "vectors-v1.json").read_bytes()
    assert data == gen_vectors.canonical_bytes(gen_vectors.document())
    assert b"TOCTOU_CONFIRMED" in data and b"STALE_TRANSLATION" in data
    assert hashlib.sha256(data).hexdigest() in (FIXTURES / "README.md").read_text()


def test_experiment_data_stays_in_the_experiment():
    src_file = (Path(__file__).resolve().parents[1] / "tools" / "experiments" / "device.py").read_text()
    for forbidden in (q6.TOKEN_A.decode(), q6.TOKEN_B.decode(), "stale_rows", "Q6", "OWN"):
        assert forbidden not in src_file, f"device.py mentions {forbidden!r}"
