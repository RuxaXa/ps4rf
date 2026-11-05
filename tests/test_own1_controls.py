"""OWN-1 instrumentation controls and coverage identities (readiness wave).

These are not oracle-parity vectors: they pin the properties the reading
instrumentation must have before a live wave can certify anything (see the
offline-readiness note next to A2b): full-coverage arithmetic, positive and
negative controls, and the delayed-free (settle) behaviour.
"""
from __future__ import annotations

from tools.experiments import own1
from tools.experiments.device import (BMP_DYNAMIC_FIRST_WORD, PT_DYNAMIC_FIRST_SLOT,
                                      SimulatedConsole)


def _run(scenario: str):
    return own1.run(SimulatedConsole(scenario, {}))


def test_coverage_identities():
    """Both windows cover exactly the dynamically allocatable range of the space.

    bitmap: one word covers 1 MiB of GPUVA (64 bits x 0x4000 unit); the window starts at
    the first dynamic MiB word and its 4072 bytes end exactly at the end of the 24232-byte
    bitmap. level1: one 8-byte block entry per 8 MiB; the 512-byte window covers all 64
    possible dynamic blocks.
    """
    assert own1.INDICES["idx_bitmap_word"] == 0x9D800000 >> 20
    assert own1.INDICES["idx_bitmap_word"] * 8 + 4072 == 24232  # ends at the bitmap end
    assert own1.INDICES["idx_ptslot"] == 0x9D800000 >> 0x17
    assert PT_DYNAMIC_FIRST_SLOT == own1.INDICES["idx_ptslot"]
    assert ((0xBD558000 - 1) >> 0x17) - PT_DYNAMIC_FIRST_SLOT + 1 == 512 // 8
    assert BMP_DYNAMIC_FIRST_WORD == own1.INDICES["idx_bitmap_word"]


def test_positive_control_known_structures_are_seen():
    """A known artefact at the wave positions is reported at T0 (sensitivity witness)."""
    rep = _run("on1_stale")
    assert rep.pt_new > 0 and rep.bits_delta > 0
    assert rep.settle_bmp_bytes_chg == 0 and rep.settle_pt_bytes_chg == 0
    assert rep.verdict == own1.RESIDUAL_STATE_CONFIRMED


def test_negative_control_no_crosstalk_from_outside():
    """An artefact outside every window never appears in the read set."""
    rep = _run("on1_ctrl_outside")
    assert rep.classification == own1.FULL_ROLLBACK  # nothing changed inside the windows
    assert rep.bmp_bytes_chg == 0 and rep.pt_bytes_chg == 0
    assert rep.pt_new == 0 and rep.bits_delta == 0
    assert rep.settle_bmp_bytes_chg == 0 and rep.settle_pt_bytes_chg == 0
    # the windows are still shown to be live, so the read itself is not vacuous
    assert rep.bmp_window_varied == 1 or rep.pt_slots_live > 0


def test_delayed_free_is_transient_not_residual():
    """A T0 artefact that drains before the settle read is a delayed free."""
    rep = _run("on1_delayed")
    assert rep.classification == own1.STALE_TRANSLATION  # the T0 signal, as in on1_stale
    assert rep.settle_bmp_bytes_chg > 0 or rep.settle_pt_bytes_chg > 0
    assert rep.verdict == own1.TRANSIENT_DRAINED
    assert rep.verdict != own1.RESIDUAL_STATE_CONFIRMED


def test_settle_read_is_stable_when_no_deferred_free_exists():
    rep = _run("on1_stale")  # no settle key: nothing drains between the post reads
    assert rep.settle_bmp_bytes_chg == 0 and rep.settle_pt_bytes_chg == 0


def test_verdict_gates_are_strict():
    """The verdict predicates: no witness -> INCONCLUSIVE; a clean bitmap alone is not enough."""
    clean = own1.Own1Report(attach=1, classification=own1.FULL_ROLLBACK, bmp_window_varied=1)
    assert own1.verdict(clean) == own1.ROLLBACK_CONFIRMED
    blind = own1.Own1Report(attach=1, classification=own1.FULL_ROLLBACK)
    assert own1.verdict(blind) == own1.INCONCLUSIVE
    detached = own1.Own1Report(attach=0, classification=own1.FULL_ROLLBACK,
                               bmp_window_varied=1)
    assert own1.verdict(detached) == own1.INCONCLUSIVE
    residual = own1.Own1Report(attach=1, classification=own1.STALE_TRANSLATION,
                               bmp_window_varied=1, pt_new=1, bits_delta=1)
    assert own1.verdict(residual) == own1.RESIDUAL_STATE_CONFIRMED
    transient = own1.Own1Report(attach=1, classification=own1.STALE_TRANSLATION,
                                bmp_window_varied=1, pt_new=1, bits_delta=1,
                                settle_pt_bytes_chg=8)
    assert own1.verdict(transient) == own1.TRANSIENT_DRAINED
    drifting = own1.Own1Report(attach=1, classification=own1.FULL_ROLLBACK,
                               bmp_window_varied=1, settle_bmp_bytes_chg=8)
    assert own1.verdict(drifting) == own1.INCONCLUSIVE
