"""OWN-1 stale-translation experiment (PS4RF form).

The trigger geometry and the authority list live here; the primitives stay generic.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from tools.experiments.device import Target, build_ioctl_blob
from tools.experiments.inventory import byte_diff, popcount, word_delta

RECIPE = "own1-recipe-v2"
TAG4 = 0xC0184404
MODE = 1
SEG = 0x4000
WINDOW_SEGS = 4
HOLE_SEG = WINDOW_SEGS - 1
WINDOW_LEN = WINDOW_SEGS * SEG
# The bitmap words below 0x9D800000 are covered by the statically reserved boot union
# [0, 0x9D800000) (campaign A2 run-union), so allocation artefacts can only appear at
# words >= 0x9D800000 >> 20 = 2520; a window at word 0 reads the boot region and can
# only ever see zero. The slice covers words 2520..3028 (the bitmap measures 24232 bytes).
# The PT side is the level1 array: one 8-byte block entry per 8 MiB, index = gpuva >> 0x17
# (map_for_samu 0x4d0b03/0x4d0b12, leaf_mapper 0x4caa96/0x4cab49, rollback 0x4d0cdf).
# The dynamically allocatable blocks are 0x9D800000 >> 0x17 = 315 .. (0xBD558000-1) >> 0x17
# = 378, so the slice starts at 315 and covers all 64 possible blocks (512 bytes).
INDICES = {"idx_bitmap_word": 2520, "idx_ptslot": 315}

CELL_BMP_LIMIT = "BMP_LIMIT"
CELL_BMP_ROOT = "BMP_ROOT"
CELL_BITS = "BMP_SLICE"
CELL_RECORDS = "RECORDS"
CELL_VMID = "VMID"
CELL_COUNTERS = "VMID_COUNTERS"
CELL_POOL = "POOL_COUNTER"
CELL_PT_ROOT = "PTSLOT_ROOT"
CELL_PT = "PTSLOT_SLICE"
ATTACH_CELLS = ("CDEV_SLOT", "SOFTC_A_ROOT", "SOFTC_B_ROOT")

FULL_ROLLBACK = "FULL_ROLLBACK"
RESOURCE_LEAK = "RESOURCE_LEAK"
STALE_OWNER = "STALE_OWNER"
AUTHORITY_DIVERGENCE = "AUTHORITY_DIVERGENCE"
STALE_TRANSLATION = "STALE_TRANSLATION"
MEASURED_INCONCLUSIVE = "MEASURED_INCONCLUSIVE"

# Wave verdicts (readiness level, stricter than the oracle signal names):
# a T0 signal is only a RESIDUAL_STATE_CONFIRMED if it survives the settle read, and a
# clean pair of post reads is only ROLLBACK_CONFIRMED with a sensitivity witness present.
# A signal that drains between the two post reads is a delayed free (TRANSIENT_DRAINED),
# never a residual state. Everything else is INCONCLUSIVE.
RESIDUAL_STATE_CONFIRMED = "RESIDUAL_STATE_CONFIRMED"
ROLLBACK_CONFIRMED = "ROLLBACK_CONFIRMED"
TRANSIENT_DRAINED = "TRANSIENT_DRAINED"
INCONCLUSIVE = "INCONCLUSIVE"


@dataclass
class Own1Report:
    rc: int = 0
    errno: int = 0
    segs_geom: int = WINDOW_SEGS
    hole_seg: int = HOLE_SEG
    attach: int = 0
    bmp_bits0: int = 0
    bmp_bits1: int = 0
    bits_delta: int = 0
    bmp_bytes_chg: int = 0
    pt_bytes_chg: int = 0
    pt_new: int = 0
    pt_lost: int = 0
    cnt_chg: int = 0
    own_chg: int = 0
    vmid_chg: int = 0
    root_chg: int = 0
    limit_chg: int = 0
    settle_bmp_bytes_chg: int = 0
    settle_pt_bytes_chg: int = 0
    bmp_window_varied: int = 0
    pt_slots_live: int = 0
    classification: str = ""
    verdict: str = ""
    notes: list = field(default_factory=list)

    def as_dict(self) -> dict:
        d = dict(self.__dict__)
        d["segs_effect_pt_new"] = min(self.pt_new, WINDOW_SEGS)
        return d


def run(target: Target) -> Own1Report:
    rep = Own1Report()
    s0 = target.run_recipe(RECIPE, INDICES)
    rep.attach = s0.attach
    rep.rc, rep.errno, _ = target.ioctl(target.policy.device, TAG4,
                                        build_ioctl_blob(target.policy, TAG4, mode=MODE,
                                                         ptr=0x0, length=WINDOW_LEN), mode=MODE)
    s1 = target.run_recipe(RECIPE, INDICES)
    s2 = target.run_recipe(RECIPE, INDICES)  # settle read: deferred frees drain here
    rep.classification, rep.notes = classify(measure(s0, s1, rep, s2))
    rep.verdict = verdict(rep)
    return rep


def measure(s0, s1, rep: Own1Report, s2=None) -> Own1Report:
    def data(snap, name):
        cell = snap.get(name)
        return cell.data if cell.ok() else b""

    bits0, bits1 = data(s0, CELL_BITS), data(s1, CELL_BITS)
    pt0 = data(s0, CELL_PT)
    rep.bmp_bits0, rep.bmp_bits1 = popcount(bits0), popcount(bits1)
    rep.bits_delta = abs(rep.bmp_bits1 - rep.bmp_bits0)
    rep.bmp_bytes_chg = byte_diff(bits0, bits1)
    rep.pt_bytes_chg = byte_diff(data(s0, CELL_PT), data(s1, CELL_PT))
    rep.pt_new, rep.pt_lost = word_delta(data(s0, CELL_PT), data(s1, CELL_PT))
    rep.cnt_chg = byte_diff(data(s0, CELL_COUNTERS), data(s1, CELL_COUNTERS)) \
                + byte_diff(data(s0, CELL_POOL), data(s1, CELL_POOL))
    rep.own_chg = byte_diff(data(s0, CELL_RECORDS), data(s1, CELL_RECORDS))
    rep.vmid_chg = byte_diff(data(s0, CELL_VMID), data(s1, CELL_VMID))
    rep.limit_chg = byte_diff(data(s0, CELL_BMP_LIMIT), data(s1, CELL_BMP_LIMIT))
    rep.root_chg = byte_diff(data(s0, CELL_BMP_ROOT), data(s1, CELL_BMP_ROOT)) \
                 + byte_diff(data(s0, CELL_PT_ROOT), data(s1, CELL_PT_ROOT))
    for name in ATTACH_CELLS:
        if data(s0, name) or data(s1, name):
            rep.attach = 1
    if s2 is not None:
        rep.settle_bmp_bytes_chg = byte_diff(bits1, data(s2, CELL_BITS))
        rep.settle_pt_bytes_chg = byte_diff(data(s1, CELL_PT), data(s2, CELL_PT))
    # sensitivity witnesses: a window cannot certify anything unless it is shown to be live
    rep.bmp_window_varied = 1 if len(set(bits0)) > 1 else 0
    rep.pt_slots_live = sum(1 for i in range(0, len(pt0) - 7, 8) if pt0[i:i + 8] != b"\x00" * 8)
    return rep


def classify(rep: Own1Report) -> tuple:
    if rep.attach == 0 and rep.bmp_bytes_chg == 0 and rep.pt_bytes_chg == 0 \
            and rep.cnt_chg == 0 and rep.own_chg == 0:
        return MEASURED_INCONCLUSIVE, ["no window authority available (device not attached)"]
    if rep.root_chg or rep.pt_lost:
        return AUTHORITY_DIVERGENCE, ["root pointer or translation entry disappeared"]
    if rep.pt_new and rep.bits_delta:
        return STALE_TRANSLATION, ["surviving translation entry plus ownership artefact"]
    if rep.pt_new:
        return AUTHORITY_DIVERGENCE, ["translation entry without ownership artefact"]
    if rep.bits_delta:
        return STALE_OWNER, ["ownership bits changed without translation"]
    if rep.cnt_chg:
        return RESOURCE_LEAK, ["counters changed, no translation and no ownership artefact"]
    if rep.own_chg:
        return STALE_OWNER, ["record/ownership entry changed"]
    if rep.bmp_bytes_chg == 0 and rep.pt_bytes_chg == 0:
        return FULL_ROLLBACK, ["every measured authority identical"]
    return MEASURED_INCONCLUSIVE, ["differential not explainable by the ladder"]


def verdict(rep: Own1Report) -> str:
    """The wave verdict (readiness level for the live wave; see the readiness note).

    * A window cannot certify anything unless it is shown to be live: at least one of the
      two windows must carry non-uniform, attributable structure in the baseline read
      (``bmp_window_varied`` / ``pt_slots_live``); otherwise INCONCLUSIVE.
    * A T0 signal only becomes RESIDUAL_STATE_CONFIRMED when it survives the settle read;
      a signal that drains between the two post reads is a delayed free (TRANSIENT_DRAINED)
      and is never reported as a residual state.
    * A clean pair of post reads is ROLLBACK_CONFIRMED only with the witnesses present and
      no settle change; a clean bitmap alone is never enough.
    """
    signal0 = bool(rep.pt_new or rep.bits_delta or rep.cnt_chg or rep.own_chg
                   or rep.root_chg or rep.pt_lost)
    settle_change = bool(rep.settle_bmp_bytes_chg or rep.settle_pt_bytes_chg)
    witness = bool(rep.bmp_window_varied or rep.pt_slots_live)
    if rep.attach == 0 or not witness or rep.classification == MEASURED_INCONCLUSIVE:
        return INCONCLUSIVE
    if signal0 and not settle_change:
        return RESIDUAL_STATE_CONFIRMED
    if signal0:
        return TRANSIENT_DRAINED
    if not settle_change:
        return ROLLBACK_CONFIRMED
    return INCONCLUSIVE
