"""Q6 shared-window aliasing experiment (PS4RF form).

All Q6 data lives here: markers, status geometry, which recipe cells matter and
the classification ladder of the accepted payload.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from tools.experiments.device import Target, build_ioctl_blob
from tools.experiments.inventory import token_in, token_in_slice, token_in_window_range

RECIPE = "q6-recipe-v3"
TOKEN_A = b"Q6AAAAAA"
TOKEN_B = b"Q6BBBBBB"
BUFFER_LEN = 0x4000

#: The device verifies the staged block's first 0x20 bytes against the PUP header constant the
#: driver holds at 0xffffffffd0aebae3: `memcmp(staged, "Sony Computer Entertainment Inc.", 0x20)`
#: at 0x637120, and a mismatch is errno 79 (EFTYPE). The live submit returned exactly that until
#: the header was in place, so every payload starts with it and the token fills the rest.
PUP_HEADER = b"Sony Computer Entertainment Inc."
STATUS_OFF = 0x160
STATUS_LEN = 0x104
SECFIELD_LEN = 0x18
HEAD_CELLS = ("A_HEAD", "B_HEAD")
STATUS_CELLS = ("A_HEAD", "A_STATUS", "B_HEAD", "B_STATUS")
# each cell's base offset inside its window (from the recipe's declarative offsets)
CELL_BASE = {"A_HEAD": 0x0, "A_STATUS": STATUS_OFF, "A_CHUNK": 0x280,
             "B_HEAD": 0x0, "B_STATUS": STATUS_OFF}
WINDOW_CELLS = ("A_HEAD", "A_STATUS", "A_CHUNK", "B_HEAD", "B_STATUS")
SUBMIT = 0xC0184401
#: W18: the argument block's mode/flags word (0x10). 0 requests the base transfer only; 2 adds a
#: second engine pass (0x638376). The old model's `op` field does not exist in this ABI.
SUBMIT_MODE = 0

TOCTOU_CONFIRMED = "TOCTOU_CONFIRMED"
GLOBAL_STATUS_ALIASING = "GLOBAL_STATUS_ALIASING"
STATUS_OWNERSHIP_UNPROVABLE = "STATUS_OWNERSHIP_UNPROVABLE"
SHARED_BACKING_ONLY = "SHARED_BACKING_ONLY"
ENGINE_LATCHED_BEFORE_UNLOCK = "ENGINE_LATCHED_BEFORE_UNLOCK"
BUG_CANDIDATE = "BUG_CANDIDATE"


def host_buffers(with_pup_header: bool = False) -> dict:
    """The A and B payloads.

    The default is the frozen oracle's layout (the token from offset 0), which the offline vectors
    and the tape record. The live device rejects anything whose first 0x20 bytes are not the PUP
    header constant, so the live wave asks for ``with_pup_header=True`` and keeps the token behind
    it -- the header is a property of the device, not of the experiment.
    """
    head = PUP_HEADER if with_pup_header else b""
    fill = BUFFER_LEN - len(head)
    return {"A": head + TOKEN_A * (fill // len(TOKEN_A)),
            "B": head + TOKEN_B * (fill // len(TOKEN_B))}


@dataclass
class Q6Report:
    rc_a: int = 0
    errno_a: int = 0
    rc_b: int = 0
    errno_b: int = 0
    id_a: int = 0
    a_status: int = 0
    b_status: int = 0
    b_window: int = 0
    b_any: int = 0
    sec_field: int = 0
    attach: int = 0
    cells_a: tuple = ()
    cells_b: tuple = ()
    classification: str = ""
    notes: list = field(default_factory=list)

    def as_dict(self) -> dict:
        d = dict(self.__dict__)
        d["cells_a"] = list(self.cells_a)
        d["cells_b"] = list(self.cells_b)
        return d


def run(target: Target) -> Q6Report:
    rep = Q6Report()
    s0 = target.run_recipe(RECIPE)
    rep.rc_a, rep.errno_a, _ = target.ioctl(target.policy.device, SUBMIT,
                                            build_ioctl_blob(target.policy, SUBMIT, ptr=0x0,
                                                             size=BUFFER_LEN,
                                                             mode=SUBMIT_MODE))
    s1 = target.run_recipe(RECIPE)
    rep.attach = s1.attach
    hits_a = token_in(s1, TOKEN_A, WINDOW_CELLS)
    rep.id_a = 1 if hits_a else 0
    rep.cells_a = hits_a
    rep.a_status = 1 if token_in_window_range(s1, TOKEN_A, CELL_BASE,
                                              STATUS_OFF, STATUS_OFF + STATUS_LEN) else 0

    rep.rc_b, rep.errno_b, _ = target.ioctl(target.policy.device, SUBMIT,
                                            build_ioctl_blob(target.policy, SUBMIT, ptr=0x0,
                                                             size=BUFFER_LEN,
                                                             mode=SUBMIT_MODE))
    s2 = target.run_recipe(RECIPE)
    s3 = target.run_recipe(RECIPE)
    for snap in (s2, s3):
        if token_in_window_range(snap, TOKEN_B, CELL_BASE, STATUS_OFF, STATUS_OFF + STATUS_LEN):
            rep.b_status = 1
        hits_b = token_in(snap, TOKEN_B, WINDOW_CELLS)
        if hits_b:
            rep.b_window = 1
            rep.b_any = 1
            rep.cells_b = hits_b
        if token_in_slice(snap, TOKEN_B, HEAD_CELLS, 0, SECFIELD_LEN):
            rep.sec_field = 1
    rep.classification, rep.notes = classify(rep)
    return rep


def classify(rep: Q6Report) -> tuple:
    if rep.attach == 0 and rep.id_a == 0:
        return STATUS_OWNERSHIP_UNPROVABLE, ["target reports ATTACH=0: no window authority"]
    if rep.id_a == 0:
        if rep.b_status:
            return STATUS_OWNERSHIP_UNPROVABLE + "|" + GLOBAL_STATUS_ALIASING, \
                   ["no A-attributable field: identity cannot be established"]
        return STATUS_OWNERSHIP_UNPROVABLE, ["no A-attributable field"]
    if rep.b_status:
        notes = []
        if rep.sec_field:
            notes.append("security-sensitive field contaminated: review as " + BUG_CANDIDATE)
        return TOCTOU_CONFIRMED, notes
    if rep.b_window or rep.b_any:
        return SHARED_BACKING_ONLY, ["B state reached the shared backing window only"]
    return ENGINE_LATCHED_BEFORE_UNLOCK, ["no B influence on any A-attributable state"]
