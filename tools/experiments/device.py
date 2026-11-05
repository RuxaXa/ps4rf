"""Generic experiment target: bounded snapshot + allow-listed ioctl.

``Target`` implements the two PS4RF primitives only. It contains no experiment
knowledge: no markers, no window layouts, no command semantics.
``SimulatedConsole`` adds a simulated console (image + object memory + a
declarative effect table) so the accepted oracle vectors replay offline; the
host buffer contents and the geometry come from the experiments.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path

from tools.experiments import contracts as C

FIXTURES = Path(__file__).resolve().parents[2] / "tests" / "fixtures" / "experiments"

IMAGE_LO = 0xFFFFFFFFD0000000
WIN_A_BASE = 0xFFFF82DA068F0000
WIN_B_BASE = 0xFFFF82DA068F1000
BMP_BASE = 0xFFFFFF80055DC000
# Bitmap geometry (FW13.52, campaign A2): one word covers 1 MiB of GPUVA (64 bits of 0x4000
# units); below 0x9D800000 sits the statically reserved boot union, so allocation artefacts
# can only appear at words >= 0x9D800000 >> 20 = 2520. The scenario marks live there.
BMP_DYNAMIC_FIRST_WORD = 2520
# PT geometry (same image): level1 holds one 8-byte block entry per 8 MiB of GPUVA
# (index = gpuva >> 0x17); the first dynamically allocatable block is 0x9D800000 >> 0x17.
PT_DYNAMIC_FIRST_SLOT = 315
PT_BASE = 0xFFFF82DA052C6000
CDEV_VALUE = 0xFFFF82DA068EF200


@dataclass
class Cell:
    name: str = ""
    status: int = 0
    why: str = "NONE"
    length: int = 0
    addr: int = 0
    root_value: int = 0
    data: bytes = b""

    def ok(self) -> bool:
        return self.status == 0


@dataclass
class Snapshot:
    cells: dict = field(default_factory=dict)
    attach: int = 0

    def get(self, name: str) -> Cell:
        if name not in self.cells:
            raise KeyError(f"recipe has no cell {name!r}")
        return self.cells[name]

    def names(self) -> tuple:
        return tuple(self.cells)


def load_recipe(name: str) -> dict:
    return json.loads((FIXTURES / f"{name}.json").read_text())


def load_policy(name: str = "ioctl-policy-v1") -> C.IoctlPolicy:
    doc = json.loads((FIXTURES / f"{name}.json").read_text())
    return C.IoctlPolicy(device=doc["device"], commands=tuple(
        C.CommandPolicy(command=int(c["command"], 16), device=doc["device"],
                        blob_len=int(c["blob_len"]), out_len=int(c.get("out_len", 0)),
                        mode_values=tuple(c.get("mode_values", ())),
                        size_field=(None if c.get("size_field") is None
                                    else int(c["size_field"])),
                        size_round=int(c.get("size_round", 0x4000)),
                        mode_field=(None if c.get("mode_field") is None
                                    else int(c["mode_field"])),
                        blob_mode_values=tuple(c.get("blob_mode_values", ())))
        for c in doc["commands"]))


class Target:
    def __init__(self, policy: C.IoctlPolicy, recipe_loader=load_recipe) -> None:
        self.policy = policy
        self._recipe_loader = recipe_loader

    def run_recipe(self, recipe_id: str, indices: dict | None = None, kbase: int = IMAGE_LO) -> Snapshot:
        doc = self._recipe_loader(recipe_id)
        indices = indices or {}
        cells: dict[str, Cell] = {}
        attach = 0
        for e in doc["entries"]:
            cell = Cell(name=e["name"])
            if e["type"] == "RVA_READ":
                va = kbase + int(e["rva"], 16)
                if not C.canonical(va):
                    cell.status, cell.why = 1, "ROOT_NOT_CANONICAL"
                else:
                    cell.addr = va
                    cell.data = self.read_va(va, int(e["length"]))
                    cell.length = len(cell.data)
            else:
                root = cells[doc["entries"][e["root_index"]]["name"]]
                root_value = int.from_bytes(root.data[:8], "little") if (root.ok() and root.length == 8) else 0
                cell.root_value = root_value
                if root_value == 0:   # every FOLLOW_ONCE is attach gated (same rule as the generator)
                    cell.status, cell.why = 2, "ROOT_ZERO"
                    cells[cell.name] = cell
                    continue
                idx = 0
                if e.get("index_source"):
                    if e["index_source"] not in indices:
                        cell.status, cell.why = 1, "INDEX_MISSING"
                        cells[cell.name] = cell
                        continue
                    idx = int(indices[e["index_source"]])
                    if idx < 0 or idx > int(e["max_index"]):
                        cell.status, cell.why = 1, "INDEX"
                        cells[cell.name] = cell
                        continue
                try:
                    if e.get("index_source"):
                        _follow_ok_indexed(root_value, int(e.get("disp", 0)), idx, int(e["length"]))
                    else:
                        C.check_follow(root_value, int(e.get("disp", 0)), int(e["length"]))
                except C.ContractError as exc:
                    cell.status, cell.why = 1, str(exc).split(":")[-1].strip().upper().replace(" ", "_")
                    cells[cell.name] = cell
                    continue
                va = root_value + int(e.get("disp", 0)) + idx * 8
                cell.addr = va
                cell.data = self.read_va(va, int(e["length"]))
                cell.length = len(cell.data)
                attach = 1
            cells[cell.name] = cell
        return Snapshot(cells=cells, attach=attach)

    def read_va(self, va: int, length: int) -> bytes:
        raise NotImplementedError

    def ioctl(self, device: str, command: int, blob: bytes, mode: int | None = None) -> tuple:
        raise NotImplementedError


def _follow_ok_indexed(root: int, base_disp: int, idx: int, length: int) -> None:
    if length == 0 or length > C.MAX_ENTRY_LEN:
        raise C.ContractError("len")
    if base_disp > C.MAX_DISP:
        raise C.ContractError("disp")
    if idx * 8 + length > 0x8000:
        raise C.ContractError("span")
    if root == 0:
        raise C.ContractError("ROOT_ZERO")
    if not C.canonical(root):
        raise C.ContractError("ROOT_NOT_CANONICAL")
    if root & 7:
        raise C.ContractError("ROOT_NOT_ALIGNED")
    if not C.no_wrap(root, base_disp + idx * 8 + length):
        raise C.ContractError("WRAP")


SCENARIOS = {
    "q6_toctou": {"effects": [(1, "A", 0x160, 0, 0x40, "A"), (2, "A", 0x160, 0, 0x100, "B")], "rc": 0, "errno": 0},
    "q6_shared": {"effects": [(1, "A", 0x160, 0, 0x40, "A"), (2, "A", 0x08, 0, 0x20, "B")], "rc": 0, "errno": 0},
    "q6_latched": {"effects": [(1, "A", 0x160, 0, 0x40, "A")], "rc": 0, "errno": 0},
    "q6_noid": {"effects": [(2, "A", 0x160, 0, 0x100, "B")], "rc": 0, "errno": 0},
    "on1_rollback": {"effects": [], "rc": -1, "errno": 12, "mutate": None},
    "on1_stale": {"effects": [], "rc": -1, "errno": 12, "mutate": "pt_and_bits"},
    "on1_leak": {"effects": [], "rc": -1, "errno": 12, "mutate": "counters"},
    "on1_diverg": {"effects": [], "rc": -1, "errno": 12, "mutate": "pt_only"},
    # instrumentation controls (not oracle vectors): an artefact placed outside every window
    # must not leak into the read set; an artefact that drains between the two post reads is
    # a delayed free, not a residual state.
    "on1_ctrl_outside": {"effects": [], "rc": -1, "errno": 12, "mutate": "outside_windows"},
    "on1_delayed": {"effects": [], "rc": -1, "errno": 12, "mutate": "pt_and_bits",
                    "settle": "drain"},
}


class SimulatedConsole(Target):
    def __init__(self, scenario: str, host_buffers: dict, policy: C.IoctlPolicy | None = None,
                 recipe_loader=load_recipe) -> None:
        super().__init__(policy or load_policy(), recipe_loader)
        if scenario not in SCENARIOS:
            raise C.ContractError(f"unknown scenario {scenario!r}")
        self.scenario = scenario
        self.cfg = SCENARIOS[scenario]
        self.host_buffers = host_buffers
        self.calls = 0
        self.errno = 0
        self.attach = 1
        self.win = {"A": bytearray(0x700), "B": bytearray(0x300)}
        self.objs = {BMP_BASE: bytearray(0x8000), PT_BASE: bytearray(0x1000)}
        self.image = {0x2684810: CDEV_VALUE, 0x2684840: WIN_A_BASE, 0x2684848: WIN_B_BASE,
                      0x238A870: BMP_BASE, 0x23D4558: PT_BASE, 0x238A848: 0xBD558000}
        self.vmid = bytearray(8)
        self.rec = bytearray(0x100)
        self.cnt = bytearray(0x40)
        self.pool = bytearray(8)
        self.image_objects = {0x238A880: self.rec, 0x23D3D30: self.cnt,
                              0x23D459C: self.pool, 0x23D4538: self.vmid}
        self.vmid[0] = 0x0F
        self.pool[0] = 0x3D
        self.pool[1] = 0x01
        self.cnt[5] = 0x0A
        self.rec[1] = 0x40
        self.objs[BMP_BASE][BMP_DYNAMIC_FIRST_WORD * 8 + 0] = 0x55
        self.objs[BMP_BASE][BMP_DYNAMIC_FIRST_WORD * 8 + 1] = 0xAA
        # one steady-state block pointer in the dynamic PT range: the sensitivity witness
        lo = (PT_DYNAMIC_FIRST_SLOT + 1) * 8
        self.objs[PT_BASE][lo:lo + 8] = (0xFFFFFF8069374000).to_bytes(8, "little")
        self._post_reads = None

    def read_va(self, va: int, length: int) -> bytes:
        if IMAGE_LO <= va < IMAGE_LO + 0x40000000:
            rva = va - IMAGE_LO
            if rva in self.image:
                value = self.image[rva]
                return value.to_bytes(8, "little")[:length].ljust(length, b"\x00")
            for rva_o, store in self.image_objects.items():
                if rva_o <= rva < rva_o + len(store):
                    off = rva - rva_o
                    return bytes(store[off:off + length]).ljust(length, b"\x00")
            return bytes((va + i) & 0xFF for i in range(length))
        if WIN_A_BASE <= va < WIN_A_BASE + 0x700:
            off = va - WIN_A_BASE
            return bytes(self.win["A"][off:off + length]).ljust(length, b"\x00")
        if WIN_B_BASE <= va < WIN_B_BASE + 0x300:
            off = va - WIN_B_BASE
            return bytes(self.win["B"][off:off + length]).ljust(length, b"\x00")
        for base, store in self.objs.items():
            if base <= va < base + len(store):
                off = va - base
                return bytes(store[off:off + length]).ljust(length, b"\x00")
        raise C.ContractError(f"simulated read outside every known object: {va:#x}")

    def run_recipe(self, recipe_id, indices=None, kbase=IMAGE_LO):
        if self._post_reads == 1:
            self._apply_settle()
        snap = super().run_recipe(recipe_id, indices, kbase)
        if self._post_reads is not None:
            self._post_reads += 1
        return snap

    def _apply_settle(self):
        """A deferred free landing between the two post reads (drains the T0 artefact)."""
        if self.cfg.get("settle") != "drain":
            return
        lo = PT_DYNAMIC_FIRST_SLOT * 8
        self.objs[PT_BASE][lo:lo + 8] = b"\x00" * 8
        self.objs[BMP_BASE][BMP_DYNAMIC_FIRST_WORD * 8 + 2] &= ~0x01

    def ioctl(self, device: str, command: int, blob: bytes, mode: int | None = None) -> tuple:
        self.policy.validate(command, blob, mode)
        self.calls += 1
        if command == 0xC010440A:
            return (0, 0, b"")
        for call, win, dst, src, length, key in self.cfg["effects"]:
            if call == self.calls:
                buf = self.host_buffers[key]
                self.win[win][dst:dst + length] = buf[src:src + length]
        if command == 0xC0184404:
            mut = self.cfg.get("mutate")
            if mut == "pt_and_bits":
                lo = PT_DYNAMIC_FIRST_SLOT * 8
                self.objs[PT_BASE][lo:lo + 8] = (0xFFFF052C6000).to_bytes(8, "little")
                self.objs[BMP_BASE][BMP_DYNAMIC_FIRST_WORD * 8 + 2] |= 0x01
            elif mut == "pt_only":
                lo = PT_DYNAMIC_FIRST_SLOT * 8
                self.objs[PT_BASE][lo:lo + 8] = (0xFFFF052C6000).to_bytes(8, "little")
            elif mut == "counters":
                self.cnt[0] = (self.cnt[0] + 3) & 0xFF
                self.pool[0] = (self.pool[0] + 1) & 0xFF
            elif mut == "outside_windows":
                self.objs[PT_BASE][100 * 8] |= 0x08
                self.objs[BMP_BASE][100] |= 0x01
            self._post_reads = 0
            self.errno = self.cfg["errno"]
            return (self.cfg["rc"], self.cfg["errno"], b"")
        self.errno = self.cfg["errno"]
        return (self.cfg["rc"], self.cfg["errno"], b"")


def build_ioctl_blob(policy: C.IoctlPolicy, command: int, *, ptr: int = 0, size: int = 0,
                     length: int = 0, mode: int = 0) -> bytes:
    """The argument block for one command, in the ABI the driver actually reads.

    0xC0184401 (the submit family's sub 0, handler 0x638230) reads

    * ``field 0x00`` -- the user CPU address the kernel pins and maps (gpuvm.c ``map``:
      ``extractCpuAddrUser`` -> ``vm_fault_quick_hold_pages`` -> ``gbase_map``), held to a 0x4000
      boundary and mapping one 0x4000 unit. The experiment leaves it zero: the provider replaces
      it with the address of its own staging region, and the value the host sends never reaches
      the device.
    * ``field 0x08`` -- the request size; the handler computes
      ``(size + 0x3fff) & ~0x3fff == 0x4000`` (0x638295..0x6382b9) and answers EINVAL otherwise,
      so only 1..0x4000 is accepted.
    * ``field 0x10`` -- the mode/flags word (compared against 2 at 0x638376, which adds one engine
      pass); 0 is the proven value that requests only the base transfer.

    0xC0184404 keeps its own layout ({u16 mode, u64, u64}) from the family dispatcher; its fields
    are not proven, so ``ptr``/``length`` keep filling it as before.
    """
    pol = policy.command(command)
    if command == 0xC0184401:
        blob = (ptr.to_bytes(8, "little") + size.to_bytes(8, "little")
                + int(mode).to_bytes(4, "little") + b"\x00" * 4)
    elif command == 0xC0184404:
        blob = (mode or 0).to_bytes(2, "little") + b"\x00" * 6 + ptr.to_bytes(8, "little") \
               + length.to_bytes(8, "little")
    elif command == 0xC010440A:
        blob = b"\x00" * 24
    else:
        raise C.ContractError(f"no blob builder for {command:#x}")
    assert len(blob) == pol.blob_len, (command, len(blob), pol.blob_len)
    return blob
