"""Request/contract models for the two experiment primitives.

These are the *host-side* mirrors of the bounds the target enforces. They exist
so an experiment cannot even be expressed illegally, and so the parity oracle
tests the same rules the C side applies.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Iterable, Sequence

# --- canonical kernel address space (48-bit high canonical) -----------------
KVA_LO = 0xFFFF800000000000
KVA_HI = 0xFFFFFFFFFFFFFFFF
KVA_TRUNCATION_44BIT = 0x0000FFFF80000000  # the wrong lower bound (14 hex digits)

MAX_ENTRIES = 16
MAX_ENTRY_LEN = 0x1000
MAX_DISP = 0x1000

RVA_READ = "RVA_READ"
FOLLOW_ONCE = "FOLLOW_ONCE"
ENTRY_TYPES = (RVA_READ, FOLLOW_ONCE)


class ContractError(ValueError):
    """A request that the target would refuse; never sent."""


def canonical(va: int) -> bool:
    """48-bit high canonical, lower bound 0xffff800000000000 (16 hex digits)."""
    return KVA_LO <= va <= KVA_HI


def no_wrap(base: int, add: int) -> bool:
    """base + add must not leave the canonical range (no 64-bit wraparound)."""
    return 0 <= add and base <= KVA_HI - add


@dataclass(frozen=True)
class RecipeEntry:
    name: str
    type: str
    addr: int = 0            # RVA for RVA_READ; index of the root entry for FOLLOW_ONCE
    length: int = 0
    root_index: int = -1
    disp: int = 0
    flags: int = 0

    def validate(self, index: int, count: int) -> None:
        if self.type not in ENTRY_TYPES:
            raise ContractError(f"entry {index} {self.name}: type {self.type!r} not allowed")
        if not 0 < self.length <= MAX_ENTRY_LEN:
            raise ContractError(f"entry {index} {self.name}: length {self.length:#x} out of (0, {MAX_ENTRY_LEN:#x}]")
        if self.type == RVA_READ:
            if self.addr < 0:
                raise ContractError(f"entry {index} {self.name}: negative rva")
        else:
            if not 0 <= self.root_index < index:
                raise ContractError(f"entry {index} {self.name}: root_index {self.root_index} must name an earlier entry")
            if not 0 <= self.disp <= MAX_DISP:
                raise ContractError(f"entry {index} {self.name}: disp {self.disp:#x} above {MAX_DISP:#x}")


@dataclass(frozen=True)
class Recipe:
    """A bounded snapshot recipe: at most 16 entries, one follow level."""
    name: str
    entries: Sequence[RecipeEntry] = field(default_factory=tuple)

    def validate(self) -> "Recipe":
        if len(self.entries) > MAX_ENTRIES:
            raise ContractError(f"recipe {self.name}: {len(self.entries)} entries above {MAX_ENTRIES}")
        for i, e in enumerate(self.entries):
            e.validate(i, len(self.entries))
        return self

    def entry(self, index: int) -> RecipeEntry:
        return self.entries[index]


def check_follow(root_value: int, disp: int, length: int) -> None:
    """The rule the target applies before a FOLLOW_ONCE read."""
    if root_value == 0:
        raise ContractError("follow: root is zero (device or object not attached)")
    if not canonical(root_value):
        raise ContractError(f"follow: root {root_value:#018x} not canonical")
    if root_value & 7:
        raise ContractError(f"follow: root {root_value:#018x} not 8 byte aligned")
    if not 0 <= disp <= MAX_DISP:
        raise ContractError(f"follow: disp {disp:#x} above {MAX_DISP:#x}")
    if not 0 < length <= MAX_ENTRY_LEN:
        raise ContractError(f"follow: length {length:#x} out of range")
    if not no_wrap(root_value, disp + length):
        raise ContractError("follow: root + disp + length wraps")


# --- ioctl.invoke policy ---------------------------------------------------

@dataclass(frozen=True)
class CommandPolicy:
    command: int
    device: str
    blob_len: int          # exact arg-block size the command takes
    out_len: int = 0       # response bytes the command writes back
    mode_values: Sequence[int] = ()
    # W18 submit ABI (proven from the FW13.52 image): where the driver reads the request size and
    # the mode word inside the argument block, and what it accepts there.
    size_field: int | None = None      # offset of the u64 the handler rounds to a boundary
    size_round: int = 0x4000           # that boundary (0x4000); accepted values are (0, round]
    mode_field: int | None = None      # offset of the u32 mode/flags word
    blob_mode_values: Sequence[int] = ()   # legal values of that word


@dataclass(frozen=True)
class IoctlPolicy:
    """Explicit device/command policy: nothing else can be invoked."""
    device: str
    commands: Sequence[CommandPolicy]

    def command(self, value: int) -> CommandPolicy:
        for c in self.commands:
            if c.command == value:
                return c
        raise ContractError(f"ioctl: command {value:#010x} not in policy")

    def validate(self, command: int, blob: bytes, mode: int | None = None) -> CommandPolicy:
        pol = self.command(command)
        if len(blob) != pol.blob_len:
            raise ContractError(f"ioctl {command:#010x}: blob {len(blob)} bytes, policy wants {pol.blob_len}")
        if pol.mode_values and mode is not None and mode not in pol.mode_values:
            raise ContractError(f"ioctl {command:#010x}: mode {mode:#x} not in {pol.mode_values}")
        if pol.size_field is not None:
            # the handler computes (size + bound - 1) & ~(bound - 1) == bound and answers EINVAL
            # otherwise, so only 1..bound survive; a zero or oversized request must not leave here
            size = int.from_bytes(blob[pol.size_field:pol.size_field + 8], 'little')
            bound = int(pol.size_round)
            if size == 0 or (size + bound - 1) & ~(bound - 1) != bound:
                raise ContractError(f"ioctl {command:#010x}: request size {size:#x} is outside "
                                    f"(0, {bound:#x}] (the driver rounds it to {bound:#x})")
        if pol.mode_field is not None and pol.blob_mode_values:
            word = int.from_bytes(blob[pol.mode_field:pol.mode_field + 4], 'little')
            if word not in pol.blob_mode_values:
                raise ContractError(f"ioctl {command:#010x}: argument mode {word:#x} not in "
                                    f"{tuple(pol.blob_mode_values)}")
        return pol


def command_allowlist(policy: IoctlPolicy) -> tuple[int, ...]:
    return tuple(c.command for c in policy.commands)


def assert_no_raw_address(request: dict) -> None:
    """An experiment may not carry a raw kernel address (recipe/profile carry them)."""
    for key in ("addr", "address", "va", "kernel_address"):
        if key in request:
            raise ContractError(f"request carries a raw address field {key!r}; addresses come from the profile")
