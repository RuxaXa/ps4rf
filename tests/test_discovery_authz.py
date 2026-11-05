"""Privilege reachability: dispatch is provable offline, absence of a gate is not."""
from __future__ import annotations

import sys
import pathlib

ROOT = pathlib.Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from tools.discovery import authz


class FakeImage:
    base = 0xFFFFFFFFD0000000

    def __init__(self, blobs):
        self.blobs = blobs

    def read(self, rva, size):
        blob = self.blobs.get(rva)
        if blob is None:
            return b""
        return blob[:size]

    def is_canonical_kernel_va(self, pointer):
        return pointer >> 32 == 0xFFFFFFFF


def test_sysent_slots_resolve_to_in_image_handlers():
    facts = {"tables": {"sysent": {"rva": "0x1000", "stride": 48, "narg_offset": 0,
                                   "sy_call_offset": 8, "entries_checked": 2}}}
    handler = 0xFFFFFFFFD0002000
    image = FakeImage({0x1008: handler.to_bytes(8, "little"),
                       0x1038: (handler + 0x40).to_bytes(8, "little")})
    records = authz.resolve_syscall_dispatch(image, facts)
    assert [r["handler"] for r in records] == ["0x2000", "0x2040"]
    assert records[0]["pointer_field"] == "0x1008"
    assert records[0]["handler_va"] == hex(handler)


def test_a_pointer_outside_the_image_is_not_a_dispatch_target():
    facts = {"tables": {"sysent": {"rva": "0x1000", "stride": 48,
                                   "sy_call_offset": 8, "entries_checked": 1}}}
    image = FakeImage({0x1008: (0x1234).to_bytes(8, "little")})
    assert authz.resolve_syscall_dispatch(image, facts) == []


def test_a_detected_gate_makes_the_entry_privileged():
    gates = {"gates": [{"site": "0x2004", "kind": "prison0-reference",
                        "evidence": "mov rax, [rip + 0x111fa18] reads prison0"}],
             "functions_walked": 3, "truncated": False}
    verdict = authz.classify({"kind": "syscall"}, gates, {})
    assert verdict["status"] == authz.PRIVILEGED
    assert verdict["basis"] == "prison0-reference"


def test_without_authorization_symbols_the_answer_stays_unknown():
    verdict = authz.classify({"kind": "syscall"}, {"gates": [], "functions_walked": 9,
                                                  "truncated": True}, {})
    assert verdict["status"] == authz.UNKNOWN
    assert "authorization symbols are not resolved" in verdict["missing_obligation"]
    assert verdict["walk_truncated"] is True


def test_recorded_evidence_is_the_only_way_to_reach_unprivileged():
    facts = {"entry_authorization": {"basis": "cdevsw-world-accessible",
                                     "evidence": "record mode 0666 at 0x1aec0f0",
                                     "unprivileged": True}}
    verdict = authz.classify({"kind": "cdevsw"}, {"gates": [], "functions_walked": 1}, facts)
    assert verdict["status"] == authz.UNPRIVILEGED
    assert "0666" in verdict["evidence"]


def test_a_claim_without_evidence_is_not_unprivileged():
    facts = {"entry_authorization": {"basis": "cdevsw-world-accessible", "unprivileged": True}}
    verdict = authz.classify({"kind": "cdevsw"}, {"gates": [], "functions_walked": 1}, facts)
    assert verdict["status"] != authz.UNPRIVILEGED
