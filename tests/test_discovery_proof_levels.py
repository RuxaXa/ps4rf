"""The proof ladder must stop where the evidence stops."""
from __future__ import annotations

import sys
import pathlib

ROOT = pathlib.Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from tools.discovery import chains


def finding(**overrides):
    base = {"detector": "D2_double_release", "function": {"rva": "0x100"},
            "bug_class": "OWNERSHIP_DOUBLE_FREE", "rank": 1}
    base.update(overrides)
    return base


def test_the_ladder_has_the_five_levels_in_order():
    assert chains.PROOF_LEVELS == ("CFG_REACHABLE", "UNPRIV_REACHABLE", "OBJECT_FLOW_PROVEN",
                                  "PRIMITIVE_VALIDATED", "EXPLOIT_CHAIN_VALIDATED")


def test_a_reachable_but_unauthorized_chain_stops_at_cfg_reachable():
    chain = chains.compose(finding(), "entry:sysent[22]", {}, entry_proved=True)
    assert chain.proof_level == "CFG_REACHABLE"
    rung = next(r for r in chain.obligations if r["status"] == "OPEN")
    assert rung["level"] == "UNPRIV_REACHABLE"
    assert [m["requirement"] for m in rung["missing"]] == ["REQ_UNPRIV_ENTRY"]
    assert "authorization" in rung["missing"][0]["why"]


def test_even_a_proved_path_never_reads_as_an_exploitable_chain():
    """The lesson of S1.3: 'proved' is a control-flow statement, not a vulnerability."""
    chain = chains.compose(finding(), "entry:sysent[22]", {}, entry_proved=True)
    assert chain.proof_level != "EXPLOIT_CHAIN_VALIDATED"
    assert chain.proof_level != "PRIMITIVE_VALIDATED"
    assert chain.complete is False


def test_an_unreachable_chain_sits_below_the_first_rung():
    chain = chains.compose(finding(), "entry:sysent[22]", {}, entry_proved=False)
    assert chain.proof_level == chains.UNREACHED


def test_authorization_alone_advances_to_unpriv_reachable():
    evidence = {"authorization": {"basis": "syscall-cred-gate-absent",
                                  "evidence": "handler path read: no cred load",
                                  "unprivileged": True}}
    chain = chains.compose(finding(), "entry:sysent[22]", {}, entry_proved=True,
                           entry_evidence=evidence)
    assert chain.entry_privilege == chains.UNPRIVILEGED
    assert chain.proof_level == "UNPRIV_REACHABLE"
    rung = next(r for r in chain.obligations if r["status"] == "OPEN")
    assert rung["level"] == "OBJECT_FLOW_PROVEN"


def test_object_flow_evidence_advances_the_ladder_one_rung():
    evidence = {"authorization": {"basis": "syscall-cred-gate-absent",
                                 "evidence": "handler path read", "unprivileged": True}}
    flow = {"proved": True, "evidence": "rdi --mov--> rbx; both drop sites use rbx"}
    chain = chains.compose(finding(object_flow=flow), "entry:sysent[22]", {},
                           entry_proved=True, entry_evidence=evidence)
    assert chain.proof_level == "OBJECT_FLOW_PROVEN"


def test_a_call_edge_is_not_object_flow():
    flow = {"proved": False, "why": "the object is passed in rdi but the callee does not use it"}
    evidence = {"authorization": {"basis": "syscall-cred-gate-absent",
                                 "evidence": "handler path read", "unprivileged": True}}
    chain = chains.compose(finding(object_flow=flow), "entry:sysent[22]", {},
                           entry_proved=True, entry_evidence=evidence)
    assert chain.proof_level == "UNPRIV_REACHABLE"
    rung = next(r for r in chain.obligations if r["status"] == "OPEN")
    assert rung["missing"][0]["requirement"] == "REQ_OBJECT_FLOW"
    assert "callee does not use it" in rung["missing"][0]["why"]


def test_chain_stability_is_never_cleared_offline():
    outcome = chains._requirement_status("REQ_CHAIN_STABILITY", finding(), "syscall", {})
    assert outcome["status"] == chains.OPEN
    assert "live measurement" in outcome["why"]


def test_a_finding_whose_entry_key_is_a_label_still_composes():
    """The scan carries `entry` as a string; reading `.get` off it killed 211 chains once."""
    chain = chains.compose(finding(entry="sysent[22]", entry_witness="0x10 -> 0x20"),
                           "entry:sysent[22]", {}, entry_proved=True)
    assert chain.proof_level == "CFG_REACHABLE"
    assert chain.dimensions["cfg"]["verdict"] == "PROVEN"
    assert chain.dimensions["cfg"]["evidence"] == "0x10 -> 0x20"
