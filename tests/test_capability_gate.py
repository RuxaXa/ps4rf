"""P4/W4 capability gate: policy, matrix and the required negative scenarios.

Every scenario the work order names is a test here. All of them must end in
``OPERATION_DEFERRED``: the gate is fail-closed, claims carry no authority, and even a
fully satisfied context stays deferred until the provider is wired and approved.
"""
from __future__ import annotations

import importlib.util
import pathlib
import re
import sys

REPO_ROOT = pathlib.Path(__file__).resolve().parents[1]
DOC = REPO_ROOT / "docs" / "P4-CAPABILITY-GATE.md"
PACKAGE = REPO_ROOT / "tools" / "primitive_iface"
sys.path.insert(0, str(REPO_ROOT))

SID = "SES-0123456789ABCDEF"
BID = "BOOT-0123456789ABCDEF"
RUN = "RUN-" + "a" * 32
PROVIDER = "ps4rfd-native"


def _load(name: str, path: pathlib.Path):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


GATE = _load("w4_gate", PACKAGE / "gate.py")
SCHEMA = _load("w4_schema", PACKAGE / "schema.py")
STUB = _load("w4_stub", PACKAGE / "stub.py")


def _capability_record(req, **overrides):
    record = {
        "name": req.capability,
        "namespace": req.namespace,
        "verified_by_operation": req.verification_op,
        "availability": "AVAILABLE",
        "assurance": req.min_assurance,
        "context": req.allowed_contexts[0],
        "provider": PROVIDER,
        "provider_type": "NATIVE",
        "scope": "SESSION",
        "session_id": SID,
        "boot_id": BID,
    }
    record.update(overrides)
    return record


def _verification_record(req, **overrides):
    record = {
        "run_id": RUN,
        "operation": req.verification_op,
        "outcome": "PASS",
        "capability": req.capability,
        "provider": PROVIDER,
        "provider_type": "NATIVE",
        "session_id": SID,
        "boot_id": BID,
    }
    record.update(overrides)
    return record


def satisfied_ctx(op: str, **overrides):
    """A context in which every precondition except wiring is satisfied."""
    req = GATE.REQ_BY_OP[op]
    kwargs = dict(
        capability_records=(_capability_record(req),),
        verification_records=(_verification_record(req),),
        evidence_refs=({"run_id": RUN, "sha256": "b" * 64},),
        profile_binding=({"present": True, "sha256": "c" * 64,
                          "fields": {name: "PLACEHOLDER" for name in req.profile_fields}}
                         if req.profile_required else None),
        session_id=SID,
        boot_id=BID,
        session_state="ACTIVE",
        provider=PROVIDER,
        provider_type="NATIVE",
        wired=False,
        approval={"approved": True, "state": "APPROVED", "id": "CMR-1"},
    )
    kwargs.update(overrides)
    return GATE.GateContext(**kwargs)


def _reasons(op: str, **overrides) -> tuple[str, ...]:
    return GATE.gate_for(op, satisfied_ctx(op, **overrides)).reasons


PRIVILEGED = GATE.privilege_gated_ops()
SAMPLE = "kernel.read"


# --- the required negative scenarios ------------------------------------------------
def test_scenario_missing_capability_stays_deferred():
    reasons = _reasons(SAMPLE, capability_records=())
    assert GATE.CAPABILITY_MISSING in reasons


def test_scenario_available_but_assurance_too_low_stays_deferred():
    req = GATE.REQ_BY_OP[SAMPLE]
    for lower in ("OBSERVED", "UNVERIFIED"):
        reasons = _reasons(SAMPLE, capability_records=(_capability_record(req, assurance=lower),))
        assert GATE.ASSURANCE_TOO_LOW in reasons, lower


def test_scenario_wrong_context_stays_deferred():
    req = GATE.REQ_BY_OP[SAMPLE]
    reasons = _reasons(SAMPLE, capability_records=(_capability_record(req, context="HOMEBREW"),))
    assert GATE.CONTEXT_MISMATCH in reasons


def test_scenario_wrong_session_boot_or_scope_stays_deferred():
    req = GATE.REQ_BY_OP[SAMPLE]
    assert GATE.BINDING_MISMATCH in _reasons(
        SAMPLE, capability_records=(_capability_record(req, session_id="SES-FFFFFFFFFFFFFFFF"),))
    assert GATE.BINDING_MISMATCH in _reasons(
        SAMPLE, capability_records=(_capability_record(req, boot_id="BOOT-FFFFFFFFFFFFFFFF"),))
    assert GATE.BINDING_MISMATCH in _reasons(
        SAMPLE, capability_records=(_capability_record(req, scope="BOOT", session_id=None),))


def test_scenario_wrong_profile_binding_stays_deferred():
    assert GATE.PROFILE_UNBOUND in _reasons(SAMPLE, profile_binding=None)
    assert GATE.PROFILE_UNBOUND in _reasons(SAMPLE, profile_binding={"present": True, "sha256": "c" * 64, "fields": {}})
    assert GATE.PROFILE_UNBOUND in _reasons(
        SAMPLE, profile_binding={"present": True, "sha256": None, "fields": {"addr": "PLACEHOLDER"}})
    # a profile entry alone activates nothing
    assert GATE.PROFILE_UNBOUND in _reasons(
        SAMPLE, capability_records=(), verification_records=(), profile_binding=None)


def test_scenario_missing_or_invalid_verification_evidence_stays_deferred():
    assert GATE.EVIDENCE_MISSING in _reasons(SAMPLE, verification_records=())
    req = GATE.REQ_BY_OP[SAMPLE]
    assert GATE.EVIDENCE_MISSING in _reasons(
        SAMPLE, verification_records=(_verification_record(req, outcome="FAIL"),))
    assert GATE.EVIDENCE_MISSING in _reasons(
        SAMPLE, verification_records=(_verification_record(req, provider_type="MOCK"),))
    assert GATE.EVIDENCE_MISSING in _reasons(SAMPLE, evidence_refs=())
    assert GATE.EVIDENCE_MISSING in _reasons(SAMPLE, evidence_refs=({"run_id": RUN},))
    assert GATE.EVIDENCE_MISSING in _reasons(
        SAMPLE, verification_records=(_verification_record(req, session_id="SES-FFFFFFFFFFFFFFFF"),))


def test_scenario_wrong_provider_stays_deferred():
    req = GATE.REQ_BY_OP[SAMPLE]
    for ptype in ("MOCK", "RUNTIME_PROBE", "FIRMWARE_PROFILE", "BOOTSTRAP", None):
        reasons = _reasons(SAMPLE, capability_records=(_capability_record(req, provider_type=ptype),))
        assert GATE.PROVIDER_NOT_ALLOWED in reasons, ptype
    reasons = _reasons(SAMPLE, capability_records=(_capability_record(req, provider="some-other-agent"),))
    assert GATE.PROVIDER_NOT_ALLOWED in reasons


def test_scenario_recovery_required_stays_deferred():
    reasons = _reasons(SAMPLE, session_state="RECOVERY_REQUIRED")
    assert GATE.RECOVERY_REQUIRED in reasons


def test_scenario_everything_satisfied_but_not_wired_stays_deferred():
    for op in PRIVILEGED + tuple(r.op for r in GATE.HOST_CHAIN_REQUIREMENTS):
        decision = GATE.gate_for(op, satisfied_ctx(op))
        assert decision.decision == "DEFERRED", op
        assert decision.reasons == (GATE.NOT_WIRED,), (op, decision.reasons)
        assert decision.wire_code == "OPERATION_DEFERRED"
        assert decision.executable is False
    # and with wiring claimed, the strongest possible answer is still not an execution
    wired = GATE.gate_for(SAMPLE, satisfied_ctx(SAMPLE, wired=True))
    assert wired.decision == "ELIGIBLE" and wired.reasons == ()
    assert wired.executable is False and wired.wire_code == "OPERATION_DEFERRED"


def test_scenario_no_path_from_mock_evidence_to_privileged_release():
    req = GATE.REQ_BY_OP[SAMPLE]
    mock_ctx = GATE.GateContext(
        capability_records=(_capability_record(req, provider_type="MOCK", provider="mock"),),
        verification_records=(_verification_record(req, provider_type="MOCK", provider="mock"),),
        evidence_refs=({"run_id": RUN, "sha256": "b" * 64},),
        profile_binding={"present": True, "sha256": "c" * 64,
                         "fields": {name: "PLACEHOLDER" for name in req.profile_fields}},
        session_id=SID, boot_id=BID, session_state="ACTIVE", provider="mock",
        provider_type="MOCK", wired=True, approval={"approved": True, "state": "APPROVED"},
        claims={"mock_success": True},
    )
    decision = GATE.gate_for(SAMPLE, mock_ctx)
    assert decision.decision == "DEFERRED"
    assert GATE.PROVIDER_NOT_ALLOWED in decision.reasons
    assert GATE.EVIDENCE_MISSING in decision.reasons
    # the stub never fakes a success either, whatever the gate says
    stub = STUB.StubProvider()
    rid = "REQ-" + "0" * 31 + "7"
    response = stub.call(SAMPLE, {"region_index": 1, "offset": 0, "length": 16}, rid)
    assert response["status"] == "ERROR"
    assert response["error"]["code"] == "OPERATION_DEFERRED"


def test_approval_missing_is_its_own_reason():
    assert GATE.APPROVAL_MISSING in _reasons(SAMPLE, approval=None)
    assert GATE.APPROVAL_MISSING in _reasons(SAMPLE, approval={"approved": False, "state": "DRAFT"})


# --- policy: claims carry no authority ----------------------------------------------
def test_claims_carry_no_authority():
    claims = {"symbol": "kern_read", "firmware_rva": "PLACEHOLDER", "profile_entry": True,
              "mock_success": True, "interface_exists": True, "operator_claim": "works"}
    only_claims = GATE.gate_for(SAMPLE, GATE.GateContext(claims=claims))
    assert only_claims.decision == "DEFERRED"
    assert set(only_claims.reasons) >= {GATE.CAPABILITY_MISSING, GATE.EVIDENCE_MISSING,
                                       GATE.APPROVAL_MISSING, GATE.NOT_WIRED}
    with_claims = GATE.gate_for(SAMPLE, satisfied_ctx(SAMPLE, claims=claims))
    assert with_claims.reasons == (GATE.NOT_WIRED,)  # claims change nothing


def test_unknown_claim_keys_are_refused():
    try:
        GATE.GateContext(claims={"magic_override": True})
    except ValueError as exc:
        assert "magic_override" in str(exc)
    else:
        raise AssertionError("unknown claim keys must be refused")


def test_gate_rejects_non_gated_operations():
    for op in ("memory.alloc", "session.ping", "mock.hang", "no.such.op"):
        try:
            GATE.gate_for(op, GATE.GateContext())
        except ValueError:
            continue
        raise AssertionError(f"{op} must not be a gate candidate")


def test_empty_context_is_deferred_for_every_gated_operation():
    for op in PRIVILEGED + tuple(r.op for r in GATE.HOST_CHAIN_REQUIREMENTS):
        decision = GATE.gate_for(op, GATE.GateContext())
        assert decision.decision == "DEFERRED", op
        assert decision.reasons, op
        assert decision.next_action, op


def test_every_reason_has_an_owner_for_the_transition_path():
    for op in PRIVILEGED:
        decision = GATE.gate_for(op, GATE.GateContext())
        for reason in decision.reasons:
            assert reason in GATE.REASON_OWNER
    assert set(GATE.REASON_OWNER) == set(GATE.REASONS)


# --- matrix, frozen core and document parity ----------------------------------------
def test_matrix_covers_exactly_the_privilege_gated_operations():
    assert sorted(GATE.REQ_BY_OP) == sorted(list(PRIVILEGED) + [r.op for r in GATE.HOST_CHAIN_REQUIREMENTS])
    for op in PRIVILEGED:
        spec = SCHEMA.OPS_BY_NAME[op]
        assert spec.status == SCHEMA.STATUS_DEFER_PRIVILEGE
        req = GATE.REQ_BY_OP[op]
        assert req.capability == spec.capability, op
        if req.namespace in SCHEMA.PRIVILEGED_NAMESPACES:
            assert req.min_assurance == "PROVEN", op
            assert "MOCK" not in req.allowed_providers, op


def test_doc_matrix_matches_the_gate_module():
    rows = []
    for line in DOC.read_text().splitlines():
        if line.startswith("| `") and line.count("|") == 8:
            cells = [c.strip() for c in line.strip("|").split("|")]
            rows.append(cells)
    assert len(rows) == len(GATE.REQ_BY_OP), f"expected the requirement-mechanism rows, found {len(rows)}"
    for cells in rows:
        op = cells[0].strip("`")
        req = GATE.REQ_BY_OP[op]
        assert cells[1] == req.namespace, op
        assert cells[2] == req.min_assurance, op
        assert cells[3] == req.class_, op
        assert cells[4].strip("`") == req.verification_op, op
        assert (cells[5] == "yes") is req.profile_required, op
        assert (cells[6] == "yes") is req.cleanup_required, op
    assert {c[0].strip("`") for c in rows} == set(GATE.REQ_BY_OP)


def test_doc_and_module_stay_a_pure_data_layer():
    for path in (DOC, PACKAGE / "gate.py"):
        text = path.read_text()
        assert "/home/" not in text, path.name
        assert not re.search(r"0x[0-9a-fA-F]{6,}", text), path.name
        for token in ("import socket", "import subprocess", "urllib"):
            assert token not in text, path.name
    doc = DOC.read_text()
    assert "OPERATION_DEFERRED" in doc and "userland only" in doc
    assert "W4 produces gate decisions only" in doc


def test_the_gate_self_test_is_clean():
    """W17F: the module's own self check is part of the suite (it carried a count literal and went
    stale with the first operation the surface gained -- a gate nobody runs is a gate that lies)."""
    assert GATE._self_test() == []
    # the gated set is the interface's deferred-privilege surface, and no privileged namespace may
    # sit outside the gate -- the property the deleted 14 was standing in for.
    assert set(GATE.privilege_gated_ops()) == {
        op.op for op in SCHEMA.OPS if op.status == SCHEMA.STATUS_DEFER_PRIVILEGE}
    ungated = [op.op for op in SCHEMA.OPS
               if op.op.split(".")[0] in SCHEMA.PRIVILEGED_NAMESPACES
               and op.status not in (SCHEMA.STATUS_DEFER_PRIVILEGE, SCHEMA.STATUS_DEFER_CHAIN)]
    assert ungated == []


def test_gate_and_dispatch_route_classes_agree():
    """Both views derive from the interface statuses; this pins them to each other."""
    from tools.dispatch import matrix as MX
    routed = {op for op in SCHEMA.OPS_BY_NAME if MX.route_for(op)["route"] == MX.ROUTE_DEFERRED_PRIVILEGE}
    assert routed == set(GATE.privilege_gated_ops())
