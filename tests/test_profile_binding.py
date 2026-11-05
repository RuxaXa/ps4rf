"""P4/W5 profile binding: every scenario the work order names, plus the invariants.

All scenarios end fail-closed: a profile match never makes an operation executable,
never removes ``NOT_WIRED``, never legitimises a mock provider and never claims runtime
reachability. Fixtures are fixtures: no real firmware address appears anywhere.
"""
from __future__ import annotations

import hashlib
import json
import pathlib
import re
import sys

import pytest

REPO_ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))

from tools.primitive_iface.gate import (  # noqa: E402
    GateContext, NOT_WIRED, REQ_BY_OP, privilege_gated_ops,
)
from tools.profiles import binding as B  # noqa: E402
from tools.profiles import loader as L  # noqa: E402
from tools.profiles import schema as S  # noqa: E402
from tools.profiles import w4_adapter as A  # noqa: E402

FIXTURES = REPO_ROOT / "tests" / "fixtures" / "profiles"
DOC = REPO_ROOT / "docs" / "P4-PROFILE-BINDING.md"
SCHEMA_JSON = REPO_ROOT / "schemas" / "profile.schema.json"

BOOT_A = "BOOT-0123456789ABCDEF"
BOOT_B = "BOOT-FEDCBA9876543210"
SID = "SES-0123456789ABCDEF"
RUN = "RUN-" + "a" * 32
PROVIDER = "ps4rfd-native"
SAMPLE = "kernel.read"


# --- helpers -------------------------------------------------------------------------
def concrete_profile(**overrides) -> dict:
    """A structurally complete, clearly fixture-marked profile (no real addresses)."""
    doc = json.loads((FIXTURES / "concrete-fixture.json").read_text(encoding="utf-8"))
    doc = json.loads(json.dumps(doc))
    doc.update(overrides)
    return doc


def with_evidence_provenance(doc: dict, *, source: str) -> dict:
    """Mark every fact as evidence-backed by a real file reference (test only).

    The referenced artifact is the pinned fixture file itself: the sha256 is real and
    verifiable. Real profiles must reference on-site capture artifacts.
    """
    sha = hashlib.sha256((FIXTURES / "concrete-fixture.json").read_bytes()).hexdigest()
    out = json.loads(json.dumps(doc))
    for loc in out["locators"].values():
        loc["provenance"] = {"kind": "evidence", "source": source, "sha256": sha}
        loc["confidence"] = "OBSERVED"
    out["fixture"] = False
    out["canonical_sha256"] = S.canonical_profile_sha256(out)
    return out


def rebind(doc: dict) -> dict:
    """Recompute the declared hash after a mutation (so hash drift is explicit)."""
    out = json.loads(json.dumps(doc))
    out["canonical_sha256"] = S.canonical_profile_sha256(out)
    return out


def satisfied_gate_kwargs(op: str, profile: dict) -> dict:
    """Everything the W4 gate needs apart from the profile reason and wiring."""
    req = REQ_BY_OP[op]
    cap = {
        "name": req.capability, "namespace": req.namespace,
        "verified_by_operation": req.verification_op, "availability": "AVAILABLE",
        "assurance": req.min_assurance, "context": req.allowed_contexts[0],
        "provider": PROVIDER, "provider_type": "NATIVE", "scope": "SESSION",
        "session_id": SID, "boot_id": BOOT_A,
    }
    verification = {
        "run_id": RUN, "operation": req.verification_op, "outcome": "PASS",
        "capability": req.capability, "provider": PROVIDER, "provider_type": "NATIVE",
        "session_id": SID, "boot_id": BOOT_A,
        "profile_sha256": S.canonical_profile_sha256(profile),
    }
    return dict(
        capability_records=(cap,), verification_records=(verification,),
        evidence_refs=({"run_id": RUN, "sha256": "b" * 64},),
        session_id=SID, boot_id=BOOT_A, session_state="ACTIVE",
        provider=PROVIDER, provider_type="NATIVE", wired=False,
        approval={"approved": True, "state": "APPROVED", "id": "CMR-1"},
    )


# --- 1..4 identity, hash and boot -----------------------------------------------------
def test_exact_profile_match():
    doc = concrete_profile()
    boot = B.BootBinding.from_profile(doc, BOOT_A)
    verdict = S.profile_preconditions(
        doc, boot_binding=boot, current_boot_id=BOOT_A,
        expected_target={"platform": "ORBIS", "firmware_version": "13.52",
                         "firmware_build_id": "FIXTURE-BUILD", "architecture": "x86-64"},
    )
    assert verdict.codes == (S.PROFILE_MATCH,)
    assert verdict.matched
    assert verdict.evidence_backed is False  # fixture facts: match, but not evidenced
    assert verdict.profile_sha256 == S.canonical_profile_sha256(doc)


def test_wrong_firmware_is_a_profile_mismatch():
    doc = concrete_profile()
    boot = B.BootBinding.from_profile(doc, BOOT_A)
    verdict = S.profile_preconditions(doc, boot_binding=boot, current_boot_id=BOOT_A,
                                      expected_target={"firmware_version": "9.00"})
    assert verdict.codes == (S.PROFILE_MISMATCH,)
    assert not verdict.matched


def test_wrong_profile_hash_is_rejected():
    doc = concrete_profile()
    doc["canonical_sha256"] = "0" * 64
    assert S.validate_profile(doc)  # refused by the validator
    verdict = S.profile_preconditions(doc)
    assert S.PROFILE_MISMATCH in verdict.codes
    # the loader refuses the same document
    path = FIXTURES / "concrete-fixture.json"
    tampered = json.loads(path.read_text(encoding="utf-8"))
    tampered["target"]["firmware_version"] = "13.53"  # content changed, hash not re-stamped
    (FIXTURES / "_tampered.json").write_text(json.dumps(tampered), encoding="utf-8")
    try:
        with pytest.raises(L.ProfileLoadError):
            L.load_profile(FIXTURES / "_tampered.json")
    finally:
        (FIXTURES / "_tampered.json").unlink()


def test_wrong_boot_is_a_boot_binding_mismatch():
    doc = concrete_profile()
    boot = B.BootBinding.from_profile(doc, BOOT_A)
    assert boot.valid_for(BOOT_A, S.canonical_profile_sha256(doc))
    assert not boot.valid_for(BOOT_B, S.canonical_profile_sha256(doc))
    verdict = S.profile_preconditions(doc, boot_binding=boot, current_boot_id=BOOT_B)
    assert S.BOOT_BINDING_MISMATCH in verdict.codes


# --- 5..9 locator facts ---------------------------------------------------------------
def test_missing_locator():
    doc = concrete_profile()
    del doc["locators"][SAMPLE]
    boot = B.BootBinding.from_profile(doc, BOOT_A)
    verdict = S.profile_preconditions(
        doc, boot_binding=boot, current_boot_id=BOOT_A,
        requests=(S.LocatorRequest(SAMPLE),))
    assert S.LOCATOR_MISSING in verdict.codes


def test_wrong_module():
    doc = concrete_profile()
    boot = B.BootBinding.from_profile(doc, BOOT_A)
    verdict = S.profile_preconditions(
        doc, boot_binding=boot, current_boot_id=BOOT_A,
        requests=(S.LocatorRequest(SAMPLE, module="userland"),))
    assert S.LOCATOR_MISMATCH in verdict.codes
    assert "module" in " ".join(verdict.details)


def test_wrong_section():
    doc = concrete_profile()
    boot = B.BootBinding.from_profile(doc, BOOT_A)
    verdict = S.profile_preconditions(
        doc, boot_binding=boot, current_boot_id=BOOT_A,
        requests=(S.LocatorRequest(SAMPLE, section=".data"),))
    assert S.LOCATOR_MISMATCH in verdict.codes
    assert "section" in " ".join(verdict.details)


def test_wrong_permissions():
    doc = concrete_profile()
    boot = B.BootBinding.from_profile(doc, BOOT_A)
    verdict = S.profile_preconditions(
        doc, boot_binding=boot, current_boot_id=BOOT_A,
        requests=(S.LocatorRequest(SAMPLE, permissions="rw-"),))
    assert S.LOCATOR_MISMATCH in verdict.codes
    assert "permissions" in " ".join(verdict.details)


def test_signature_mismatch_refuses_the_binding():
    doc = concrete_profile()
    doc["locators"][SAMPLE]["expected_bytes"] = {"offset": 0, "hex": "aa" * 8}
    doc = rebind(doc)
    boot = B.BootBinding.from_profile(doc, BOOT_A)
    plan = {"mode": "read", "read_size": 16, "operation": SAMPLE, "module": "kernel",
            "locator_kind": "rva", "section": ".text", "permissions": "r-x"}
    assert B.validate_probe_plan(plan) == []
    with pytest.raises(B.BindingError) as excinfo:
        B.apply_probe_result(plan, {"runtime_base": 4096, "bytes_hex": "bb" * 8,
                                    "section_ok": True}, boot, doc, BOOT_A)
    assert S.LOCATOR_MISMATCH in excinfo.value.codes
    # matching bytes produce a complete runtime binding
    result = B.apply_probe_result(plan, {"runtime_base": 4096, "bytes_hex": "aa" * 8,
                                         "section_ok": True}, boot, doc, BOOT_A)
    assert result.probe_complete and result.address_for(SAMPLE) == 4096 + doc["locators"][SAMPLE]["locator"]["value"]


# --- 10..12 boot vs facts, hash sensitivity -------------------------------------------
def test_stale_binding_after_reboot():
    doc = concrete_profile()
    boot = B.BootBinding.from_profile(doc, BOOT_A)
    runtime = B.create_runtime_binding(doc, boot, {"kernel": 4096}, BOOT_A,
                                       operations=(SAMPLE,))
    assert runtime.boot_id == BOOT_A
    # reboot: facts stay, the old runtime binding does not apply any more
    with pytest.raises(B.BindingError) as excinfo:
        B.create_runtime_binding(doc, boot, {"kernel": 4096}, BOOT_B, operations=(SAMPLE,))
    assert S.BOOT_BINDING_MISMATCH in excinfo.value.codes
    assert runtime.boot_id != BOOT_B


def test_same_facts_new_boot_needs_a_new_runtime_binding():
    doc = concrete_profile()
    sha_before = S.canonical_profile_sha256(doc)
    boot_a = B.BootBinding.from_profile(doc, BOOT_A)
    boot_b = B.BootBinding.from_profile(doc, BOOT_B)
    assert S.canonical_profile_sha256(doc) == sha_before  # facts persist
    assert boot_a.profile_sha256 == boot_b.profile_sha256 == sha_before
    assert boot_a.boot_id != boot_b.boot_id
    fresh = B.create_runtime_binding(doc, boot_b, {"kernel": 4096}, BOOT_B, operations=(SAMPLE,))
    assert fresh.boot_id == BOOT_B and fresh.address_for(SAMPLE) is not None
    with pytest.raises(B.BindingError):
        B.create_runtime_binding(doc, boot_a, {"kernel": 4096}, BOOT_B, operations=(SAMPLE,))


def test_locator_change_changes_the_profile_hash():
    base = concrete_profile()
    base_sha = S.canonical_profile_sha256(base)
    mutations = {
        "firmware identity": lambda d: d["target"].update({"firmware_version": "13.53"}),
        "locator": lambda d: d["locators"][SAMPLE]["locator"].update({"value": 12345}),
        "expected bytes": lambda d: d["locators"][SAMPLE].update(
            {"expected_bytes": {"offset": 0, "hex": "cc" * 4}}),
        "operation mapping": lambda d: d["operation_policy"][SAMPLE].update(
            {"profile_fields": ["addr"]}),
        "section/permission": lambda d: (d["locators"][SAMPLE].update({"section": ".data"}),
                                         d["locators"][SAMPLE].update({"permissions": "rw-"})),
    }
    for label, mutate in mutations.items():
        changed = json.loads(json.dumps(base))
        mutate(changed)
        assert S.canonical_profile_sha256(changed) != base_sha, label
    # and the hash is stable for identical content
    assert S.canonical_profile_sha256(json.loads(json.dumps(base))) == base_sha


# --- 13..15 the W4 seam ---------------------------------------------------------------
def test_profile_match_alone_stays_not_wired():
    doc = concrete_profile()
    boot = B.BootBinding.from_profile(doc, BOOT_A)
    decision, verdict = A.evaluate(SAMPLE, doc=doc, boot_binding=boot, current_boot_id=BOOT_A,
                                   **satisfied_gate_kwargs(SAMPLE, doc))
    assert verdict.matched and not verdict.evidence_backed
    assert decision.decision == "DEFERRED"
    assert A.W4_PROFILE_REASON in decision.reasons and NOT_WIRED in decision.reasons

    evidenced = with_evidence_provenance(doc, source="tests/fixtures/profiles/concrete-fixture.json")
    boot_e = B.BootBinding.from_profile(evidenced, BOOT_A)
    decision_e, verdict_e = A.evaluate(SAMPLE, doc=evidenced, boot_binding=boot_e,
                                       current_boot_id=BOOT_A,
                                       **satisfied_gate_kwargs(SAMPLE, evidenced))
    assert verdict_e.matched and verdict_e.evidence_backed
    assert A.W4_PROFILE_REASON not in decision_e.reasons        # profile reason satisfied
    assert decision_e.reasons == (NOT_WIRED,)                   # everything else still defers
    for decision_ in (decision, decision_e):
        assert decision_.executable is False
        assert decision_.wire_code == "OPERATION_DEFERRED"
        assert decision_.decision != "ELIGIBLE"


def test_mock_capability_with_a_perfect_profile_stays_deferred():
    doc = with_evidence_provenance(concrete_profile(), source="mock-regression")
    boot = B.BootBinding.from_profile(doc, BOOT_A)
    kwargs = satisfied_gate_kwargs(SAMPLE, doc)
    cap = dict(kwargs["capability_records"][0], provider_type="MOCK", assurance="PROVEN")
    kwargs["capability_records"] = (cap,)
    kwargs["verification_records"] = (dict(kwargs["verification_records"][0],
                                           provider_type="MOCK"),)
    decision, verdict = A.evaluate(SAMPLE, doc=doc, boot_binding=boot, current_boot_id=BOOT_A,
                                   **kwargs)
    assert verdict.matched and verdict.evidence_backed
    assert decision.decision == "DEFERRED"
    assert "PROVIDER_NOT_ALLOWED" in decision.reasons
    assert decision.wire_code == "OPERATION_DEFERRED"


def test_evidence_with_another_profile_hash_is_rejected():
    doc = concrete_profile()
    other = "d" * 64
    record = {"run_id": RUN, "operation": "verify.kernel.read", "profile_sha256": other,
              "outcome": "PASS"}
    assert S.check_evidence_profile_hash(record, S.canonical_profile_sha256(doc)) is False
    assert S.check_evidence_profile_hash(dict(record, profile_sha256=S.canonical_profile_sha256(doc)),
                                         S.canonical_profile_sha256(doc)) is True
    boot = B.BootBinding.from_profile(doc, BOOT_A)
    verdict = S.profile_preconditions(doc, boot_binding=boot, current_boot_id=BOOT_A,
                                      evidence_profile_sha256=other)
    assert S.PROFILE_MISMATCH in verdict.codes


# --- 16 the operation mapping ---------------------------------------------------------
def test_every_gated_operation_has_an_explicit_profile_policy():
    gated = privilege_gated_ops()
    matrix = S.operation_matrix()
    assert sorted(row["op"] for row in matrix) == sorted(gated)
    for row in matrix:
        assert isinstance(row["profile_required"], bool)
        assert row["w4_reason"]
        if row["profile_required"]:
            assert row["profile_fields"] and row["module"] and row["locator_kind"]
        else:
            assert row["module"] is None and row["locator_kind"] is None
    # parity with the frozen W4 matrix
    for row in matrix:
        assert row["profile_required"] == bool(REQ_BY_OP[row["op"]].profile_required)
        assert list(REQ_BY_OP[row["op"]].profile_fields) == row["profile_fields"]
    # every shipped fixture declares all fourteen explicitly
    for name in ("fw1352-fixture.json", "fw900-fixture.json", "concrete-fixture.json"):
        doc = json.loads((FIXTURES / name).read_text(encoding="utf-8"))
        assert sorted(doc["operation_policy"]) == sorted(gated), name
    # an incomplete policy is refused (no implicit defaults)
    incomplete = concrete_profile()
    del incomplete["operation_policy"][SAMPLE]
    incomplete = rebind(incomplete)
    assert any("no explicit entry" in err for err in S.validate_profile(incomplete))


# --- invariants and artifacts ---------------------------------------------------------
def test_profiles_cannot_carry_a_runtime_address():
    for key in ("runtime_address", "absolute_address", "slide", "runtime_base"):
        doc = concrete_profile()
        doc[key] = 4096
        assert any("unknown field" in err for err in S.validate_profile(doc)), key
        loc = concrete_profile()
        loc["locators"][SAMPLE][key] = 4096
        assert any("unknown field" in err for err in S.validate_profile(loc)), key


def test_probe_plans_are_read_only_and_bounded():
    plan = {"mode": "write", "writes": [{"address": 0, "hex": "00"}], "read_size": 8,
            "operation": SAMPLE, "module": "kernel", "locator_kind": "rva",
            "section": ".text", "permissions": "r-x"}
    errors = B.validate_probe_plan(plan)
    assert any("read" in e for e in errors) and any("writes" in e for e in errors)
    oversized = dict(plan, mode="read", writes=[])
    oversized["read_size"] = B.MAX_PROBE_BYTES + 1
    assert any("bound" in e for e in B.validate_probe_plan(oversized))
    absolute = dict(plan, mode="read", writes=[], locator_kind="absolute")
    assert any("rva" in e for e in B.validate_probe_plan(absolute))


def test_evidence_provenance_is_required_for_a_trusted_confidence():
    doc = concrete_profile()
    doc["locators"][SAMPLE]["confidence"] = "OBSERVED"   # still fixture provenance
    assert any("evidence provenance" in err for err in S.validate_profile(rebind(doc)))
    doc2 = concrete_profile()
    doc2["locators"][SAMPLE]["provenance"] = {"kind": "evidence", "source": None,
                                              "sha256": None}
    assert any("source" in err or "sha256" in err for err in S.validate_profile(rebind(doc2)))


def test_unresolved_profile_keeps_the_gate_fail_closed():
    for name in ("fw1352-fixture.json", "fw900-fixture.json"):
        doc = json.loads((FIXTURES / name).read_text(encoding="utf-8"))
        assert doc["fixture"] is True
        assert S.unresolved_facts(doc)
        boot = B.BootBinding.from_profile(doc, BOOT_A)
        verdict = S.profile_preconditions(doc, boot_binding=boot, current_boot_id=BOOT_A)
        assert S.PROFILE_UNVERIFIED in verdict.codes and not verdict.matched
        decision, _ = A.evaluate(SAMPLE, doc=doc, boot_binding=boot, current_boot_id=BOOT_A)
        assert A.W4_PROFILE_REASON in decision.reasons and NOT_WIRED in decision.reasons
        assert decision.wire_code == "OPERATION_DEFERRED"


def test_no_profile_at_all_is_a_binding_missing():
    verdict = S.profile_preconditions(None)
    assert verdict.codes == (S.PROFILE_BINDING_MISSING,)
    decision, _ = A.evaluate(SAMPLE, doc=None)
    assert A.W4_PROFILE_REASON in decision.reasons


def test_every_profile_field_has_a_value_domain():
    coverage = S.domain_coverage()
    assert coverage["missing"] == []
    # W17F: semantic parity against the authoritative field registry (no historical count).
    from tools.profiles import schema as _PROFILE_SCHEMA
    _fields = list(coverage["fields"])
    assert len(_fields) == len(set(_fields)), f'duplicate profile fields: {sorted({f for f in _fields if _fields.count(f) > 1})}'
    # W17F: coverage["fields"] is the OPERATION-authority field set (fields referenced by
    # operation_policy), not the full domain registry. The property to protect is inclusion:
    # every referenced field must have a value domain. FIELD_DOMAINS legitimately also holds
    # locator/profile-validation consumers (rva, runtime_va), so no reverse equality is required.
    _domains = set(_PROFILE_SCHEMA.FIELD_DOMAINS)
    _missing = set(_fields) - _domains
    assert not _missing, f'profile fields without a value domain: {sorted(_missing)}'
    assert coverage["resolved"] == ["addr", "expected", "expected_sha256", "size", "va"]
    assert coverage["unresolved"]  # no verified domain yet -> fail closed
    for unresolved in coverage["unresolved"]:
        errors = S.validate_field_value(unresolved, 1)
        assert any("unresolved" in err for err in errors), unresolved
    assert S.validate_field_value("addr", 4096) == []
    assert S.validate_field_value("addr", 0)
    assert S.validate_field_value("size", 16) == []
    assert S.validate_field_value("expected_sha256", "a" * 64) == []
    assert S.validate_field_value("expected_sha256", "nope")


def test_adapter_mapping_is_total():
    for code in S.PRECONDITION_CODES:
        assert code in A.PROFILE_CODE_TO_W4_REASON
        assert A.PROFILE_CODE_TO_W4_REASON[code] == A.W4_PROFILE_REASON
    assert A.PROFILE_CODE_TO_W4_REASON[S.PROFILE_MATCH] is None
    assert A.HANDOFF["w5_never_provides"]


def test_fixtures_match_their_generator():
    import importlib.util

    spec = importlib.util.spec_from_file_location("w5_gen", FIXTURES / "gen_profiles.py")
    assert spec is not None and spec.loader is not None
    gen = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(gen)
    for name, document in gen.build().items():
        assert (FIXTURES / name).read_text(encoding="utf-8") == gen.render(document), name
    assert (FIXTURES / "operation-matrix.json").read_text(encoding="utf-8") == gen.render_matrix()


def test_doc_and_module_agree():
    text = DOC.read_text(encoding="utf-8")
    for code in S.PRECONDITION_CODES + (S.PROFILE_MATCH,):
        assert code in text, code
    for phrase in ("runtime address = profile locator (relative) + runtime base of the module",
                   "executable = False, wire = OPERATION_DEFERRED", "require_evidence_backed"):
        assert phrase in text, phrase
    assert "PROFILE_UNBOUND" in text and "NOT_WIRED" in text


def test_json_schema_matches_the_python_allowlists():
    js = json.loads(SCHEMA_JSON.read_text(encoding="utf-8"))
    assert js["additionalProperties"] is False
    assert sorted(js["properties"]) == sorted(S.TOP_KEYS)
    assert sorted(js["required"]) == sorted(set(S.TOP_KEYS) - {"canonical_sha256", "notes"})
    target = js["properties"]["target"]
    assert sorted(target["properties"]) == sorted(S.TARGET_KEYS)
    assert sorted(target["required"]) == sorted(S.TARGET_KEYS)
    locator = js["properties"]["locators"]["additionalProperties"]
    assert sorted(locator["properties"]) == sorted(S.LOCATOR_KEYS + S.LOCATOR_OPTIONAL_KEYS)
    assert sorted(locator["required"]) == sorted(S.LOCATOR_KEYS), (
        "the W10 optional keys stay optional so the W5 fixtures keep validating")
    assert sorted(locator["properties"]["locator"]["properties"]) == sorted(S.LOCATOR_INNER_KEYS)
    assert locator["properties"]["permissions"]["enum"] == list(S.PERMISSIONS) + [S.UNRESOLVED]
    assert locator["properties"]["confidence"]["enum"] == list(S.CONFIDENCE)
    provenance = locator["properties"]["provenance"]
    assert sorted(provenance["properties"]) == sorted(S.PROVENANCE_KEYS)
    eb = locator["properties"]["expected_bytes"]["oneOf"][1]
    assert sorted(eb["properties"]) == sorted(S.EXPECTED_BYTES_KEYS)
    policy = js["properties"]["operation_policy"]["additionalProperties"]
    assert sorted(policy["properties"]) == sorted(S.POLICY_KEYS)
    modules = js["properties"]["modules"]["additionalProperties"]
    assert sorted(modules["properties"]) == sorted(S.MODULE_KEYS)


def test_w5_artifacts_contain_no_real_looking_addresses():
    pattern = re.compile(r"0x[0-9a-fA-F]{6,}")
    targets = sorted((REPO_ROOT / "tools" / "profiles").glob("*.py"))
    targets += [DOC, FIXTURES / "operation-matrix.json"]
    targets += sorted(FIXTURES.glob("*-fixture.json"))
    for path in targets:
        hits = pattern.findall(path.read_text(encoding="utf-8"))
        assert not hits, f"{path.name}: {hits}"


def test_loader_accepts_the_shipped_fixtures():
    for name in ("fw1352-fixture.json", "fw900-fixture.json", "concrete-fixture.json"):
        doc = L.load_profile(FIXTURES / name)
        summary = L.profile_summary(doc)
        assert summary["canonical_sha256"] == doc["canonical_sha256"]
        assert summary["fixture"] is True
        assert summary["gated_operations"] == len(privilege_gated_ops())


def test_boot_binding_requires_a_profile_hash_and_a_boot_id():
    doc = concrete_profile()
    with pytest.raises(B.BindingError):
        B.BootBinding.from_profile(doc, "")
    foreign = B.BootBinding(boot_id=BOOT_A, profile_sha256="e" * 64)
    with pytest.raises(B.BindingError) as excinfo:
        B.create_runtime_binding(doc, foreign, {"kernel": 4096}, BOOT_A, operations=(SAMPLE,))
    assert S.BOOT_BINDING_MISMATCH in excinfo.value.codes
