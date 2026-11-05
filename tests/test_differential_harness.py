"""P4/W6 differential harness: every scenario the work order names, plus invariants.

Diffs produce findings and OBSERVATION candidates - never a verdict, never an
authorization. Fixtures are fixtures: no firmware address is invented anywhere, and a
missing artifact is reported as ``ARTIFACT_MISSING`` instead of being synthesized.
"""
from __future__ import annotations

import hashlib
import json
import pathlib
import subprocess
import sys

import pytest

REPO_ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))

from tools.differential import candidates as CG  # noqa: E402
from tools.differential import compare as CP  # noqa: E402
from tools.differential import inventory as INV  # noqa: E402
from tools.differential import normalize as NORM  # noqa: E402
from tools.differential import schema as SC  # noqa: E402
from tools.profiles import loader as PL  # noqa: E402
from tools.profiles import schema as PS  # noqa: E402

FIX = REPO_ROOT / "tests" / "fixtures" / "differential"
PROFILES = REPO_ROOT / "tests" / "fixtures" / "profiles"
DOC = REPO_ROOT / "docs" / "P4-DIFFERENTIAL-HARNESS.md"
STAMP = "2026-10-05T00:00:00Z"

VOCAB_WORDS = ("vulnerability", "fixed", "exploitable", "bug", "primitive", "proven")


# --- helpers -------------------------------------------------------------------------
def run(kind: str, before, after, **kwargs) -> dict:
    report = CP.run_diff(kind, str(before), str(after), timestamp=STAMP, **kwargs)
    return CP.attach_candidates(report, CG.generate(report["findings"], report["inputs"]))


def classes(report: dict) -> dict:
    return report["summary"]["counts"]


def subjects(report: dict, class_: str) -> list[str]:
    return sorted(f["subject"] for f in report["findings"] if f["class"] == class_)


def profile_bytes() -> dict:
    return {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in PROFILES.glob("*.json")}


def write_profile(tmp_path: pathlib.Path, doc: dict, name: str) -> pathlib.Path:
    path = tmp_path / name
    path.write_text(json.dumps(doc, indent=1, sort_keys=True) + "\n", encoding="utf-8")
    return path


def load_fixture_profile(name: str) -> dict:
    return json.loads((PROFILES / name).read_text(encoding="utf-8"))


# --- 1..2 equality -------------------------------------------------------------------
def test_identical_profiles_produce_an_empty_diff():
    report = run("profiles", PROFILES / "concrete-fixture.json", PROFILES / "concrete-fixture.json")
    assert report["findings"] == []
    assert report["candidates"] == []
    assert report["summary"]["identical"] is True


def test_reordered_json_produces_an_empty_diff(tmp_path):
    doc = load_fixture_profile("fw1352-fixture.json")
    shuffled = {k: doc[k] for k in sorted(doc, reverse=True)}
    shuffled["target"] = {k: doc["target"][k] for k in sorted(doc["target"], reverse=True)}
    a = write_profile(tmp_path, doc, "a.json")
    b = write_profile(tmp_path, shuffled, "b.json")
    assert json.loads(a.read_text()) == json.loads(b.read_text())
    report = run("profiles", a, b)
    assert report["findings"] == [] and report["summary"]["identical"] is True


# --- 3..7 profile/operation classes --------------------------------------------------
def test_locator_change_is_moved_or_changed(tmp_path):
    doc = load_fixture_profile("concrete-fixture.json")
    original = doc["locators"]["kernel.read"]["locator"]["value"]
    doc["locators"]["kernel.read"]["locator"]["value"] = original + 0x1000
    doc["canonical_sha256"] = PS.canonical_profile_sha256(doc)
    report = run("profiles", PROFILES / "concrete-fixture.json", write_profile(tmp_path, doc, "moved.json"))
    assert subjects(report, SC.MOVED) == ["locators.kernel.read.locator.value"]
    assert report["findings"][0]["before"] == NORM.u64_hex(original)
    assert report["findings"][0]["after"] == NORM.u64_hex(original + 0x1000)

    doc2 = load_fixture_profile("concrete-fixture.json")
    doc2["locators"]["kernel.read"]["locator"]["value"] = original + 0x1000
    doc2["locators"]["kernel.read"]["section"] = ".data"
    doc2["canonical_sha256"] = PS.canonical_profile_sha256(doc2)
    report2 = run("profiles", PROFILES / "concrete-fixture.json", write_profile(tmp_path, doc2, "changed.json"))
    assert "locators.kernel.read.locator.value" in subjects(report2, SC.CHANGED)
    assert "locators.kernel.read.section" in subjects(report2, SC.CHANGED)


def test_expected_bytes_change_is_signature_changed(tmp_path):
    doc = load_fixture_profile("concrete-fixture.json")
    doc["locators"]["kernel.read"]["expected_bytes"] = {"offset": 0, "hex": "aa" * 8}
    doc["canonical_sha256"] = PS.canonical_profile_sha256(doc)
    report = run("profiles", PROFILES / "concrete-fixture.json", write_profile(tmp_path, doc, "sig.json"))
    assert "locators.kernel.read.expected_bytes" in subjects(report, SC.SIGNATURE_CHANGED)


def test_permissions_change_is_permission_changed(tmp_path):
    doc = load_fixture_profile("concrete-fixture.json")
    doc["locators"]["kernel.read"]["permissions"] = "rw-"
    doc["canonical_sha256"] = PS.canonical_profile_sha256(doc)
    report = run("profiles", PROFILES / "concrete-fixture.json", write_profile(tmp_path, doc, "perm.json"))
    assert subjects(report, SC.PERMISSION_CHANGED) == ["locators.kernel.read.permissions"]


def test_operation_added_and_removed():
    report = run("operations", FIX / "operation-inventory-before.json",
                 FIX / "operation-inventory-after.json")
    assert classes(report).get(SC.ADDED) == 1 and not classes(report).get(SC.REMOVED)
    assert subjects(report, SC.ADDED) == ["verify.samu.access"]

    reverse = run("operations", FIX / "operation-inventory-after.json",
                  FIX / "operation-inventory-before.json")
    assert subjects(reverse, SC.REMOVED) == ["verify.samu.access"]


def test_unresolved_becomes_resolved():
    report = run("operations", FIX / "operation-inventory-before.json",
                 FIX / "operation-inventory-after.json")
    assert subjects(report, SC.UNRESOLVED) == ["gpuvm.map.locator"]
    reverse = run("operations", FIX / "operation-inventory-after.json",
                  FIX / "operation-inventory-before.json")
    assert subjects(reverse, SC.UNRESOLVED) == ["gpuvm.map.locator"]


# --- 8..9 artifacts do not lie -------------------------------------------------------
def test_incompatible_architecture_is_incomparable(tmp_path):
    before = json.loads((FIX / "section-inventory-before.json").read_text())
    after = json.loads((FIX / "section-inventory-after.json").read_text())
    after["architecture"] = "aarch64"
    a = write_profile(tmp_path, before, "before.json")
    b = write_profile(tmp_path, after, "after.json")
    report = run("artifacts", a, b)
    assert classes(report) == {SC.INCOMPARABLE: 1}
    assert report["findings"][0]["confidence"] == SC.UNKNOWN
    assert any("architecture conflict" in note for note in report["summary"]["notes"])


def test_missing_artifact_is_reported_not_synthesized(tmp_path):
    report = run("artifacts", tmp_path / "fw900-kernel.img", tmp_path / "fw1352-kernel.img")
    assert classes(report) == {SC.ARTIFACT_MISSING: 1}
    assert report["candidates"] == []
    assert all(item["missing"] for item in report["inputs"])
    assert report["findings"][0]["confidence"] == SC.UNKNOWN


def test_artifact_section_phenomena_are_classified():
    report = run("artifacts", FIX / "section-inventory-before.json",
                 FIX / "section-inventory-after.json")
    assert classes(report) == {SC.PERMISSION_CHANGED: 1, SC.SIGNATURE_CHANGED: 2,
                               SC.CHANGED: 1, SC.MOVED: 1, SC.ADDED: 1, SC.REMOVED: 1}
    assert subjects(report, SC.MOVED) == [".text#file_offset"]
    assert all(f["confidence"] == SC.WEAK for f in report["findings"])  # fixture inputs


# --- 10 fail-closed ------------------------------------------------------------------
def test_altered_input_hash_is_rejected():
    with pytest.raises(CP.DifferentialRunError):
        CP.run_diff("profiles", str(PROFILES / "fw900-fixture.json"),
                    str(PROFILES / "fw1352-fixture.json"), timestamp=STAMP,
                    expect_hashes={"before": "0" * 64})
    with pytest.raises(CP.DifferentialRunError):
        CP.run_diff("artifacts", str(FIX / "section-inventory-before.json"),
                    str(FIX / "section-inventory-after.json"), timestamp=STAMP,
                    expect_hashes={"after": "1" * 64})
    # a declared hash for an input that does not exist is a refusal, not a report
    with pytest.raises(CP.DifferentialRunError):
        CP.run_diff("artifacts", str(FIX / "absent-image.img"),
                    str(FIX / "section-inventory-after.json"), timestamp=STAMP,
                    expect_hashes={"before": "2" * 64})


def test_tampered_profile_is_refused(tmp_path):
    doc = load_fixture_profile("fw1352-fixture.json")
    doc["target"]["firmware_version"] = "13.53"          # content changed, hash not restamped
    bad = write_profile(tmp_path, doc, "tampered.json")
    with pytest.raises(CP.DifferentialRunError):
        CP.run_diff("profiles", str(bad), str(PROFILES / "fw900-fixture.json"), timestamp=STAMP)


def test_unknown_normalization_version_is_refused():
    with pytest.raises(NORM.NormalizationError):
        NORM.check_normalization_version("ps4rf.normalize.v99")


def test_runtime_address_cannot_enter_a_comparison(tmp_path):
    doc = load_fixture_profile("concrete-fixture.json")
    doc["locators"]["kernel.read"]["runtime_address"] = 4096
    path = write_profile(tmp_path, doc, "addr.json")
    with pytest.raises(NORM.NormalizationError):
        NORM.normalize_document(json.loads(path.read_text()), path.name)
    with pytest.raises(NORM.NormalizationError):
        NORM.check_relative_locators(
            {"locators": {"x": {"locator": {"kind": "absolute", "value": 4096}}}}, "doc")
    # the same refusal applies to an artifact inventory the harness reads
    inv = json.loads((FIX / "section-inventory-before.json").read_text())
    inv["entries"][0]["absolute_address"] = 4096
    bad = write_profile(tmp_path, inv, "inv.json")
    with pytest.raises(CP.DifferentialRunError):
        CP.run_diff("artifacts", str(bad), str(FIX / "section-inventory-after.json"),
                    timestamp=STAMP)


# --- 11..13 determinism and non-interference -----------------------------------------
def test_same_semantic_inputs_produce_byte_identical_output(tmp_path):
    def cli(*args) -> bytes:
        return subprocess.run([sys.executable, "-m", "tools.differential.cli", *args],
                              cwd=REPO_ROOT, capture_output=True, check=True).stdout

    # a reordered copy of the same inventory must yield the identical report
    raw = json.loads((FIX / "section-inventory-before.json").read_text())
    shuffled = tmp_path / "shuffled.json"
    shuffled.write_text(json.dumps(raw, indent=3, sort_keys=False) + "\n", encoding="utf-8")
    baseline = cli("diff", "artifacts", str(FIX / "section-inventory-before.json"),
                   str(FIX / "section-inventory-after.json"), "--timestamp", STAMP)
    reordered = cli("diff", "artifacts", str(shuffled),
                    str(FIX / "section-inventory-after.json"), "--timestamp", STAMP)
    # the findings are identical; only the recorded input hash differs (different file bytes)
    key = lambda f: (f["class"], f["subject"], f["before"], f["after"])
    assert [key(f) for f in json.loads(reordered)["findings"]] == \
        [key(f) for f in json.loads(baseline)["findings"]]
    first = cli("diff", "artifacts", str(FIX / "section-inventory-before.json"),
                str(FIX / "section-inventory-after.json"), "--timestamp", STAMP)
    second = cli("diff", "artifacts", str(FIX / "section-inventory-before.json"),
                 str(FIX / "section-inventory-after.json"), "--timestamp", STAMP)
    assert first == second
    report = json.loads(first)
    assert report["output_sha256"] == json.loads(second)["output_sha256"]
    assert report["run_id"].startswith("W6-")


def test_report_hash_ignores_volatile_fields():
    report = run("profiles", PROFILES / "fw900-fixture.json", PROFILES / "fw1352-fixture.json")
    other = dict(report, timestamp="2030-01-01T00:00:00Z", run_id="W6-other")
    assert NORM.canonical_body_sha256(report, exclude=("timestamp", "run_id", "output_sha256")) == \
        NORM.canonical_body_sha256(other, exclude=("timestamp", "run_id", "output_sha256"))


def test_diff_does_not_modify_its_inputs():
    before = profile_bytes()
    fixture_bytes = {p.name: hashlib.sha256(p.read_bytes()).hexdigest()
                     for p in FIX.glob("*.json")}
    run("profiles", PROFILES / "fw900-fixture.json", PROFILES / "fw1352-fixture.json")
    run("operations", FIX / "operation-inventory-before.json", FIX / "operation-inventory-after.json")
    elf = REPO_ROOT / "native" / "build" / "ps4rfd.elf"
    if elf.exists():
        run("artifacts", elf, elf)
    assert profile_bytes() == before
    assert {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in FIX.glob("*.json")} == fixture_bytes


# --- 14..15 no escalation ------------------------------------------------------------
def test_candidate_cannot_satisfy_the_w4_gate():
    from tools.primitive_iface.gate import GateContext, REQ_BY_OP, gate_for

    report = run("profiles", PROFILES / "fw900-fixture.json", PROFILES / "fw1352-fixture.json")
    assert report["candidates"], "the fixture differential must produce a candidate"
    candidate = report["candidates"][0]
    assert candidate["impact"]["w4"] == "NONE"
    # feeding a candidate where the gate expects a profile binding satisfies nothing
    req = REQ_BY_OP["kernel.read"]
    ctx = GateContext(
        capability_records=({"name": req.capability, "namespace": req.namespace,
                             "verified_by_operation": req.verification_op,
                             "availability": "AVAILABLE", "assurance": req.min_assurance,
                             "context": req.allowed_contexts[0], "provider_type": "NATIVE",
                             "scope": "SESSION", "session_id": "SES-1", "boot_id": "BOOT-1"},),
        verification_records=({"run_id": "RUN-1", "operation": req.verification_op,
                               "outcome": "PASS", "capability": req.capability,
                               "provider_type": "NATIVE", "session_id": "SES-1",
                               "boot_id": "BOOT-1"},),
        evidence_refs=({"run_id": "RUN-1", "sha256": "b" * 64},),
        profile_binding=candidate, session_id="SES-1", boot_id="BOOT-1",
        provider_type="NATIVE", wired=True, approval={"approved": True, "state": "APPROVED"},
    )
    decision = gate_for("kernel.read", ctx)
    assert "PROFILE_UNBOUND" in decision.reasons
    assert decision.decision == "DEFERRED" and decision.executable is False
    # and the generator has no path to the gate at all
    source = (REPO_ROOT / "tools" / "differential" / "candidates.py").read_text(encoding="utf-8")
    assert "primitive_iface" not in source and "gate_for" not in source


def test_candidate_cannot_become_proven():
    report = run("profiles", PROFILES / "fw900-fixture.json", PROFILES / "fw1352-fixture.json")
    candidate = report["candidates"][0]
    assert candidate["status"] == "OBSERVATION"
    assert SC.CANDIDATE_STATUS == ("OBSERVATION",)
    assert SC.validate_candidate(dict(candidate, status="PROVEN"))
    assert SC.validate_candidate(dict(candidate, **{"kind": "exploit"}))
    body = json.dumps(report).lower()
    for word in VOCAB_WORDS:
        assert f'"{word}"' not in body.replace('"provenance"', '')
    assert "requires" in candidate and candidate["requires"]


# --- 16 firmware differential (fixtures) ---------------------------------------------
def test_fw900_vs_fw1352_differential_is_deterministic():
    first = run("profiles", PROFILES / "fw900-fixture.json", PROFILES / "fw1352-fixture.json")
    second = run("profiles", PROFILES / "fw900-fixture.json", PROFILES / "fw1352-fixture.json")
    assert json.dumps(first, sort_keys=True) == json.dumps(second, sort_keys=True)
    assert classes(first) == {SC.CHANGED: 1}
    assert subjects(first, SC.CHANGED) == ["target.firmware_version"]
    assert first["findings"][0]["before"] == "9.00" and first["findings"][0]["after"] == "13.52"
    assert first["findings"][0]["confidence"] == SC.WEAK  # fixture inputs


def test_operation_layer_matches_the_w4_matrix():
    inventory = CP.operations_from_profile(load_fixture_profile("concrete-fixture.json"))
    # W17E: the inventory covers exactly the privilege-gated operations (no literal count).
    assert set(inventory["operations"]) == set(CP.privilege_gated_ops())
    for op, entry in inventory["operations"].items():
        assert entry["profile_required"] == bool(CP.REQ_BY_OP[op].profile_required)
        assert entry["verification_requirement"] == CP.REQ_BY_OP[op].verification_op
    report = run("operations", PROFILES / "concrete-fixture.json", PROFILES / "fw900-fixture.json")
    from tools.primitive_iface import schema as _S
    # W17F: derive the deferred-privilege class from the authoritative status set (no literal).
    _deferred_ops = {_o.op for _o in _S.OPS if _o.status == _S.STATUS_DEFER_PRIVILEGE}
    assert classes(report) == {SC.UNRESOLVED: len(_deferred_ops)}  # resolved fixture facts vs UNRESOLVED skeleton


# --- external analysis ingestion path ------------------------------------------------
def test_external_analysis_findings_are_capped_at_weak():
    report = run("artifacts", FIX / "section-inventory-before.json",
                 FIX / "section-inventory-after.json",
                 external=(json.loads((FIX / "external-ghidra-before.json").read_text()),
                           json.loads((FIX / "external-rizin-after.json").read_text())))
    external = [f for f in report["findings"] if f["layer"] == SC.LAYER_EXTERNAL]
    assert external and all(f["confidence"] == SC.WEAK for f in external)
    assert any("adapter" in note for note in report["summary"]["notes"])


def test_external_analysis_without_matching_provenance_is_refused():
    analysis = json.loads((FIX / "external-ghidra-before.json").read_text())
    analysis["artifact_sha256"] = "f" * 64
    with pytest.raises(CP.DifferentialRunError):
        run("artifacts", FIX / "section-inventory-before.json",
            FIX / "section-inventory-after.json", external=(analysis, analysis))
    broken = json.loads((FIX / "external-rizin-after.json").read_text())
    broken.pop("artifact_sha256")
    assert CP.validate_external_analysis(broken)


# --- schema, docs, fixtures ----------------------------------------------------------
def test_report_and_candidates_validate_against_the_schema():
    report = run("artifacts", FIX / "section-inventory-before.json",
                 FIX / "section-inventory-after.json")
    assert SC.validate_report(report) == []
    for candidate in report["candidates"]:
        assert SC.validate_candidate(candidate) == []
    assert report["schema"] == SC.REPORT_SCHEMA
    assert report["normalization_version"] == NORM.NORM_VERSION
    assert report["config_sha256"] == NORM.DEFAULT_CONFIG.sha256
    assert len(report["inputs"]) == 2 and all(i["sha256"] for i in report["inputs"])


def test_vocabulary_has_no_verdict_states():
    vocabulary = SC.vocabulary()
    listed = json.dumps({k: v for k, v in vocabulary.items() if k != "forbidden_words"}).upper()
    for word in ("VULNERABILITY", "FIXED", "EXPLOITABLE", "BUG", "PRIMITIVE", "PROVEN"):
        assert word not in listed, word
    assert set(vocabulary["forbidden_words"]) == {"PROVEN", "BUG", "VULNERABILITY",
                                                  "EXPLOITABLE", "PRIMITIVE", "FIXED", "VERIFIED"}
    assert "EXPLOITABLE" not in SC.CLASSES and "BUG" not in SC.CANDIDATE_KINDS


def test_fixtures_match_their_generator():
    import importlib.util

    spec = importlib.util.spec_from_file_location("w6_gen", FIX / "gen_fixtures.py")
    assert spec is not None and spec.loader is not None
    gen = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(gen)
    for name, document in gen.build().items():
        assert (FIX / name).read_text(encoding="utf-8") == gen.render(document), name


def test_doc_and_modules_agree():
    text = DOC.read_text(encoding="utf-8")
    for name in SC.CLASSES + SC.CONFIDENCES:
        assert name in text, name
    lowered = text.lower()
    for phrase in ("analysis, not authorization", "observation",
                   "locator + runtime base" if False else "file_offset", "weak",
                   "artifact_missing", "no adapter is implemented"):
        assert phrase in lowered, phrase


def test_harness_imports_no_network_or_subprocess():
    for path in sorted((REPO_ROOT / "tools" / "differential").glob("*.py")):
        source = path.read_text(encoding="utf-8")
        for banned in ("import socket", "import subprocess", "urllib", "requests",
                       "paramiko", "orbisprobe.live"):
            assert banned not in source, f"{path.name}: {banned}"


# --- 16 (work order) D18 regression --------------------------------------------------
def test_d18_profile_schema_drift_entry_is_consistent():
    """The documented drift entry must match reality, and the manifest must be frozen."""
    import re

    drift = (REPO_ROOT / "FREEZE-DRIFT.md").read_text(encoding="utf-8")
    block = json.loads(re.search(r"```json\n(.*?)\n```", drift, re.S).group(1))
    entries = {e["file"]: e for e in block["entries"]}
    assert "schemas/profile.schema.json" in entries
    actual = hashlib.sha256((REPO_ROOT / "schemas" / "profile.schema.json").read_bytes()).hexdigest()
    assert entries["schemas/profile.schema.json"]["new_sha256"] == actual
    manifest = hashlib.sha256((REPO_ROOT / "SHA256SUMS").read_bytes()).hexdigest()
    assert manifest == block["manifest"]["manifest_sha256"]
    assert entries["schemas/profile.schema.json"]["phase"].startswith("W")
    # every manifest file that is not documented must still match the frozen manifest
    documented = set(entries)
    for line in (REPO_ROOT / "SHA256SUMS").read_text(encoding="utf-8").splitlines():
        digest, _, name = line.partition("  ")
        if not name or name in documented:
            continue
        path = REPO_ROOT / name
        if path.exists():
            assert hashlib.sha256(path.read_bytes()).hexdigest() == digest, name
