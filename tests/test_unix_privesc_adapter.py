"""Platform-independent local enumeration adapter tests (offline, pure data).

Everything runs offline: the adapter reads synthetic collector documents and
classifies them; nothing is executed on the host or on any target/console. The
mock generator (``tools/recon/unix_privesc/mock/collector_mock.py``) is inert
and deterministic; pinned fixture hashes come from
``tests/fixtures/unix_privesc/README.md``.

Run from the repo root:

    .venv/bin/python -m pytest -q tests/test_unix_privesc_adapter.py
"""

from __future__ import annotations

import copy
import hashlib
import json
import re
from collections import Counter
from pathlib import Path

import pytest
from pydantic import ValidationError

from tools.recon.unix_privesc.adapter import (SCHEMA_ID, UnixPrivescAdapter,
                                              UnixPrivescConfigError,
                                              UnixPrivescEvidenceError,
                                              UnixPrivescHashMismatch,
                                              UnixPrivescSchemaError,
                                              UnixPrivescStateError,
                                              classify_document,
                                              detect_platform, verify_report)
from tools.recon.unix_privesc.mock.collector_mock import (VARIANTS,
                                                          build_document,
                                                          dump_document, main)
from tools.recon.unix_privesc.models import (CATEGORY_SEMANTICS,
                                             PS4_OWNERSHIP_OWNER, PS4_SCOPE_NOTE,
                                             Category, CategoryEntry,
                                             CategoryStatus, CollectorDocument,
                                             DocumentBinding, ObservationClass,
                                             PlatformInterpretation,
                                             PlatformSemantics,
                                             PlatformSpecificStatus,
                                             TargetPlatform)

REPO = Path(__file__).resolve().parents[1]
FIXTURES = Path(__file__).parent / "fixtures" / "unix_privesc"
LINUX_FIXTURE = FIXTURES / "collector-linux.json"
ORBIS_FIXTURE = FIXTURES / "collector-freebsd-orbisos.json"

LINUX_SHA = "fcbc305efc0cca7382b13c9d2c91635036604a3e456b6a4c57c14d62a0e8f95b"
ORBIS_SHA = "392384f265fd5704097bb1d8a087ae29d3300a75753ddef3c6bc8622173845c8"


@pytest.fixture()
def adapter() -> UnixPrivescAdapter:
    return UnixPrivescAdapter()


def _load(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def _write_document(tmp_path: Path, document: dict, name: str = "doc.json") -> Path:
    path = tmp_path / name
    path.write_text(dump_document(document), encoding="utf-8")
    return path


# ------------------------------------------------------------- platform detection
def test_platform_detection_three_cases(adapter: UnixPrivescAdapter):
    assert detect_platform("Linux") is TargetPlatform.LINUX
    assert detect_platform("GNU/Linux 6.8") is TargetPlatform.LINUX
    assert detect_platform("OrbisOS (FreeBSD 12.1, synthetic)") is TargetPlatform.FREEBSD_ORBISOS
    assert detect_platform("FreeBSD") is TargetPlatform.FREEBSD_ORBISOS
    assert detect_platform("mystery-os") is TargetPlatform.UNKNOWN
    assert detect_platform("") is TargetPlatform.UNKNOWN
    # detection is exercised end-to-end on the two committed documents
    assert adapter.classify(LINUX_FIXTURE).platform is TargetPlatform.LINUX
    assert adapter.classify(ORBIS_FIXTURE).platform is TargetPlatform.FREEBSD_ORBISOS


# ---------------------------------------------------------- fixture determinism
def test_mock_regenerates_fixtures_byte_identically():
    for variant, fixture, pinned in (("linux", LINUX_FIXTURE, LINUX_SHA),
                                     ("freebsd_orbisos", ORBIS_FIXTURE, ORBIS_SHA)):
        first = dump_document(build_document(variant))
        second = dump_document(build_document(variant))
        assert first == second, "mock output must be deterministic"
        assert first == fixture.read_text(encoding="utf-8")
        assert hashlib.sha256(first.encode("utf-8")).hexdigest() == pinned


def test_fixture_readme_pins_match():
    readme = (FIXTURES / "README.md").read_text(encoding="utf-8")
    assert LINUX_SHA in readme
    assert ORBIS_SHA in readme


# ------------------------------------------------------------------- Linux target
def test_linux_document_classifies(adapter: UnixPrivescAdapter):
    report = adapter.classify(LINUX_FIXTURE, expected_sha256=LINUX_SHA)
    assert report.schema_id == SCHEMA_ID
    assert report.platform is TargetPlatform.LINUX
    assert report.platform_hint == "Linux"
    assert report.platform_interpretation is PlatformInterpretation.APPLICABLE
    assert report.source.document_sha256 == LINUX_SHA
    assert report.source.document_bytes == LINUX_FIXTURE.stat().st_size
    assert report.source.hostname == "synth-host"
    assert report.source.collector_tool == "ps4rf-unix-collector"
    assert len(report.categories) == len(Category)
    statuses = {item.category: item.status for item in report.categories}
    assert statuses[Category.PROCFS] is CategoryStatus.APPLICABLE
    assert statuses[Category.SYSTEMD] is CategoryStatus.APPLICABLE
    assert statuses[Category.JAILS] is CategoryStatus.INAPPLICABLE
    suid = next(i for i in report.categories if i.category is Category.SUID)
    assert [entry.key for entry in suid.entries] == ["/usr/bin/synth-suid-helper"]
    assert suid.entries[0].classification is ObservationClass.OBSERVATION


def test_freebsd_only_jails_on_linux_is_inapplicable(adapter: UnixPrivescAdapter):
    report = adapter.classify(LINUX_FIXTURE)
    jails = next(i for i in report.categories if i.category is Category.JAILS)
    assert jails.platform_semantics is PlatformSemantics.FREEBSD_ONLY
    assert jails.status is CategoryStatus.INAPPLICABLE
    assert jails.entries == []
    assert "not interpreted" in jails.note


# -------------------------------------------------------- FreeBSD/OrbisOS target
def test_orbisos_document_yields_no_linux_only_interpretation(adapter: UnixPrivescAdapter):
    raw = ORBIS_FIXTURE.read_bytes()
    assert b"/proc" not in raw          # the OrbisOS fixture carries no linux-only material
    assert b"systemd" not in raw
    report = adapter.classify(ORBIS_FIXTURE, expected_sha256=ORBIS_SHA)
    assert report.platform is TargetPlatform.FREEBSD_ORBISOS
    by_category = {item.category: item for item in report.categories}
    for category in (Category.PROCFS, Category.SYSTEMD):
        item = by_category[category]
        assert item.platform_semantics is PlatformSemantics.LINUX_ONLY
        assert item.status is CategoryStatus.INAPPLICABLE   # recorded, never dropped
        assert item.entries == []                           # never misapplied
    jails = by_category[Category.JAILS]
    assert jails.status is CategoryStatus.APPLICABLE
    assert [entry.key for entry in jails.entries] == ["jails.count", "synth-jail"]
    applicable = {item.category for item in report.categories
                  if item.status is CategoryStatus.APPLICABLE}
    expected_applicable = {c for c in Category
                           if CATEGORY_SEMANTICS[c] is not PlatformSemantics.LINUX_ONLY}
    assert applicable == expected_applicable
    assert {item.category for item in report.categories} == set(Category)  # nothing dropped


def test_orbisos_platform_specific_bucket_is_separate_and_deferred(adapter: UnixPrivescAdapter):
    report = adapter.classify(ORBIS_FIXTURE)
    bucket = report.platform_specific
    assert bucket.status is PlatformSpecificStatus.DEFERRED
    assert bucket.owner == PS4_OWNERSHIP_OWNER
    assert bucket.note == PS4_SCOPE_NOTE
    assert "surface/experiment" in bucket.note
    assert "no PS4 coverage claim" in bucket.note
    assert [f.key for f in bucket.findings] == ["orbisos.family_marker", "ps4.target_family"]
    generic_keys = {entry.key for item in report.categories for entry in item.entries}
    assert "ps4.target_family" not in generic_keys  # PS4 hints stay out of the generic tree


def test_platform_specific_on_linux_target_is_refused(adapter: UnixPrivescAdapter,
                                                      tmp_path: Path):
    document = _load(LINUX_FIXTURE)
    document["platform_specific"] = [{"key": "ps4.target_family", "value": "orbisos"}]
    path = _write_document(tmp_path, document, "linux-with-orbis-hint.json")
    with pytest.raises(UnixPrivescSchemaError):
        adapter.classify(path)
    assert len(adapter.run_log) == 1  # single attempt


def test_inapplicable_category_with_entries_is_refused(adapter: UnixPrivescAdapter,
                                                       tmp_path: Path):
    document = _load(ORBIS_FIXTURE)
    document["categories"].append(
        {"category": "procfs",
         "entries": [{"key": "/proc/mounts", "value": "not applicable here"}]})
    path = _write_document(tmp_path, document, "orbis-with-linux-entries.json")
    with pytest.raises(UnixPrivescSchemaError) as excinfo:
        adapter.classify(path)
    assert "inapplicable" in str(excinfo.value)


# ---------------------------------------------------------------- unknown target
def test_unknown_platform_refuses_interpretation_but_keeps_raw(adapter: UnixPrivescAdapter,
                                                               tmp_path: Path):
    document = _load(LINUX_FIXTURE)
    document["target"]["platform_hint"] = "mystery-os"
    path = _write_document(tmp_path, document, "collector-unknown.json")
    report = adapter.classify(path)
    assert report.platform is TargetPlatform.UNKNOWN
    assert report.platform_hint == "mystery-os"
    assert report.platform_interpretation is PlatformInterpretation.REFUSED
    assert "refused" in report.platform_note
    by_category = {item.category: item for item in report.categories}
    for category in (Category.PROCFS, Category.SYSTEMD, Category.JAILS):
        assert by_category[category].status is CategoryStatus.REFUSED
    raw_procfs = next(block for block in document["categories"]
                      if block["category"] == "procfs")
    observed_procfs = [{"key": entry.key, "value": entry.value}
                       for entry in by_category[Category.PROCFS].entries]
    assert observed_procfs == raw_procfs["entries"]  # raw enumeration stays accessible
    assert by_category[Category.PATH].status is CategoryStatus.APPLICABLE  # posix unaffected
    assert report.platform_specific.status is PlatformSpecificStatus.REFUSED


# -------------------------------------------------------------------- hash gate
def test_hash_mismatch_refuses_before_parsing(adapter: UnixPrivescAdapter, tmp_path: Path):
    with pytest.raises(UnixPrivescHashMismatch):
        adapter.classify(LINUX_FIXTURE, expected_sha256="0" * 64)
    assert len(adapter.run_log) == 1                    # single attempt, no retry
    broken = tmp_path / "broken.json"
    broken.write_bytes(b"{not json at all")
    with pytest.raises(UnixPrivescHashMismatch):
        adapter.classify(broken, expected_sha256="1" * 64)  # hash beats parsing
    assert len(adapter.run_log) == 2
    with pytest.raises(UnixPrivescSchemaError):
        adapter.classify(broken)                        # fail closed without a pin


# ------------------------------------------------------------------- strictness
def test_schema_rejects_extra_fields_and_bad_schema_id():
    document = _load(LINUX_FIXTURE)
    with pytest.raises(ValidationError):
        CollectorDocument.model_validate({**document, "surprise": 1})
    nested = copy.deepcopy(document)
    nested["target"]["sid"] = "x"
    with pytest.raises(ValidationError):
        CollectorDocument.model_validate(nested)
    with pytest.raises(ValidationError):
        CollectorDocument.model_validate(
            {**document, "schema": "ps4rf.unix_privesc.collect/v2"})


def test_duplicate_category_blocks_are_rejected():
    document = _load(LINUX_FIXTURE)
    document["categories"].append({"category": "suid", "entries": []})
    with pytest.raises(ValidationError):
        CollectorDocument.model_validate(document)


def test_adapter_schema_violation_fails_closed(adapter: UnixPrivescAdapter,
                                               tmp_path: Path):
    document = _load(LINUX_FIXTURE)
    document["collector"]["extra"] = True
    path = _write_document(tmp_path, document, "bad-collector.json")
    with pytest.raises(UnixPrivescSchemaError):
        adapter.classify(path)
    assert len(adapter.run_log) == 1


# -------------------------------------------------------- observation-only tree
def _walk(node):
    if isinstance(node, dict):
        yield node
        for value in node.values():
            yield from _walk(value)
    elif isinstance(node, list):
        for item in node:
            yield from _walk(item)


def test_every_report_node_is_observation_requiring_verification(
        adapter: UnixPrivescAdapter):
    for path in (LINUX_FIXTURE, ORBIS_FIXTURE):
        report = adapter.classify(path)
        dumped = report.model_dump(mode="json")
        nodes = list(_walk(dumped))
        assert nodes
        for node in nodes:
            assert node["classification"] == "OBSERVATION", node
            assert node["requires_verification"] is True, node
        expected = (3  # report node + source binding + platform_specific bucket
                    + len(report.categories)
                    + sum(len(item.entries) for item in report.categories)
                    + len(report.platform_specific.findings))
        assert len(nodes) == expected
        assert "PROVEN" not in json.dumps(dumped)


def test_observation_validator_refuses_non_observation_output():
    with pytest.raises(ValidationError):
        CategoryEntry(key="k", value="v", requires_verification=False)
    with pytest.raises(ValidationError):
        CategoryEntry.model_validate({"key": "k", "value": "v",
                                      "classification": "FINDING"})


def test_classify_document_is_a_pure_function_without_files():
    document = CollectorDocument.model_validate(_load(LINUX_FIXTURE))
    binding = DocumentBinding(document_sha256="a" * 64, document_bytes=1,
                              collector_tool="ps4rf-unix-collector",
                              collector_version="0.1-mock", hostname="synth-host")
    report = classify_document(document, source=binding)
    assert report.platform is TargetPlatform.LINUX
    assert report.source.document_sha256 == "a" * 64


# ----------------------------------------------------------------- verification
def test_verify_report_rehashes_and_detects_tamper(adapter: UnixPrivescAdapter,
                                                   tmp_path: Path):
    report = adapter.classify(LINUX_FIXTURE)
    assert verify_report(report, LINUX_FIXTURE) is True
    tampered_copy = tmp_path / "tampered.json"
    tampered_copy.write_bytes(LINUX_FIXTURE.read_bytes() + b" ")
    with pytest.raises(UnixPrivescEvidenceError):
        verify_report(report, tampered_copy)
    tampered_report = report.model_copy(deep=True)
    tampered_report.categories[0].status = CategoryStatus.INAPPLICABLE
    with pytest.raises(UnixPrivescEvidenceError):
        verify_report(tampered_report, LINUX_FIXTURE)
    with pytest.raises(UnixPrivescEvidenceError):
        verify_report(report, tmp_path / "missing.json")


# ----------------------------------------------------------------- adapter state
def test_adapter_state_and_missing_document(adapter: UnixPrivescAdapter, tmp_path: Path):
    with pytest.raises(UnixPrivescStateError):
        adapter.require_report()
    adapter.classify(LINUX_FIXTURE)
    assert adapter.require_report().platform is TargetPlatform.LINUX
    with pytest.raises(UnixPrivescConfigError):
        adapter.classify(tmp_path / "nope.json")
    assert len(adapter.run_log) == 2  # one classified + one missing, no retries


# ------------------------------------------------------------------ mock surface
def test_mock_cli_offline_roundtrip(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    log_path = tmp_path / "mock.log"
    monkeypatch.setenv("PS4RF_UNIX_PRIVESC_MOCK_LOG", str(log_path))
    out = tmp_path / "linux.json"
    assert main(["--variant", "linux", "--out", str(out)]) == 0
    assert out.read_bytes() == LINUX_FIXTURE.read_bytes()
    assert main(["--variant", "freebsd_orbisos",
                 "--out", str(tmp_path / "orbis.json")]) == 0
    assert main(["--variant", "solaris"]) == 3
    assert main([]) == 2
    lines = log_path.read_text(encoding="utf-8").splitlines()
    assert "variant:linux" in lines
    assert "exit:0" in lines
    assert "unknown-variant:solaris" in lines


def test_mock_rejects_unknown_variant_and_is_canonical():
    for variant in VARIANTS:
        assert build_document(variant)["schema"] == SCHEMA_ID
    with pytest.raises(ValueError):
        build_document("solaris")
    assert dump_document(build_document("linux")).endswith("\n")


# ----------------------------------------------------------------- dataset guard
def test_category_semantics_cover_every_category():
    assert set(CATEGORY_SEMANTICS) == set(Category)
    assert CATEGORY_SEMANTICS[Category.JAILS] is PlatformSemantics.FREEBSD_ONLY
    assert CATEGORY_SEMANTICS[Category.PROCFS] is PlatformSemantics.LINUX_ONLY
    assert CATEGORY_SEMANTICS[Category.SYSTEMD] is PlatformSemantics.LINUX_ONLY
    required = {"os_kernel", "identity", "mounts", "filesystem_permissions", "suid",
                "sgid", "path", "environment", "processes", "services", "sockets",
                "cron", "writable_executables", "writable_libraries",
                "writable_configuration", "device_nodes", "loaded_modules",
                "sysctls", "jails", "shells", "installed_binaries"}
    assert required.issubset({item.value for item in Category})


def test_status_counts_per_platform(adapter: UnixPrivescAdapter, tmp_path: Path):
    linux = Counter(item.status for item in adapter.classify(LINUX_FIXTURE).categories)
    assert linux[CategoryStatus.APPLICABLE] == len(Category) - 1   # jails inapplicable
    assert linux[CategoryStatus.INAPPLICABLE] == 1
    assert linux[CategoryStatus.REFUSED] == 0
    orbis = Counter(item.status for item in adapter.classify(ORBIS_FIXTURE).categories)
    assert orbis[CategoryStatus.APPLICABLE] == len(Category) - 2   # procfs/systemd inapplicable
    assert orbis[CategoryStatus.INAPPLICABLE] == 2
    assert orbis[CategoryStatus.REFUSED] == 0
    document = _load(LINUX_FIXTURE)
    document["target"]["platform_hint"] = "?"
    unknown = Counter(item.status for item in
                      adapter.classify(_write_document(tmp_path, document)).categories)
    assert unknown[CategoryStatus.REFUSED] == 3                    # procfs/systemd/jails
    assert unknown[CategoryStatus.APPLICABLE] == len(Category) - 3
    assert unknown[CategoryStatus.INAPPLICABLE] == 0


# ---------------------------------------------------------------- static guards
FORBIDDEN_PATTERNS = (
    r"\bimport\s+subprocess\b", r"\bfrom\s+subprocess\b", r"\bsubprocess\.",
    r"\bPopen\b",
    r"\bimport\s+socket\b", r"\bfrom\s+socket\b", r"\bsocket\.",
    r"\bimport\s+http\b", r"\bfrom\s+http\b", r"https?://",
    r"\bimport\s+urllib\b", r"\bfrom\s+urllib\b", r"\burllib\b",
    r"\burlopen\b",
    r"\bimport\s+requests\b", r"\bfrom\s+requests\b", r"\brequests\.",
    r"shell\s*=\s*True", r"\bos\.system\b", r"\bos\.popen\b", r"\bos\.exec",
    r"\beval\s*\(", r"\bexec\s*\(", r"\bimportlib\b",
)


def test_sources_stay_static_inert_and_offline():
    package = REPO / "tools" / "recon" / "unix_privesc"
    sources = sorted(package.rglob("*.py"))
    assert len(sources) >= 4, "expected package sources"
    for path in sources:
        text = path.read_text(encoding="utf-8")
        for pattern in FORBIDDEN_PATTERNS:
            assert re.search(pattern, text) is None, \
                f"forbidden token {pattern!r} in {path}"
    mock_source = (package / "mock" / "collector_mock.py").read_text(encoding="utf-8")
    for token in ("write_text(", "open(", "environ.get", "json.dumps"):
        assert token in mock_source  # sanity: the scan is looking at real content
