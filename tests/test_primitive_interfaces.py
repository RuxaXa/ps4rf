"""P4/W3 primitive interface freeze: table/doc/registry/parity as one gate.

The package is only meaningful if the three descriptions of the same surface agree:
the normative module (`tools/primitive_iface/schema.py`), the prose inventory in
`docs/P4-PRIMITIVE-INTERFACES.md`, and the frozen core registry that owns the
operation set. These tests fail if any of them drifts, and they refuse privileged
values and network capability in the package itself.
"""
from __future__ import annotations

import importlib.util
import json
import pathlib
import re
import sys
from tools.primitive_iface import gate as GATE  # noqa: E402

REPO_ROOT = pathlib.Path(__file__).resolve().parents[1]
DOC = REPO_ROOT / "docs" / "P4-PRIMITIVE-INTERFACES.md"
PACKAGE = REPO_ROOT / "tools" / "primitive_iface"
PARITY = REPO_ROOT / "tests" / "fixtures" / "parity" / "vectors-v1.json"

sys.path.insert(0, str(REPO_ROOT))


def _load(name: str, path: pathlib.Path):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


SCHEMA = _load("w3_schema", PACKAGE / "schema.py")
VALIDATE = _load("w3_validate", PACKAGE / "validate.py")
STUB = _load("w3_stub", PACKAGE / "stub.py")


def _doc_rows() -> list[dict]:
    rows: list[dict] = []
    for line in DOC.read_text().splitlines():
        if not line.startswith("| `"):
            continue
        cells = [c.strip() for c in line.strip("|").split("|")]
        if len(cells) != 6:
            continue
        op, family, status, capability, mutating, recovery = cells
        rows.append({
            "op": op.strip("`"), "family": family, "status": status.strip("`"),
            "capability": None if capability == "—" else capability,
            "mutating": mutating == "yes", "recovery_safe": recovery == "yes",
        })
    return rows


def test_doc_inventory_matches_the_schema_module():
    rows = _doc_rows()
    assert len(rows) == len(SCHEMA.OPS), f"doc has {len(rows)} rows"
    by_name = {row["op"]: row for row in rows}
    assert sorted(by_name) == sorted(SCHEMA.OPS_BY_NAME)
    for o in SCHEMA.OPS:
        row = by_name[o.op]
        assert row["family"] == o.family, o.op
        assert row["status"] == o.status, o.op
        assert row["capability"] == o.capability, o.op
        assert row["mutating"] is o.mutating, o.op
        assert row["recovery_safe"] is o.recovery_safe, o.op


def test_schema_matches_the_frozen_core_registry():
    assert SCHEMA.check_against_core() == []


def test_referenced_capabilities_exist_in_the_frozen_catalog():
    assert SCHEMA.check_capabilities_exist() == []


def test_schema_structure_is_self_consistent():
    assert SCHEMA.validate_structure() == []
    # W17F: the three statuses partition the surface (no literal count, and every operation has
    # exactly one implementation status).
    statuses = [o.status for o in SCHEMA.OPS]
    assert len(statuses) == len(set(o.op for o in SCHEMA.OPS))
    assert set(statuses) <= {SCHEMA.STATUS_STUB, SCHEMA.STATUS_DEFER_PRIVILEGE,
                             SCHEMA.STATUS_DEFER_CHAIN, SCHEMA.STATUS_MOCK}
    assert len(SCHEMA.ERROR_CODES) == 11
    assert set(SCHEMA.NEW_ERROR_CODES) <= SCHEMA.ERROR_CODES


def test_fail_closed_validators_and_stub_self_tests_pass(capsys):
    assert SCHEMA.main(["--self-test"]) == 0
    assert VALIDATE.main(["--self-test"]) == 0
    assert STUB.main(["--self-test"]) == 0
    out = capsys.readouterr().out
    assert "SCHEMA OK" in out and "checks passed" in out


def test_recovery_safe_set_is_exactly_the_specified_one():
    safe = {o.op for o in SCHEMA.OPS if o.recovery_safe}
    # W14 §15 (revision R4): the authenticated admin shutdown is recovery-safe by policy -- a
    # controller that has to stop an agent whose boot is in recovery must be able to.
    assert safe == {"session.ping", "session.status", "telemetry.read", "session.shutdown"}


def test_catalog_request_and_response_shapes_validate():
    """The pinned frames are the wire truth; the request bodies must satisfy W3."""
    catalog = json.loads(PARITY.read_bytes())
    requests, responses, byes = [], [], []
    for frame in catalog["frames"]:
        obj = frame["object"]
        {"REQUEST": requests, "RESPONSE": responses, "BYE": byes}[frame["message_type"]].append((frame["id"], obj))
    assert requests and responses and byes
    for _, obj in requests:
        # strict: operation + arguments must match the frozen schema
        assert VALIDATE.validate_request_envelope(obj)
    for _, obj in responses:
        # envelope level: framing vectors carry a placeholder result
        assert obj["status"] in ("OK", "ERROR")
        assert re.fullmatch(r"REQ-[0-9a-f]{32}", obj["header"]["in_reply_to"])
        assert sorted(set(obj) - set(VALIDATE.RESPONSE_KEYS)) == []
    for _, obj in byes:
        VALIDATE.validate_bye(obj)
    # strict result validation uses the stub's own responses (semantic payloads)
    stub = STUB.StubProvider()
    rid = "REQ-" + "0" * 31 + "1"
    resp = stub.call("session.ping", {}, rid, seq=3)
    VALIDATE.validate_response_envelope("session.ping", resp)
    assert resp["result"] == {"pong": True, "seq": 3}


def test_memory_alloc_requires_size():
    stub = STUB.StubProvider()
    rid = "REQ-" + "0" * 31 + "1"
    resp = stub.call("memory.alloc", {}, rid)
    assert resp["status"] == "ERROR" and resp["error"]["code"] == "ARGUMENT_INVALID"


def test_every_gated_operation_is_refused_with_operation_deferred():
    stub = STUB.StubProvider()
    rid = "REQ-" + "0" * 31 + "1"
    # W17F: drive the expectation from the gate metadata, not from "everything that is not a stub".
    gated = [o for o in SCHEMA.OPS if o.status == SCHEMA.STATUS_DEFER_PRIVILEGE]
    assert {o.op for o in gated} == set(GATE.privilege_gated_ops()), "gate metadata and schema disagree"
    for o in gated:
        args = {}
        for fl in o.args:
            args[fl.name] = {"int": 1, "str": "x", "bool": True, "ref": "mem:0123456789ABCDEF",
                             "hex32": "a" * 64, "array": [], "object": {}}[fl.type]
        resp = stub.call(o.op, args, rid)
        assert resp["status"] == "ERROR", o.op
        assert resp["error"]["code"] == "OPERATION_DEFERRED", o.op


def test_package_is_a_pure_data_layer():
    """No privileged values, no secrets, no network/subprocess capability."""
    banned_imports = ("import socket", "import subprocess", "import requests",
                      "import http", "urllib")
    for path in (PACKAGE / "schema.py", PACKAGE / "validate.py", PACKAGE / "stub.py", DOC):
        text = path.read_text()
        assert "/home/" not in text, f'{path.name} leaks an absolute path'
        assert "PRIVATE KEY" not in text
        # no invented hardware values: no address-like literals, no RVA/offset tables
        assert not re.search(r"0x[0-9a-fA-F]{6,}", text), f'{path.name} contains an address-like literal'
        for token in banned_imports:
            assert token not in text, f'{path.name} uses {token}'
    # the doc must state the userland-only guard explicitly
    doc = DOC.read_text()
    assert "userland only" in doc and "OPERATION_DEFERRED" in doc
