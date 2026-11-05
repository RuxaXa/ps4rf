"""S1.2c handle/object identity: fixtures, discrimination and the no-constants rule.

The fixture image is produced by real binutils and analysed through the same
capstone path as the firmware.  The fixture document hands in the release root as
data, exactly like a firmware anchor; no fixture *name* reaches the analysis.

The four cases differ only in the shape under test:

* handle decision + two drops  -> a claim (``D7_handle_object_identity``)
* object decision + two drops  -> silence, and a *verified premise* counter
* handle decision + one drop   -> silence
* two drops, no decision       -> an observation only (``D8_reference_balance``)
"""
from __future__ import annotations

import hashlib
import json
import pathlib
import re
import subprocess
import sys

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from capstone import CS_ARCH_X86, CS_MODE_64, Cs

from tools.discovery import handles, patterns
from tools.discovery.image import FunctionIndex, FunctionRecord
from tools.discovery.ownership import OwnershipCatalog

FIXDIR = ROOT / "tests" / "fixtures" / "discovery"
FIXTURE = FIXDIR / "handle-fixtures.json"
GENERATOR = FIXDIR / "gen_handles.py"


class FixtureImage:
    def __init__(self, doc: dict):
        self.base = int(doc["base_rva"], 16)
        self.data = bytes.fromhex(doc["image_hex"])
        self.size = self.base + len(self.data)
        self.sha256 = hashlib.sha256(self.data).hexdigest()

    def read(self, rva: int, length: int) -> bytes:
        return self.data[rva - self.base: rva - self.base + length]

    def disasm(self, rva: int, length: int, instructions: bool = True):
        md = Cs(CS_ARCH_X86, CS_MODE_64)
        md.detail = bool(instructions)
        available = max(0, len(self.data) - (rva - self.base))
        return list(md.disasm(self.read(rva, min(length, available)), rva)), md

    def executable_ranges(self):
        return [(self.base, self.base + len(self.data))]


@pytest.fixture(scope="module")
def env():
    doc = json.loads(FIXTURE.read_text(encoding="utf-8"))
    image = FixtureImage(doc)
    index = FunctionIndex(
        [FunctionRecord(int(meta["rva"], 16), int(meta["size"], 16), name)
         for name, meta in doc["symbols"].items()]
    )
    facts = {
        "anchors": {"free": doc["roots"]["free"]},
        "anchor_provenance": {"free": "fixture data root"},
    }
    catalog = OwnershipCatalog(image, index, facts)
    return doc, image, index, catalog


def scan(env, name: str):
    _doc, image, index, catalog = env
    rec = index.by_name(name)
    assert rec is not None, f"fixture symbol missing: {name}"
    ctx = patterns.ScanContext(
        ownership=catalog, handles=handles.HandleCatalog(image, index), subsystem="fixture"
    )
    return patterns.scan_function(image, rec.rva, rec.size, rec.name, ctx), ctx, index, image


def test_fixture_matches_generator():
    """The committed image is exactly what the generator produces (no drift)."""
    before = FIXTURE.read_text(encoding="utf-8")
    result = subprocess.run([sys.executable, str(GENERATOR), "--check"],
                            cwd=str(ROOT), capture_output=True, text=True)
    assert result.returncode == 0, result.stdout + result.stderr
    assert FIXTURE.read_text(encoding="utf-8") == before


@pytest.mark.parametrize("name,expected", [
    ("fixture_handle_reuse", "D7_handle_object_identity"),
    ("fixture_object_identity", "NO_CLAIM"),
    ("fixture_handle_single_drop", "NO_CLAIM"),
    ("fixture_no_identity_premise", "D8_reference_balance"),
    ("fixture_two_generations", "NO_CLAIM"),
    ("fixture_borrowed_reference", "NO_CLAIM"),
])
def test_identity_case(env, name, expected):
    findings, _ctx, _index, _image = scan(env, name)
    got = {f.detector for f in findings}
    if expected == "NO_CLAIM":
        assert "D7_handle_object_identity" not in got
    else:
        assert expected in got, f"{name}: expected {expected}, got {sorted(got)}"


def test_handle_case_claim_is_explainable(env):
    findings, _ctx, _index, image = scan(env, "fixture_handle_reuse")
    claim = next(f for f in findings if f.detector == "D7_handle_object_identity")
    _doc, _image, _index2, _catalog = env
    assert claim.rank == 2
    claims = claim.claims
    assert claims["decision_domain"] == "handle"
    assert claims["drops_on_object"] == 2
    assert claims["surplus_drops"], "the surplus drop must be named"
    # every claimed site is inside the fixture function
    _d, _i, index, _c = env
    rec = index.by_name("fixture_handle_reuse")
    for site in claim.site_rvas:
        assert rec.rva <= site < rec.rva + rec.size
    # the evidence window shows the decision and the surplus drop
    joined = " ".join(claim.window)
    assert "cmp dword ptr" in joined
    assert claim.falsification


def test_object_case_records_verified_premise(env):
    findings, ctx, _index, _image = scan(env, "fixture_object_identity")
    assert not [f for f in findings if f.detector == "D7_handle_object_identity"]
    assert ctx.analytics.get("handle_identity_premise_verified") == 1


def test_single_drop_is_not_a_claim(env):
    findings, _ctx, _index, _image = scan(env, "fixture_handle_single_drop")
    assert not [f for f in findings
                if f.detector in ("D7_handle_object_identity", "D8_reference_balance")]


def test_balance_without_premise_is_observation_only(env):
    findings, _ctx, _index, _image = scan(env, "fixture_no_identity_premise")
    balance = [f for f in findings if f.detector == "D8_reference_balance"]
    assert balance
    assert balance[0].rank == 3, "a count without an identity decision must stay an observation"
    assert not [f for f in findings if f.detector == "D7_handle_object_identity"]


def _detector_source(name: str) -> str:
    source = (ROOT / "tools" / "discovery" / "patterns.py").read_text(encoding="utf-8")
    start = source.index(f"def {name}(")
    end = source.index("\nDETECTORS = (", start)
    return source[start:end]


@pytest.mark.parametrize("name", ["detect_handle_object_identity", "detect_reference_balance"])
def test_generic_rules_carry_no_target_constants(name):
    """P3: no syscall numbers, command constants, names or offsets in the rules."""
    body = _detector_source(name)
    low = body.lower()
    for forbidden in ("netcontrol", "netevent", "fdrop", "getsock", "socket_fd",
                      "0x20000003", "0x20000007", "0x20000002"):
        assert forbidden not in low, f"{name} must not mention {forbidden}"
    # no firmware addresses: any hex literal longer than two digits would be one
    bad = [h for h in re.findall(r"0x[0-9a-fA-F]+", body) if len(h) > 4]
    assert not bad, f"{name} contains literal addresses: {bad}"

    helper = (ROOT / "tools" / "discovery" / "handles.py").read_text(encoding="utf-8")
    assert "netcontrol" not in helper.lower()
    assert "fdrop" not in helper.lower()
    assert not [h for h in re.findall(r"0x[0-9a-fA-F]+", helper) if len(h) > 4]
