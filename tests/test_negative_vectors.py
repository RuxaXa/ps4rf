"""Self-verifying checks for the W2 boundary/negative script catalog.

The catalog is the machine-readable bridge between the frozen Python reference and
the native parity harness: every expected outcome in it is recomputed by its
generator from the frozen core. These tests assert that the file on disk really
is that product and that nothing in the catalog was hand-written:

(a) byte-reproducible from the generator,
(b) the pinned source hashes match the files on disk,
(c) its boundary section agrees with the crypto catalog's recorded outcomes,
(d) every negative case required by the W2 work order is present and runnable,
(e) structural exemptions are explicit and carry a reason.
"""
from __future__ import annotations

import hashlib
import importlib.util
import json
import pathlib
import sys

REPO_ROOT = pathlib.Path(__file__).resolve().parents[1]
FIXTURES = REPO_ROOT / "tests" / "fixtures"
NEG_FILE = FIXTURES / "parity" / "w2-negative-v1.json"
CRYPTO_FILE = FIXTURES / "crypto" / "vectors-v1.json"
PARITY_FILE = FIXTURES / "parity" / "vectors-v1.json"


def _load_generator():
    spec = importlib.util.spec_from_file_location(
        "ps4rf_negative_gen", FIXTURES / "parity" / "gen_negative.py")
    assert spec is not None and spec.loader is not None, "generator not loadable"
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)
    return mod


GEN = _load_generator()
FILE_BYTES = NEG_FILE.read_bytes()
FILE = json.loads(FILE_BYTES)
CRYPTO = json.loads(CRYPTO_FILE.read_bytes())

# The W2 work order lists these negative cases by name.
REQUIRED_NEGATIVES = {
    "n01_bad_transcript": "bad transcript",
    "n02_bad_auth_proof": "bad AUTH proof",
    "n03_bad_auth_ack_proof": "bad AUTH_ACK proof",
    "n04_wrong_direction": "wrong direction",
    "n05_wrong_message_type": "wrong message type",
    "n06_unknown_type_byte": "unknown type byte",
    "n07_wrong_sequence": "wrong sequence",
    "n08_duplicate_sequence": "duplicate sequence",
    "n09_sequence_gap": "sequence gap",
    "n10_sequence_at_ceiling": "sequence at ceiling",
    "n11_sequence_over_ceiling": "sequence over ceiling",
    "n12_tampered_ciphertext": "tampered ciphertext",
    "n13_tampered_tag": "tampered tag",
    "n14_tampered_aad": "tampered AAD",
    "n15_oversized_frame": "oversized frame",
    "n16_truncated_frame": "truncated frame",
    "n17_wrong_session_id": "wrong session id",
    "n18_wrong_protocol_version": "wrong protocol version",
}


def _sha256(path: pathlib.Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def test_catalog_is_byte_reproducible():
    assert GEN.render(GEN.build()) == FILE_BYTES


def test_pinned_sources_match_files_on_disk():
    source = FILE["source"]
    assert source["crypto_catalog"]["sha256"] == _sha256(CRYPTO_FILE)
    assert source["parity_catalog"]["sha256"] == _sha256(PARITY_FILE)
    for rel, digest in source["frozen_core"].items():
        assert digest == _sha256(REPO_ROOT / rel), rel


def test_boundary_expectations_match_the_crypto_catalog():
    recorded = {e["id"]: e for e in CRYPTO["boundaries"]}
    covered = {e["id"] for e in FILE["boundaries"] if e["id"] in recorded}
    assert covered == set(recorded), "every recorded boundary must be represented"
    for entry in FILE["boundaries"]:
        rec = recorded.get(entry["id"])
        if rec is None:
            continue  # native-only variant (documented in the description)
        assert entry["reference_outcome"] == rec["outcome"], entry["id"]
        assert entry.get("reference_exception") == rec.get("exception"), entry["id"]


def test_structural_exemptions_are_explicit_and_empty():
    structural = [e for e in FILE["boundaries"] if e.get("structural")]
    assert structural, "the three structural boundaries must be listed explicitly"
    for entry in structural:
        assert entry["steps"] == []
        assert entry["structural_reason"].strip()
        assert entry["reference_outcome"] == "raises"


def test_every_required_negative_case_is_present_and_runnable():
    ids = {e["id"] for e in FILE["negative"]}
    missing = set(REQUIRED_NEGATIVES) - ids
    assert not missing, f"missing negative cases: {sorted(missing)}"
    for entry in FILE["negative"]:
        assert entry["steps"], f"{entry['id']} has no steps"
        for step in entry["steps"]:
            assert step["call"] and step["stage"]
            assert step.get("expect") in {"ok", "raises"}


def test_negative_cases_pin_an_exception_name():
    for entry in FILE["negative"]:
        raises = [s for s in entry["steps"] if s.get("expect") == "raises"]
        for step in raises:
            assert step.get("exception"), f"{entry['id']} does not pin an exception"


def test_parity_cases_cover_the_catalog_channel_cases():
    catalog_ids = {c["id"] for c in json.loads(PARITY_FILE.read_bytes())["channel"]["cases"]}
    script_ids = {e["id"].replace("channel_", "", 1) for e in FILE["parity_cases"]
                  if e["id"].startswith("channel_")}
    assert script_ids == catalog_ids
    for entry in FILE["parity_cases"]:
        assert entry["steps"]


def test_catalog_has_no_paths_or_production_material():
    text = FILE_BYTES.decode()
    assert "/home/" not in text
    assert "PRIVATE KEY" not in text
    assert FILE["session"]["session_id"].startswith("SES-")
