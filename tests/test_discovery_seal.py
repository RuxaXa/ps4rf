"""Seal tests.

An audit hook cannot be uninstalled, so every test that installs one runs in a fresh
subprocess: sealing a real directory inside the pytest process would break every later
test that reads it, and a guard that quietly disables itself under test is not a guard.
"""
from __future__ import annotations

import json
import pathlib
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]

HARNESS = r'''
import json, pathlib, sys
sys.path.insert(0, {root!r})
from tools.discovery import seal

sealed_dir = pathlib.Path({sealed!r})
allowed_dir = pathlib.Path({allowed!r})
recorded = []
seal.seal([sealed_dir], recorder=recorded)
out = {{"recorded_ok": None, "blocked": None, "allowed_read_ok": None}}
try:
    (allowed_dir / "visible.txt").read_text()
    out["allowed_read_ok"] = True
except Exception as exc:
    out["allowed_read_ok"] = type(exc).__name__
try:
    (sealed_dir / "answer.json").read_text()
    out["blocked"] = "READ SUCCEEDED -- the seal did not hold"
except seal.SealViolation:
    out["blocked"] = "SealViolation"
try:
    list(sealed_dir.iterdir())
    out["recorded_ok"] = "LISTING SUCCEEDED -- the seal did not cover listing"
except seal.SealViolation:
    out["recorded_ok"] = "SealViolation"
out["saw_allowed"] = any(str(allowed_dir) in path for path in recorded)
print(json.dumps(out))
'''


def run_harness(tmp_path: pathlib.Path) -> dict:
    sealed = tmp_path / "sealed"
    allowed = tmp_path / "allowed"
    sealed.mkdir(); allowed.mkdir()
    (sealed / "answer.json").write_text('{"site": 4660}', encoding="utf-8")
    (allowed / "visible.txt").write_text("image bytes", encoding="utf-8")
    script = HARNESS.format(root=str(ROOT), sealed=str(sealed), allowed=str(allowed))
    proc = subprocess.run([sys.executable, "-c", script], capture_output=True, text=True,
                          cwd=str(ROOT))
    assert proc.returncode == 0, proc.stdout + proc.stderr
    return json.loads(proc.stdout.strip().splitlines()[-1])


def test_reading_a_sealed_file_raises(tmp_path):
    assert run_harness(tmp_path)["blocked"] == "SealViolation"


def test_listing_a_sealed_directory_raises(tmp_path):
    assert run_harness(tmp_path)["recorded_ok"] == "SealViolation"


def test_reading_outside_the_seal_still_works(tmp_path):
    result = run_harness(tmp_path)
    assert result["allowed_read_ok"] is True
    assert result["saw_allowed"] is True, "the recorder should show the allowed read"


def test_matching_is_path_based_not_name_based():
    from tools.discovery import seal

    sealed = [str((ROOT / "tools" / "discovery" / "data" / "corpus").resolve())]
    inside = ROOT / "tools" / "discovery" / "data" / "corpus" / "afterglow.json"
    sibling = ROOT / "tools" / "discovery" / "data" / "corpus-notes.md"
    assert seal.is_sealed(inside, sealed) is True
    assert seal.is_sealed(sibling, sealed) is False


def test_the_default_sealed_set_names_the_answer_directories():
    from tools.discovery import seal

    assert set(seal.DEFAULT_SEALED) == {"corpus", "blind", "negative"}


def test_unseal_refuses_instead_of_pretending():
    from tools.discovery import seal

    try:
        seal.unseal()
    except seal.SealNotRemovable as exc:
        assert "run the sealed part last" in str(exc)
    else:
        raise AssertionError("unseal() must not silently pretend the seal is gone")
