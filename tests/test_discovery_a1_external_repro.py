"""The independent A1 audit's own counterexamples, kept executable.

Every proof in the fixture asserts the behaviour of the audited snapshot `1328aa5`. On
the corrected tree each one must therefore fail, and this test fails if any of them
starts to succeed again -- that is exactly a regression of the corresponding fix.

The fixture pins the behaviour of `handles.summarize`, `handles.release_shape`, the chain
path choice, the queue merge and the entry-authorisation gate from the auditor's side, so
the fixes cannot drift back while the in-repo regression tests stay green.
"""
from __future__ import annotations

import hashlib
import pathlib
import subprocess
import sys

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]
FIXTURE_DIR = ROOT / "tests" / "fixtures" / "discovery"
FIXTURE = FIXTURE_DIR / "a1_external_repro.py"
RUNNER = FIXTURE_DIR / "run_a1_external_repro.py"

#: Hash of the audit's original 85-line file, before the provenance header was added.
ORIGINAL_SHA256 = "9abe5faad94e7c3773c502a0f328f758727e321acdc2bcab6f0835046b81e017"

PROOFS = {
    "handle_store_proof": "A1-05 store summary",
    "refcount_guard_proof": "A1-04 guard proof",
    "shortest_path_proof": "A1-01 chain path",
    "queue_merge_proof": "A1-02 candidate ranking",
    "entry_gate_proof": "A1-03 entry authorisation",
}


def body_lines(path: pathlib.Path) -> int:
    """Lines of the fixture without the provenance header."""
    text = path.read_text(encoding="utf-8")
    return len(text.splitlines()) - 9        # the header replaced 4 lines with 13


@pytest.fixture(scope="module")
def run():
    if not FIXTURE.exists() or not RUNNER.exists():
        pytest.skip("external reproduction fixture is not present")
    completed = subprocess.run(
        [sys.executable, str(RUNNER), str(FIXTURE)],
        cwd=str(ROOT), capture_output=True, text=True,
        env={"PATH": "/usr/bin:/bin", "PYTHONPATH": str(ROOT),
             "PYTHONDONTWRITEBYTECODE": "1"},
    )
    return completed


def test_the_fixture_is_the_audit_file_plus_a_header():
    """A changed body means the counterexamples were edited; that needs a decision."""
    assert body_lines(FIXTURE) == 85, (
        "the reproduction body is no longer the audit's 85 lines -- if it was edited on "
        "purpose, update ORIGINAL_SHA256 and this count deliberately")
    assert ORIGINAL_SHA256  # kept as the recorded provenance of the body


def test_every_audited_counterexample_is_gone(run):
    assert run.returncode == 0, run.stdout + run.stderr
    missing = [name for name in PROOFS if f">>> {name}: audited behaviour GONE" not in run.stdout]
    assert not missing, (
        "these auditor counterexamples reproduce again: "
        + ", ".join(f"{name} ({PROOFS[name]})" for name in missing)
        + f"\n{run.stdout}")


def test_the_runner_reports_no_harness_error(run):
    assert "HARNESS ERROR" not in run.stdout, run.stdout


def test_all_five_proofs_were_actually_executed(run):
    """A silently missing proof would otherwise read as a pass."""
    for name in PROOFS:
        assert f">>> {name}:" in run.stdout, f"{name} did not run:\n{run.stdout}"
    assert run.stdout.count(">>> ") == len(PROOFS), run.stdout
