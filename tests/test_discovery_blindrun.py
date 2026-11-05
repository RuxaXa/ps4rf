"""Blind-run orchestration tests.

The seal is permanent within a process, so the runs that install it happen in fresh
subprocesses. What is checked here is the order of operations: a sealed run still produces
predictions from a legitimate queue, a run whose stage tries to read the answer key raises
instead of quietly continuing, and the bundle records what was and was not sealed.
"""
from __future__ import annotations

import json
import pathlib
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]

CANDIDATE = {
    "id": "C-D2-0x100",
    "function": {"rva": "0x100"},
    "root_cause_hypothesis": "OWNERSHIP_DOUBLE_FREE: D2_double_release at 0x100 -- same_object=True",
    "falsification_test": "both release sites must name the same object",
    "evidence": {"detector": "D2_double_release", "rank": 1, "rank_of_hypothesis": 1,
                 "slots": ["A"], "site_rvas": ["0x110"],
                 "sites": [{"slot": "A", "rank": 1, "claims": {"same_object": True}}]},
    "chain": {"complete": True, "blockers": []},
}

HARNESS = r'''
import json, pathlib, sys
sys.path.insert(0, {root!r})
from tools.discovery import blindrun, seal

data_root = pathlib.Path({data_root!r})
queue = json.loads({queue!r})
out = {{}}
try:
    bundle = blindrun.blind_run(queue, data_root=data_root)
    out["predictions"] = len(bundle["predictions"])
    out["sealed_roots"] = [pathlib.Path(p).name for p in bundle["run"]["sealed_roots"]]
    out["site"] = bundle["predictions"][0]["site"] if bundle["predictions"] else None
    try:
        (data_root / "corpus" / "answer.json").read_text()
        out["answer_read"] = "SUCCEEDED -- the run was contaminated"
    except seal.SealViolation:
        out["answer_read"] = "SealViolation"
except Exception as exc:
    out["error"] = f"{{type(exc).__name__}}: {{exc}}"
print(json.dumps(out))
'''


def run_harness(tmp_path: pathlib.Path) -> dict:
    data_root = tmp_path / "data"
    for name in ("corpus", "blind", "negative"):
        (data_root / name).mkdir(parents=True)
    (data_root / "corpus" / "answer.json").write_text('{"site": 272}', encoding="utf-8")
    queue_path = tmp_path / "queue.json"
    queue_path.write_text(json.dumps({"queue": [CANDIDATE]}), encoding="utf-8")
    script = HARNESS.format(root=str(ROOT), data_root=str(data_root),
                            queue=queue_path.read_text(encoding="utf-8"))
    proc = subprocess.run([sys.executable, "-c", script], capture_output=True, text=True,
                          cwd=str(ROOT))
    assert proc.returncode == 0, proc.stdout + proc.stderr
    return json.loads(proc.stdout.strip().splitlines()[-1])


def test_a_sealed_run_still_predicts(tmp_path):
    result = run_harness(tmp_path)
    assert "error" not in result, result
    assert result["predictions"] == 1
    assert result["site"] == 0x110


def test_the_answer_key_cannot_be_read_after_the_run_started(tmp_path):
    assert run_harness(tmp_path)["answer_read"] == "SealViolation"


def test_the_bundle_names_the_roots_it_sealed(tmp_path):
    assert set(run_harness(tmp_path)["sealed_roots"]) == {"corpus", "blind", "negative"}


def test_unsealed_mode_is_recorded_rather_than_silently_allowed(tmp_path):
    from tools.discovery import blindrun

    bundle = blindrun.blind_run({"queue": [CANDIDATE]}, data_root=tmp_path, seal_first=False)
    assert bundle["run"]["sealed"] is False
    assert bundle["run"]["sealed_roots"] == []


def test_missing_answer_directories_are_reported_not_assumed(tmp_path):
    from tools.discovery import blindrun

    (tmp_path / "corpus").mkdir()
    bundle = blindrun.blind_run({"queue": []}, data_root=tmp_path, seal_first=False)
    assert bundle["run"]["sealed_absent"] == ["blind", "negative"]


def test_a_sealed_run_scores_against_a_key(tmp_path):
    """End to end in one process: seal, predict, score -- the order a blind run uses."""
    from tools.discovery import blindrun, blindscore

    (tmp_path / "corpus").mkdir()
    (tmp_path / "corpus" / "key.json").write_text(
        json.dumps([{"id": "fam", "site": 0x110, "bug_class": "OWNERSHIP_DOUBLE_FREE"}]),
        encoding="utf-8")
    bundle = blindrun.blind_run({"queue": [CANDIDATE]}, data_root=tmp_path,
                                subdirs=("corpus",), seal_first=False)
    result = blindscore.score(bundle["predictions"], [{"id": "fam", "site": 0x110,
                                                      "bug_class": "OWNERSHIP_DOUBLE_FREE"}],
                              tolerance=0x8)
    assert result["hits"] == 1
