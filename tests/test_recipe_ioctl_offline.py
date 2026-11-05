"""W17 offline tests: bounded snapshot recipe + generic ioctl provider.

Compiles ``tests/harness/recipe_ioctl_offline.c`` against the *generated* recipe
table and runs it. Together with ``test_experiment_parity.py`` this is the
offline proof that the PS4RF primitives behave as the frozen payload oracles do.
"""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
HARNESS = REPO / "tests" / "harness" / "recipe_ioctl_offline.c"
TARGET = REPO / "native" / "target"
BIN = REPO / "tests" / "harness" / "_recipe_ioctl_offline.bin"

EXPECTED_CHECKS = (
    "recipe_table_loaded",
    "q6_recipe_run",
    "q6_attach_zero",
    "own1_indexed_follow",
    "follow_guards",
    "block_exhausted",
    "validate_rejects_forward_root",
    "ioctl_policy_refusals",
    "ioctl_invoke_bounded",
    "submit_abi_staged_block",
)


def _build() -> None:
    cmd = ["gcc", "-std=c11", "-O1", "-Wall", "-Wextra", "-Werror",
           "-I", str(TARGET), "-o", str(BIN), str(HARNESS),
           str(TARGET / "ps4rf_recipe.c"), str(TARGET / "ps4rf_ioctl.c")]
    done = subprocess.run(cmd, capture_output=True, text=True)
    assert done.returncode == 0, done.stderr


def _run() -> list:
    BIN.parent.mkdir(parents=True, exist_ok=True)
    _build()
    done = subprocess.run([str(BIN)], capture_output=True, text=True)
    assert done.returncode == 0, done.stderr
    lines = [json.loads(l) for l in done.stdout.splitlines() if l.strip().startswith("{")]
    assert lines and all(l["suite"] == "w17_recipe_ioctl_offline" for l in lines)
    return lines


def test_harness_checks_all_pass():
    lines = _run()
    names = [l["check"] for l in lines]
    assert list(names) == list(EXPECTED_CHECKS), names
    failed = [l for l in lines if not l["ok"]]
    assert not failed, failed


def test_recipe_table_matches_the_profile_generator():
    done = subprocess.run([sys.executable, str(TARGET / "gen_recipe.py"), "--check"],
                          capture_output=True, text=True)
    assert done.returncode == 0, done.stdout + done.stderr
    header = (TARGET / "ps4rf_recipe_data.h").read_text()
    assert "PS4RF_RECIPE_TABLE_COUNT 14u" in header
    readme = (REPO / "tests" / "fixtures" / "experiments" / "README.md").read_text()
    import hashlib
    digest = hashlib.sha256(header.encode()).hexdigest()
    assert digest in readme, "recipe table hash is not pinned in the fixtures README"
    # no hand written 0x2688000 pseudo-window entries anywhere in the Q6 table
    assert "2688000" not in header


def test_provider_surface_stays_generic():
    """The ioctl provider must not know experiment layouts."""
    ioctl_src = (TARGET / "ps4rf_ioctl.c").read_text() + (TARGET / "ps4rf_ioctl.h").read_text()
    for forbidden in ("segment", "hole", "Q6", "OWN1", "OWN-1", "marker", "stale_rows", "window"):
        assert forbidden not in ioctl_src, f"ioctl provider mentions {forbidden!r}"
    recipe_src = (TARGET / "ps4rf_recipe.c").read_text()
    for forbidden in ("0x2688000", "stale_rows"):
        assert forbidden not in recipe_src
