"""Native parity gate (P4/W2): build the C skeleton and prove byte parity offline.

These tests shell out to the host toolchain; they skip cleanly when gcc/make are
missing so the suite stays portable. What they assert:

1. the native core builds into an ET_DYN ELF plus a flat BIN artifact,
2. the offline harness replays both golden catalogs and the W2 negative catalog
   with zero mismatches (byte-level comparison),
3. the agent skeleton completes a full handshake and session loop against an
   in-process host stub (`--self-test-loopback`),
4. two independent builds are byte-identical (reproducible build artifact).
"""
from __future__ import annotations

import shutil
import subprocess

import pytest

REPO_ROOT = __import__("pathlib").Path(__file__).resolve().parents[1]
NATIVE = REPO_ROOT / "native"
CATALOGS = [
    "../tests/fixtures/crypto/vectors-v1.json",
    "../tests/fixtures/parity/vectors-v1.json",
    "../tests/fixtures/parity/w2-negative-v1.json",
]


def _require_tools() -> None:
    for tool in ("gcc", "make", "objcopy", "readelf"):
        if shutil.which(tool) is None:
            pytest.skip(f"{tool} not available: native build tests skipped")


def _build(build_dir) -> None:
    proc = subprocess.run(["make", "all", f"BUILD={build_dir}"], cwd=NATIVE,
                          capture_output=True, text=True)
    assert proc.returncode == 0, proc.stdout + proc.stderr


@pytest.fixture(scope="module")
def build_dir(tmp_path_factory):
    _require_tools()
    path = tmp_path_factory.mktemp("ps4rf-native")
    _build(path)
    return path


def test_native_parity_harness_has_zero_mismatches(build_dir):
    proc = subprocess.run([str(build_dir / "ps4rf_parity"), *CATALOGS], cwd=NATIVE,
                          capture_output=True, text=True)
    output = proc.stdout
    assert proc.returncode == 0, output[-4000:]
    assert "parity verdict: PASS" in output
    fail_lines = [line for line in output.splitlines() if line.startswith("FAIL")]
    assert fail_lines == [], "\n".join(fail_lines)
    # every stage must have executed at least one vector
    for stage in ("canonicalization", "transcript", "hkdf", "aad", "nonce", "aead",
                  "frame_header", "wire_frame", "handshake"):
        assert f"{stage} " in output, f"stage {stage} missing from the harness report"


def test_agent_elf_is_et_dyn_and_bin_artifact_exists(build_dir):
    elf = build_dir / "ps4rfd.elf"
    flat = build_dir / "ps4rfd.bin"
    assert elf.exists() and flat.exists()
    header = subprocess.run(["readelf", "-h", str(elf)], capture_output=True, text=True).stdout
    type_line = next((line for line in header.splitlines() if "Type:" in line), "")
    token = type_line.split("Type:")[1].strip().split()[0] if "Type:" in type_line else ""
    # ELF64 PIE: binutils prints "DYN (Position-Independent Executable file)",
    # which is ET_DYN in the header.
    assert token in {"DYN", "ET_DYN"}, header


def test_native_self_test_loopback_passes(build_dir):
    proc = subprocess.run([str(build_dir / "ps4rfd.elf"), "--self-test-loopback"],
                          capture_output=True, text=True)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "verdict:              PASS" in proc.stdout
    assert "both sides agree:     k_hs yes, host->agent prefix yes" in proc.stdout


def test_native_build_is_reproducible(tmp_path):
    _require_tools()
    import hashlib

    def hashes(directory):
        _build(directory)
        out = {}
        for name in ("ps4rfd.elf", "ps4rfd.bin", "ps4rf_parity"):
            out[name] = hashlib.sha256((directory / name).read_bytes()).hexdigest()
        return out

    first = hashes(tmp_path / "a")
    second = hashes(tmp_path / "b")
    assert first == second, f"builds differ: {first} vs {second}"
