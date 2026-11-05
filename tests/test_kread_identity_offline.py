#!/usr/bin/env python3
"""W16 (option B) offline test: the binding-window step, driven through the production module.

The harness ``tests/harness/kread_identity_offline.c`` links ``native/target/ps4rf_kread.c`` and
replaces only its leaves and the two SDK entry points, so the row check against the compiled table,
the step's own one-shot re-arm and spend, the single ordered read, the copy-out and the monotonic
lifetime cursor are the code that runs on the console.

This module then plays the **host's** part, which is the whole division of labour of the W16 wave:
the payload reports raw bytes and makes no match claim, and the host re-derives the expected bytes
independently -- here from the canonical registry (``rva`` -> the synthetic image pattern) -- and
compares. A payload-reported byte string that does not describe the pinned window fails.

Counter-proof: the harness carries a mutant build (``-DPS4RF_KREAD_IDENTITY_MUTANT_WRONG_SLOT``)
that declares the wrong row for the first slot; the run must fail, which is what proves the checks
above are not vacuous.
"""
from __future__ import annotations

import json
import pathlib
import subprocess
import sys

REPO = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO))

from tools.profiles import regions                                            # noqa: E402

HARNESS = REPO / 'tests/harness/kread_identity_offline.c'
MODULE = REPO / 'native/target/ps4rf_kread.c'
BUILD_DIR = pathlib.Path.home() / '.hermes/cache/scratch/ps4rf-w16/test-harness'
CANDIDATE = 'profiles/fw1352/profile-13.52-ccp1.json'
CLOCK = 2654435761


def expected_windows() -> list[tuple[str, int]]:
    """(name, rva) of the revision candidate's STRICT windows, in compiled table order."""
    picked: list[tuple[str, int]] = []
    for region in regions.compiled_regions():
        if region.identity_status != regions.IDENTITY_STRICT or CANDIDATE not in region.provenance:
            continue
        assert region.rva is not None and region.length is not None, region.name
        picked.append((region.name, region.rva))
    assert len(picked) == 5, picked
    return picked


def sim_bytes(rva: int, length: int = 16) -> str:
    """The harness's synthetic image: byte at rva is (rva * 2654435761) >> 24, 32 bit wrap."""
    return ''.join(f'{(((rva + i) * CLOCK) & 0xFFFFFFFF) >> 24:02x}' for i in range(length))


def build(flags: tuple[str, ...] = (), name: str = 'kread_identity_offline') -> pathlib.Path:
    BUILD_DIR.mkdir(parents=True, exist_ok=True)
    binary = BUILD_DIR / name
    units = [HARNESS, MODULE, REPO / 'native/src/jcs.c', REPO / 'native/src/sha256.c']
    result = subprocess.run(
        ['gcc', '-std=c11', '-O1', '-Wall', '-Wextra', '-Wno-unused-parameter', *flags,
         '-I', str(REPO / 'native/target'), '-I', str(REPO / 'native/src'),
         '-o', str(binary), *[str(u) for u in units]],
        capture_output=True, text=True)
    assert result.returncode == 0, f'harness build failed:\n{result.stderr}'
    assert not result.stderr.strip(), f'harness build emitted warnings:\n{result.stderr}'
    return binary


def run(binary: pathlib.Path) -> dict:
    result = subprocess.run([str(binary)], capture_output=True, text=True)
    lines = [line for line in result.stdout.splitlines() if line.startswith('{')]
    assert len(lines) == 1, f'unexpected harness output:\n{result.stdout}\n{result.stderr}'
    return json.loads(lines[0])


def test_the_step_reads_exactly_the_five_windows_and_the_host_rederives_every_byte():
    """Five steps, in table order, one window each -- judged from the outside."""
    report = run(build())
    windows = expected_windows()
    assert report['problems'] == 0, report
    assert report['window_count'] == 5
    assert [w['index'] for w in report['windows']] == [9, 10, 11, 12, 13]
    assert [w['status_name'] for w in report['windows']] == ['OK'] * 5
    assert [w['copied_len'] for w in report['windows']] == [16] * 5
    for entry, (name, rva) in zip(report['windows'], windows):
        assert entry['bytes_hex'] == sim_bytes(rva), f'{name}: the host re-derivation differs'
    # one privileged transition per step and nothing else: 5 kexecs, 5 dispatches, 80 bytes read
    assert report['kexec_calls'] == 5 and report['dispatch_calls'] == 5
    assert report['bytes_read'] == 5 * 16
    assert report['cursor'] == 5


def test_the_lifetime_cursor_makes_a_second_read_impossible():
    """After the fifth window the set is exhausted: SET_COMPLETE, and no further transition.

    This is the property the wave depends on -- a window is read once per lifetime, a failed one is
    never retried, and a session re-arm (which happens before every step here) cannot re-open it.
    """
    report = run(build())
    assert report['exhausted']['status_name'] == 'SET_COMPLETE'
    assert report['exhausted']['kexec_delta'] == 0
    assert report['exhausted']['kexec_calls'] == 5      # exactly one transition per window, ever
    assert report['row_check_stays_out'] is True
    assert report['cursor'] == 5


def test_the_wrong_slot_mutant_is_caught():
    """Counter-proof: declare the wrong row for a slot and the run must fail."""
    binary = build(('-DPS4RF_KREAD_IDENTITY_MUTANT_WRONG_SLOT',), 'kread_identity_offline_mutant')
    result = subprocess.run([str(binary)], capture_output=True, text=True)
    assert result.returncode != 0, 'the mutant must not pass'
    report = json.loads([line for line in result.stdout.splitlines()
                         if line.startswith('{')][0])
    assert report['problems'] >= 1, report
    assert any('row other than its own slot' in text for text in report['problem_text']), report
