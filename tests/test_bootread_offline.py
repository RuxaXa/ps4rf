"""W11.2 offline tests: the fail-closed privileged boot read harness.

The harness test compiles and runs ``tests/harness/bootread_offline.c``, which links the
production callback (``native/target/ps4rf_bootread.c``) and replaces only its two weak leaf
operations (MSR read, byte read) plus the two SDK entry points (``kexec``, ``get_kernel_base``)
with a synthetic kernel -- the code in between is the code that runs on the console.

The synthetic kernel dispatches exactly like the console's syscall 11 does (the shape the W9
live run proved and ``ps4rf_attest.h`` documents): it builds ``{ void *syscall_handler; payload }``
and passes a pointer to that wrapper to the callback, with the caller's argument block in the
**second** field. The harness reports case by case when a payload cannot find its argument
block under that dispatch, and its exit code mirrors the per-case verdicts.
"""

from __future__ import annotations

import json
import pathlib
import subprocess
import sys

REPO = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO))

HARNESS = REPO / 'tests/harness/bootread_offline.c'
MODULE = REPO / 'native/target/ps4rf_bootread.c'
BUILD_DIR = pathlib.Path.home() / '.hermes/cache/scratch/ps4rf-w11/test-harness'

CASES = ('A', 'B', 'C', 'D', 'E', 'F', 'G', 'H')


def _build_harness() -> pathlib.Path:
    BUILD_DIR.mkdir(parents=True, exist_ok=True)
    binary = BUILD_DIR / 'bootread_offline'
    units = [HARNESS, MODULE, REPO / 'native/src/jcs.c']
    result = subprocess.run(
        ['gcc', '-std=c11', '-Os', '-Wall', '-Wextra', '-Wno-unused-parameter',
         '-I', str(REPO / 'native/target'), '-I', str(REPO / 'native/src'),
         '-o', str(binary), *[str(u) for u in units]],
        capture_output=True, text=True)
    assert result.returncode == 0, f'harness build failed:\n{result.stderr}'
    return binary


def _diagnosis(cases: dict, run: subprocess.CompletedProcess) -> str:
    """The failure text names the per-case evidence and the one structural cause the harness
    can detect: an argument structure that does not match the console syscall-11 wrapper."""
    parts = ['W11.2 offline boot-read cases failed:']
    for letter in CASES:
        case = cases.get(letter)
        if case is not None and case.get('pass'):
            continue
        if case is None:
            parts.append(f'  case {letter}: no case object was emitted')
        else:
            parts.append(f"  case {letter} ({case['name']}): expected {case['expected']!r}")
            parts.append(f"      observed {case['observed']!r}")
    parts += [
        '',
        'The harness drives the live-verified console dispatch: the kernel builds '
        '{ syscall_handler; payload } and calls the payload with a pointer to it, so the',
        "caller's argument block sits in the wrapper's SECOND field (offset 8). A case failing "
        'with run=4(RESULT_INVALID) and zero reads means',
        'the callback never reached its argument block: struct ps4rf_bootread_args reads the '
        'caller pointer at offset 0, where the',
        'console wrapper carries syscall_handler -- compare ps4rf_attest.h, whose args struct '
        'carries void *syscall_handler first.',
        'With that one field added to the boot-read args struct the same harness reports all '
        'eight cases pass; the harness itself needs no change.',
        f'exit code: {run.returncode}',
    ]
    return '\n'.join(parts)


def test_offline_harness_exercises_the_production_callback():
    binary = _build_harness()
    run = subprocess.run([str(binary)], capture_output=True, text=True)
    assert run.stdout.strip(), f'harness produced no stdout:\n{run.stderr}'
    lines = [json.loads(line) for line in run.stdout.splitlines() if line.startswith('{')]
    case_lines = [line for line in lines if 'case' in line]
    cases = {case['case']: case for case in case_lines}
    assert set(cases) == set(CASES), f'expected cases {CASES}, got {sorted(cases)}'
    for letter in CASES:
        assert set(cases[letter]) == {'case', 'name', 'expected', 'observed', 'pass'}, \
            f'case {letter} does not carry the mandated JSON fields'
    assert lines[-1]['suite'] == 'w11_2_bootread_offline'

    failed = [letter for letter in CASES if not cases[letter]['pass']]
    assert not failed, _diagnosis(cases, run)

    # the contract, per case (reached only when every case passed)
    assert run.returncode == 0
    assert lines[-1]['cases_failed'] == 0
    # A: the one correct measurement, decoded from the synthetic image
    a = cases['A']['observed']
    assert 'run=0(OK)' in a and 'read_len=16' in a and 'cross=MATCH' in a
    assert 'validation=OK' in a and 'reads=16' in a
    # B-E: each refusal rule, on the exact validation string
    assert 'TV_SEC_NONPOSITIVE' in cases['B']['observed']
    assert 'TV_USEC_NEGATIVE' in cases['C']['observed']
    assert 'TV_USEC_OUT_OF_RANGE' in cases['D']['observed']
    assert 'BOOT_TIME_AFTER_WALL_CLOCK' in cases['E']['observed']
    assert 'run=6(BOOT_TIME_IMPLAUSIBLE)' in cases['E']['observed']
    # F/G: the callback stops with zero bytes read
    assert 'LSTAR_SHAPE_INVALID' in cases['F']['observed'] and 'reads=0' in cases['F']['observed']
    assert 'KBASE_CROSS_CHECK_MISMATCH' in cases['G']['observed']
    assert 'reads=0' in cases['G']['observed']
    # H: a second call after a successful run is refused without any kernel traffic
    h = cases['H']['observed']
    assert 'second_call=1(SECOND_CALL_REFUSED)' in h and 'reads_delta=0' in h
    assert 'kexec_calls_delta=0' in h
