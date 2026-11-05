"""W12 offline tests: the bounded kernel.read provider, its generator and its harness.

The harness test compiles and runs ``tests/harness/kread_offline.c``, which links the
production module (``native/target/ps4rf_kread.c``) and replaces only its two leaf operations
(synthetic LSTAR read, synthetic byte read) plus the two SDK entry points (``kexec``,
``get_kernel_base``) with a synthetic kernel -- everything in between is the code that runs on
the console: the argument-block check, the caller marker, the full request validation (region
index, max length, 32 bit checked add, region containment), the LSTAR shape gate, the kbase
cross check, the canonical resolved runtime VA, the one-shot guard and the bounded copy.

Two contract shapes are checked from the outside:

* the dispatch ABI. The console builds ``{ void *syscall_handler; payload }`` and calls the
  callback with a pointer to that wrapper, so the caller's block sits in the **second** field
  (offset 8). The harness dispatches exactly that way, and it carries a counter-proof build
  (``-DPS4RF_KREAD_HARNESS_MUTANT_HOST_ABI``) that puts the block in the first field instead:
  the production callback must refuse it, which is what proves the passing run is not vacuous.
* no kernel write on any path. The wrapper's first field points at a harness-owned block; on
  the console that field *is* kernel memory. Case J points it at a decoy that carries a valid
  caller marker, so a wrong-ABI callback would write a status word there -- the case proves the
  decoy is byte-identical after the dispatch, and every case sha256-hashes the simulated kernel
  image before and after the call.

The generator tests cover the refusal rules (hermetically, via ``--self-test``), the drift gate
(``--check`` against a fresh generation) and the PROVISIONAL bootstrap fallback.
"""

from __future__ import annotations

import hashlib
import importlib.util
import json
import pathlib
import re
import subprocess
import sys

REPO = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO))

HARNESS = REPO / 'tests/harness/kread_offline.c'
MODULE = REPO / 'native/target/ps4rf_kread.c'
GENERATOR = REPO / 'native/target/gen_kread_regions.py'
REGIONS_H = REPO / 'native/target/ps4rf_kread_regions.h'
BOOTSTRAP = REPO / 'native/target/ps4rf_kread_regions_bootstrap.py'
CANONICAL = REPO / 'tools/profiles/regions.py'
BUILD_DIR = pathlib.Path.home() / '.hermes/cache/scratch/ps4rf-w12/test-harness'

CASES = ('A', 'B', 'C', 'D', 'E', 'E2', 'F', 'G', 'H', 'I', 'J', 'B2', 'D2', 'E3', 'K', 'L', 'M',
         'N', 'N2', 'O', 'P', 'Q')
REFUSAL_CASES = ('B', 'C', 'D', 'E', 'E2', 'P', 'Q')
INDEX_REFUSAL_CASES = ('N', 'N2')


def _build_harness(flags: tuple[str, ...] = (), binary_name: str = 'kread_offline'):
    BUILD_DIR.mkdir(parents=True, exist_ok=True)
    binary = BUILD_DIR / binary_name
    units = [HARNESS, MODULE, REPO / 'native/src/jcs.c', REPO / 'native/src/sha256.c']
    result = subprocess.run(
        ['gcc', '-std=c11', '-O1', '-Wall', '-Wextra', '-Wno-unused-parameter', *flags,
         '-I', str(REPO / 'native/target'), '-I', str(REPO / 'native/src'),
         '-o', str(binary), *[str(u) for u in units]],
        capture_output=True, text=True)
    assert result.returncode == 0, f'harness build failed:\n{result.stderr}'
    assert not result.stderr.strip(), f'harness build emitted warnings:\n{result.stderr}'
    return binary


def _observer(binary: pathlib.Path):
    run = subprocess.run([str(binary)], capture_output=True, text=True)
    assert run.stdout.strip(), f'harness produced no stdout:\n{run.stderr}'
    lines = [json.loads(line) for line in run.stdout.splitlines() if line.startswith('{')]
    case_lines = [line for line in lines if 'case' in line]
    cases = {case['case']: case for case in case_lines}
    return cases, lines, run


def _counts(observed: str) -> dict:
    out = {}
    for key in ('reads', 'msr', 'kexec', 'dispatch', 'kernel_mem_writes'):
        match = re.search(rf'\b{key}=(-?\d+)', observed)
        out[key] = int(match.group(1)) if match else None
    return out


def _diagnosis(cases: dict, run: subprocess.CompletedProcess) -> str:
    parts = ['W12 offline kernel.read cases failed:']
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
        'The harness drives the live-verified console dispatch: the kernel builds',
        '{ syscall_handler; payload } and calls the payload with a pointer to the wrapper, so the',
        "caller's argument block sits in the wrapper's SECOND field (offset 8). A failing case",
        'with cb=MAGIC / run=RESULT_INVALID and zero reads means the callback never found its',
        'argument block: struct ps4rf_kread_args must carry `void *syscall_handler;` first',
        '(compare ps4rf_attest.h and W11.2). Case J additionally fails when a callback writes a',
        'status word into the wrapper field-0 decoy -- that is the console kernel write.',
        f'exit code: {run.returncode}',
    ]
    return '\n'.join(parts)


def test_offline_harness_exercises_the_production_callback():
    binary = _build_harness()
    cases, lines, run = _observer(binary)
    assert set(cases) == set(CASES), f'expected cases {CASES}, got {sorted(cases)}'
    for letter in CASES:
        assert set(cases[letter]) == {'case', 'name', 'expected', 'observed', 'pass'}, \
            f'case {letter} does not carry the mandated JSON fields'
    assert lines[-1]['suite'] == 'w12_kread_offline'

    failed = [letter for letter in CASES if not cases[letter]['pass']]
    assert not failed, _diagnosis(cases, run)
    assert run.returncode == 0
    assert lines[-1]['cases_failed'] == 0

    # A: the one happy path -- exact bytes, one callback, one LSTAR read, zero writes
    a = cases['A']['observed']
    assert 'run=0(OK)' in a and 'cb=0(OK)' in a and 'copied=16' in a
    assert 'reads=16' in a and 'msr=1' in a and 'kexec=1' in a and 'dispatch=1' in a
    assert 'flags=0xf' in a and 'cross=MATCH' in a and 'kernel_mem_writes=0' in a
    # B-E2: every refusal is pre-kernel: no read, no MSR, no kexec
    for letter in REFUSAL_CASES:
        observed = cases[letter]['observed']
        assert 'run=5(REQUEST_REFUSED)' in observed, observed
        assert _counts(observed) == {'reads': 0, 'msr': 0, 'kexec': 0, 'dispatch': 0,
                                     'kernel_mem_writes': 0}, observed
    # F/G: the callback stops before the first byte read
    assert 'LSTAR_SHAPE_INVALID' in cases['F']['observed']
    assert 'reads=0' in cases['F']['observed'] and 'msr=1' in cases['F']['observed']
    assert 'KBASE_CROSS_CHECK_MISMATCH' in cases['G']['observed']
    assert 'reads=0' in cases['G']['observed']
    # H/I: the one-shot guard, with zero deltas on a host retry
    for letter in ('H', 'I'):
        observed = cases[letter]['observed']
        assert 'second=1(SECOND_CALL_REFUSED)' in observed, observed
        assert 'third=1(SECOND_CALL_REFUSED)' in observed, observed
        assert 'reads_delta=0' in observed and 'msr_delta=0' in observed
        assert 'kexec_delta=0' in observed and 'dispatch_delta=0' in observed
    assert 'first=0(OK)' in cases['H']['observed']
    assert 'first=5(REQUEST_REFUSED)' in cases['I']['observed']
    # J: the ABI decoy -- a wrong-ABI callback would have written into it
    j = cases['J']['observed']
    assert 'decoy_write=0' in j and 'kernel_writes=0' in j and 'cb=0(OK)' in j
    # B2/D2/E3: the callback's own refusals, before the LSTAR read
    assert 'cb=4(LENGTH_INVALID)' in cases['B2']['observed']
    assert 'cb=5(OFFSET_OVERFLOW)' in cases['D2']['observed']
    assert 'cb=6(CROSS_REGION_REFUSED)' in cases['E3']['observed']
    for letter in ('B2', 'D2', 'E3'):
        assert _counts(cases[letter]['observed'])['msr'] == 0
    # K/L: the write scans
    assert 'kernel_mem_writes=0' in cases['K']['observed'] and 'cage=OK' in cases['K']['observed']
    assert 'canary=OK' in cases['K']['observed'] and 'sim=OK' in cases['K']['observed']
    assert 'kernel_mem_writes=0' in cases['L']['observed']
    # M: a read that ends exactly at the region end is still legal
    assert 'run=0(OK)' in cases['M']['observed'] and 'copied=8' in cases['M']['observed']
    # W13-C1: the request names the row -- the index is validated by the provider itself
    for letter in INDEX_REFUSAL_CASES:
        observed = cases[letter]['observed']
        assert 'run=6(KREAD_REGION_INDEX_INVALID)' in observed, observed
        assert 'cb=255(NOT_RUN)' in observed, observed
        assert _counts(observed) == {'reads': 0, 'msr': 0, 'kexec': 0, 'dispatch': 0,
                                     'kernel_mem_writes': 0}, observed
        assert 'writes=0' in observed
    # the released amd_iommu row (index 1) is read end to end on the production path
    o = cases['O']['observed']
    assert 'run=0(OK)' in o and 'cb=0(OK)' in o and 'copied=16' in o, o
    assert 'region=amd_iommu' in o and 'idx=1' in o, o
    assert 'rva=0x7ce9e9' in o and 'len=16' in o, o
    assert 'reads=16' in o and 'kexec=1' in o and 'dispatch=1' in o, o
    assert 'kernel_mem_writes=0' in o and 'cage=OK' in o and 'sha256_status=MEASURED' in o, o
    # containment is owned by the row that was named, not by region 0
    for letter in ('P', 'Q'):
        observed = cases[letter]['observed']
        assert 'run=5(REQUEST_REFUSED)' in observed, observed
        assert _counts(observed) == {'reads': 0, 'msr': 0, 'kexec': 0, 'dispatch': 0,
                                     'kernel_mem_writes': 0}, observed
        assert 'region=amd_iommu' in observed and 'idx=1' in observed, observed
    # index 0 is still image_elf: the table order did not move
    a = cases['A']['observed']
    assert 'region0=image_elf' in a and 'region=image_elf' in a and 'idx=0' in a, a


def test_valid_read_sha256_matches_an_independent_measurement():
    """The sha256 the payload reports must equal python's hash of the same bytes."""
    binary = _build_harness()
    cases, _lines, _run = _observer(binary)
    for letter in ('A', 'K', 'M'):
        observed = cases[letter]['observed']
        bytes_match = re.search(r'\bbytes=([0-9a-f]+)', observed)
        sha_match = re.search(r'\bsha256=([0-9a-f]{64})', observed)
        assert bytes_match is not None and sha_match is not None, observed
        assert hashlib.sha256(bytes.fromhex(bytes_match.group(1))).hexdigest() == \
            sha_match.group(1), f'case {letter}: the payload sha256 does not match the bytes'


def test_misread_dispatch_cannot_go_unnoticed():
    """Counter-proof: with the payload block in the wrapper's FIRST field (the host-ABI
    assumption the console does not satisfy) the production callback must refuse, and the
    harness must report it -- a passing default build therefore is not vacuous."""
    binary = _build_harness(('-DPS4RF_KREAD_HARNESS_MUTANT_HOST_ABI',),
                            binary_name='kread_offline_mutant_host_abi')
    cases, lines, run = _observer(binary)
    assert lines[-1]['cases_failed'] != 0, 'the misread dispatch was not detected'
    assert not cases['A']['pass'], 'case A passed under a dispatch the console never produces'
    assert not cases['J']['pass'], 'the decoy case must fail when field 0 is taken as the block'
    assert run.returncode != 0
    # and even then not one byte may land in the wrapper field-0 decoy (the console kernel write)
    assert 'decoy_write=1' not in json.dumps(cases), \
        'a byte was written into the wrapper field-0 decoy under the misread dispatch'


def test_generator_refusal_rules():
    result = subprocess.run([sys.executable, str(GENERATOR), '--self-test'],
                            capture_output=True, text=True)
    assert result.returncode == 0, result.stdout + result.stderr
    assert '0 problem(s)' in result.stdout


def test_generated_region_table_has_no_drift():
    result = subprocess.run([sys.executable, str(GENERATOR), '--check'],
                            capture_output=True, text=True)
    assert result.returncode == 0, result.stdout + result.stderr
    assert CANONICAL.name in result.stdout
    text = REGIONS_H.read_text()
    assert 'PROVISIONAL' not in text, 'the checked-in table must come from the canonical registry'
    assert 'tools/profiles/regions.py' in text
    assert 'UNRESOLVED entries refused by the generator' in text


def test_generator_detects_drift_and_refuses_unresolved():
    """A drifted header fails the gate; the PROVISIONAL bootstrap still generates, and every
    value it carries agrees with the canonical registry (a subset, never a contradiction)."""
    import tempfile

    with tempfile.TemporaryDirectory() as tmp:
        drifted = pathlib.Path(tmp) / 'regions.h'
        write = subprocess.run([sys.executable, str(GENERATOR), '--write', '--out', str(drifted)],
                               capture_output=True, text=True)
        assert write.returncode == 0, write.stdout + write.stderr
        check = subprocess.run([sys.executable, str(GENERATOR), '--check', '--out', str(drifted)],
                               capture_output=True, text=True)
        assert check.returncode == 0, check.stdout + check.stderr
        drifted.write_text(drifted.read_text().replace('PS4RF_KREAD_MAX_LEN', 'PS4RF_KREAD_MAX'))
        broken = subprocess.run([sys.executable, str(GENERATOR), '--check', '--out', str(drifted)],
                                capture_output=True, text=True)
        assert broken.returncode != 0 and 'drift' in broken.stderr, broken.stdout + broken.stderr

    provisional = subprocess.run(
        [sys.executable, str(GENERATOR), '--write', '--out',
         str(pathlib.Path(tempfile.mkdtemp()) / 'bootstrap.h'), '--registry', str(BOOTSTRAP)],
        capture_output=True, text=True)
    assert provisional.returncode == 0, provisional.stdout + provisional.stderr
    assert 'PROVISIONAL' in provisional.stdout
    canonical = subprocess.run(
        [sys.executable, str(GENERATOR), '--write', '--out',
         str(pathlib.Path(tempfile.mkdtemp()) / 'canonical.h'), '--registry', str(CANONICAL)],
        capture_output=True, text=True)
    assert canonical.returncode == 0, canonical.stdout + canonical.stderr
    assert 'PROVISIONAL' not in canonical.stdout


def test_request_side_carries_no_address_field():
    """The payload's request half may carry region index, offset and length -- never an
    address. The resolved runtime VA is written by the callback and read by the evidence
    builder only."""
    header = (REPO / 'native/target/ps4rf_kread.h').read_text()
    struct_match = re.search(r'typedef struct \{(.*?)\} ps4rf_kread_info;', header, re.S)
    assert struct_match is not None, 'ps4rf_kread_info not found'
    in_block = struct_match.group(1)
    request_fields = [line for line in in_block.splitlines() if '/* in ' in line]
    names = []
    for line in request_fields:
        field = re.match(r'\s*\S+\s*\**(\w+);', line)
        assert field is not None, line
        names.append(field.group(1))
    assert names == ['magic_in', 'region_index', 'offset', 'length', 'kbase_sdk'], names
    for name in names:
        assert not re.search(r'addr|address|pointer|\bptr\b|\bva\b', name), name
    source = (REPO / 'native/target/ps4rf_kread.c').read_text()
    callback = source.split('int ps4rf_kread_kpayload', 1)[1].split('\nint ps4rf_kread_', 1)[0]
    assert 'args->syscall_handler' not in callback, \
        'the callback must never read the wrapper field that carries kernel state'
    assert 'resolved_runtime_va' in callback and 'resolved_runtime_va = address' in callback
