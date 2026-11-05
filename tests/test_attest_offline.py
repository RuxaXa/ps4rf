"""W9 offline tests: the attestation table, the fail-closed callback harness, the host-side
verification, and the frozen-sequence compatibility of the W9 session shape.

The harness test compiles and runs ``tests/harness/attest_offline.c``, which links the
production callback and replaces only its two leaf operations (MSR read, byte read) plus the
two SDK entry points -- the code in between is the code that runs on the console.
"""

from __future__ import annotations

import json
import pathlib
import subprocess
import sys

REPO = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO))

from tools.hostctl import attest  # noqa: E402
from tools.hostctl import smoke  # noqa: E402
from tools.primitive_iface import schema as SCHEMA

HARNESS = REPO / 'tests/harness/attest_offline.c'
TABLE = REPO / 'native/target/ps4rf_attest_data.h'
BUILD_DIR = pathlib.Path.home() / '.hermes/cache/scratch/ps4rf-w9/test-harness'


def _build_harness() -> pathlib.Path:
    BUILD_DIR.mkdir(parents=True, exist_ok=True)
    binary = BUILD_DIR / 'attest_offline'
    units = [HARNESS, REPO / 'native/target/ps4rf_attest.c', REPO / 'native/src/ps4rf_protocol.c',
             REPO / 'native/src/jcs.c', REPO / 'native/src/sha256.c',
             REPO / 'native/src/chacha20poly1305.c']
    result = subprocess.run(
        ['gcc', '-std=c11', '-Os', '-Wall', '-Wextra', '-Wno-unused-parameter',
         '-I', str(REPO / 'native/target'), '-I', str(REPO / 'native/src'),
         '-o', str(binary), *[str(u) for u in units]],
        capture_output=True, text=True)
    assert result.returncode == 0, f'harness build failed:\n{result.stderr}'
    return binary


def test_offline_harness_exercises_the_production_callback():
    binary = _build_harness()
    run = subprocess.run([str(binary)], capture_output=True, text=True)
    assert run.returncode == 0, f'{run.stdout}\n{run.stderr}'
    lines = [json.loads(line) for line in run.stdout.splitlines() if line.startswith('{')]
    cases = {case['case']: case for case in lines if 'case' in case}
    assert set(cases) == {'clean_measurement', 'strict_window_changed_amd_iommu',
                          'corrupted_image_identity', 'structural_only_changed_aperture',
                          'lstar_wrong_shape', 'caller_marker_missing'}
    clean = cases['clean_measurement']
    # never "8/8": 7 strict fingerprints plus 1 structural observation
    assert clean['run_status'] == 0 and clean['event_status'] == 'OK'
    assert clean['strict_matches'] == 7 and clean['strict_mismatches'] == 0
    assert clean['structural_observations'] == 1
    assert clean['reads'] == 104 and clean['kbase_cross'] == 'MATCH'
    # a failed STRICT_FINGERPRINT stops the run instead of being reported as a footnote
    assert cases['strict_window_changed_amd_iommu']['run_status'] == 3
    assert cases['strict_window_changed_amd_iommu']['strict_mismatches'] == 1
    # a changed STRUCTURAL_ONLY window keeps the attestation valid and is documented instead
    structural = cases['structural_only_changed_aperture']
    assert structural['run_status'] == 0 and structural['event_status'] == 'OK'
    assert structural['strict_matches'] == 7 and structural['strict_mismatches'] == 0
    assert structural['structural_observations'] == 1
    assert structural['structural_status'] == 3            # STRUCT_BAD: recorded, not a failure
    assert structural['reads'] == 104
    # the image identity gates the measurement: only the first window is read
    assert cases['corrupted_image_identity']['reads'] == 16
    # an LSTAR of the wrong shape reads no kernel byte at all
    assert cases['lstar_wrong_shape']['reads'] == 0
    assert cases['lstar_wrong_shape']['cb_status'] == 3
    # a missing caller marker refuses before the measurement
    assert cases['caller_marker_missing']['cb_status'] == 2
    assert lines[-1]['scenarios_failed'] == 0


def test_generated_table_matches_the_pinned_evidence_shape():
    rows = attest.parse_expected_table(TABLE)
    assert len(rows) == 8, f'expected 8 entries, parsed {len(rows)}'
    by_id = {row['id']: row for row in rows}
    assert by_id['xfast_entry']['rva'] == 0x1C0, 'LSTAR must point at the xfast entry'
    assert by_id['image_elf']['rva'] == 0 and by_id['image_elf']['expected'][:4] == b'\x7fELF'
    assert by_id['amd_iommu']['expected'].startswith(b'AMD IOMMU')
    assert by_id['gbase_vtophys']['expected'].startswith(b'gbase_vtophys')
    assert by_id['code_anchor']['expected'][:4] == b'\x55\x48\x89\xe5'
    assert by_id['prison0_static']['kind'] == 'relocated'
    assert by_id['aperture_global']['kind'] == 'structural'
    assert len(by_id['code_anchor']['expected']) == 24
    # the window policy is machine readable, one of exactly two values, one per window
    strict = [row['id'] for row in rows if row['policy'] == 'STRICT_FINGERPRINT']
    structural = [row['id'] for row in rows if row['policy'] == 'STRUCTURAL_ONLY']
    assert len(strict) == 7 and len(structural) == 1
    assert structural == ['aperture_global'], 'only the documented aperture window is structural'
    assert len(strict) + len(structural) == 8
    for row in rows:
        assert row['policy'] in ('STRICT_FINGERPRINT', 'STRUCTURAL_ONLY')
        assert row['strict'] == (row['policy'] == 'STRICT_FINGERPRINT')


def test_manifest_carries_the_window_policy_when_a_build_exists():
    """The built manifest records the policy per window, machine readable."""
    build_manifest = __import__('importlib').import_module('importlib.util')
    import importlib.util as iu
    spec = iu.spec_from_file_location('bm', REPO / 'native/target/build_manifest.py')
    bm = iu.module_from_spec(spec)
    spec.loader.exec_module(bm)
    rows = bm.parse_attest_table(TABLE)
    by_id = {row[0]: row for row in rows}
    assert by_id['aperture_global'][4] == 'STRUCTURAL_ONLY'
    assert sum(1 for row in rows if row[4] == 'STRICT_FINGERPRINT') == 7
    manifest = pathlib.Path.home() / '.hermes/cache/scratch/ps4rf-w9/target-ps4/build_manifest.json'
    if manifest.exists():
        data = json.loads(manifest.read_text())
        windows = data['gates']['attestation']['windows']
        assert len(windows) == 8
        aperture = [w for w in windows if w['id'] == 'aperture_global'][0]
        assert aperture['policy'] == 'STRUCTURAL_ONLY'
        assert aperture['counts_towards_strict_score'] is False
        assert aperture['observed_required_to_equal_expected'] is False
        assert data['gates']['attestation']['policy_counts'] == {
            'STRICT_FINGERPRINT': 7, 'STRUCTURAL_ONLY': 1}


def test_host_verification_rejects_payload_claims_that_do_not_match_the_bytes():
    rows = attest.parse_expected_table(TABLE)
    kbase = 0xFFFFFFFFA2B30000
    slide = (kbase - attest.STATIC_BASE) & 0xFFFFFFFFFFFFFFFF

    def observed_for(row: dict) -> bytes:
        """What the live kernel would return: relocated pointers carry the slide."""
        if row['kind'] == 'relocated':
            value = (int.from_bytes(row['expected'], 'little') + slide) & 0xFFFFFFFFFFFFFFFF
            return value.to_bytes(8, 'little')
        return row['expected']

    event = {
        'event': 'kernel.attestation', 'status': 'OK', 'callback_executed': True,
        'kexec_rc': 0, 'lstar': f'0x{kbase + 0x1C0:x}', 'kbase_candidate': f'0x{kbase:x}',
        'kbase_sdk': f'0x{kbase:x}', 'kbase_slide': f'0x{slide:x}',
        'entry_count': 8, 'read_count': 8, 'strict_matches': 7, 'strict_mismatches': 0,
        'structural_observations': 1,
        'entries': [{'id': row['id'],
                     'policy': row['policy'],
                     'exact_match_claim': row['strict'],
                     'status': 'STRUCT_OK' if row['kind'] == 'structural' else 'MATCH',
                     'observed': observed_for(row).hex()} for row in rows],
    }
    report = attest.verify_attestation(event, rows)
    assert report['verified'], report['problems']
    # the score is the strict windows only; the structural window is an observation
    assert report['strict_matches'] == '7/7' and report['strict_total'] == 7
    assert report['strict_mismatches'] == 0 and report['structural_observations'] == 1
    assert all(row['id'] != 'aperture_global' for row in report['strict_rows'])
    assert [row['id'] for row in report['structural_results']] == ['aperture_global']
    assert report['structural_results'][0]['counts_towards_strict_score'] is False
    assert 'aperture_global' in report['profile_evidence_basis']['structural_only_excluded']

    # the payload's own status is not trusted: a claim that contradicts the bytes is a failure
    tampered = json.loads(json.dumps(event))
    tampered['entries'][1]['observed'] = 'ff' * rows[1]['len']
    tampered['entries'][1]['status'] = 'MATCH'
    report = attest.verify_attestation(tampered, rows)
    assert not report['verified']
    assert any('payload says' in problem for problem in report['problems'])

    # a callback that never ran must not produce measurements
    none_ran = dict(event, callback_executed=False, entries=[], read_count=0)
    report = attest.verify_attestation(none_ran, rows)
    assert not report['verified']
    assert 'did not run' in report['problems'][0]

    # STRUCTURAL_ONLY, regression 1: changed bytes keep the attestation valid and are recorded
    structural_changed = json.loads(json.dumps(event))
    aperture = [e for e in structural_changed['entries'] if e['id'] == 'aperture_global'][0]
    aperture['observed'] = 'ff' * 8                     # out of range on purpose
    aperture['status'] = 'STRUCT_BAD'
    report = attest.verify_attestation(structural_changed, rows)
    assert report['verified'], report['problems']
    assert report['strict_matches'] == '7/7' and report['strict_mismatches'] == 0
    assert report['structural_results'][0]['observation'] == 'STRUCT_BAD'
    assert report['structural_observations'] == 1

    # STRUCTURAL_ONLY, regression 3: it must never be counted or presented as an exact match
    claimed_exact = json.loads(json.dumps(event))
    claimed = [e for e in claimed_exact['entries'] if e['id'] == 'aperture_global'][0]
    claimed['exact_match_claim'] = True
    report = attest.verify_attestation(claimed_exact, rows)
    assert not report['verified']
    assert any('presented as an exact match' in problem for problem in report['problems'])

    # STRUCTURAL_ONLY, regression 2 (strict): a STRICT_FINGERPRINT change is a mismatch and
    # therefore a stop, and the score drops accordingly
    strict_changed = json.loads(json.dumps(event))
    strict_changed['entries'][2]['observed'] = '00' * rows[2]['len']
    strict_changed['entries'][2]['status'] = 'MATCH'
    strict_changed['strict_matches'] = 6
    report = attest.verify_attestation(strict_changed, rows)
    assert not report['verified']
    assert report['strict_mismatches'] == 1 and report['strict_matches'] == '6/7'
    assert any('STRICT_FINGERPRINT window(s) mismatch' in problem
               for problem in report['problems'])


def test_w9_sequence_keeps_the_frozen_wire_and_sends_no_privileged_arguments():
    steps = smoke.sequence_w9()
    assert [step.op for step in steps] == ['session.status', 'session.status']
    for step in steps:
        # the host sends no address, no flag, no trigger for the privileged step
        assert step.arguments == {}
    # the frozen registry is untouched by W9: the attestation is not an operation
    from core.rpc.registry import default_registry
    registry = default_registry()
    names = set(registry._specs)                       # the frozen table itself
    assert 'kernel.attestation' not in names, 'W9 must not add a privileged operation'
    assert len(names) == len(SCHEMA.OPS)
    # and the W9 inbound set is the W8 set plus exactly one documented control frame
    from tools.hostctl.session import HOST_INBOUND_W8, HOST_INBOUND_W9
    assert set(HOST_INBOUND_W9) - set(HOST_INBOUND_W8) == {'EVENT'}
