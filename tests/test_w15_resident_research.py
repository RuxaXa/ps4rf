"""W15 -- the resident research rehearsal (A/B/C), proved offline against the real daemon.

What is exercised: `tools/hostctl/live_w15.py` drives one agent lifetime through a verification
session, a plain session, a research session (one bounded read of `amd_iommu`, compiled index 1,
offset 0, length 16) and a final session that must refuse the *consumed* release and then shut the
agent down through the authenticated admin operation.

What is *not* simulated: the daemon (the same C source as the console build, linked against the
simulated kernel image of `tests/harness/ps4rf_kread_sim.c`), the wire request, the target's own
bounds/containment/LSTAR checks, the event, the store, the derivation, the one-shot consumption and
every host-side check. What is simulated is the kernel underneath the read: the image is seeded with
the profile's pinned bytes for the two windows the run touches, so a wrong window reads the pattern
and the verification refuses -- the failure mode is closed, not open.
"""
from __future__ import annotations

import hashlib
import json
import os
import pathlib
import socket
import subprocess
import sys
import time

import pytest

REPO = pathlib.Path(__file__).resolve().parents[1]
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))

from tools.hostctl import live_w15 as W15                                        # noqa: E402
from tools.research import classification as C                                   # noqa: E402
from tools.research import dataset as DATASET                                    # noqa: E402
from tools.research import w6_contract as W6                                     # noqa: E402

SCRATCH = pathlib.Path.home() / '.hermes' / 'cache' / 'scratch' / 'ps4rf-w15'
REHEARSAL_HOST = SCRATCH / 'rehearsal-host' / 'ps4rfd_host'
PSK = bytes(range(33, 65))                     # the W15 rehearsal PSK, never the W14 one
PSK_FILE = SCRATCH / 'psk-rehearsal.bin'
#: The daemon compiles PS4RF_KREAD_REGION_COUNT and its own region table into the event it
#: reports, so the cached rehearsal binary is only valid for the header it was built from. The
#: cache key is that header's hash: a table change (W16 added six regions) rebuilds instead of
#: letting a stale binary report an older count and fail the rehearsal for the wrong reason.
REGIONS_HEADER = REPO / 'native' / 'target' / 'ps4rf_kread_regions.h'
PROFILE = C.DEFAULT_PROFILE
#: the payload binding the fixtures name: the W15 console artefact (the live run's identity)
# the final W15 console artefact, built from commit de56363 (label ps4rfd-live-w15, context
# fw13-52-resident-w15): build id fcf439438e5321271c44a68a6bc2fec2, reproducible twice
PAYLOAD = {'bin_sha256': '2021205c8d8a4e680bceefc73223122bb41e1e2f20b3ec7bd01e725220801328',
           'elf_sha256': '9c106470f2acd903ae5b816d172705c7b8cef0153002ef370c07e47b7b7dd18f',
           'build_manifest_sha256': 'cd9615099d5adbffe87cf89e3b687c1fbc93d2d1b68ca7217faf6e087f3dfc94',
           'build_id': 'fcf439438e5321271c44a68a6bc2fec2', 'label': 'ps4rfd-live-w15'}


def free_port() -> int:
    probe = socket.socket()
    probe.bind(('127.0.0.1', 0))
    port = probe.getsockname()[1]
    probe.close()
    return port


@pytest.fixture(scope='session')
def rehearsal_host() -> pathlib.Path:
    """The dev-host daemon with the simulated kernel image, cached per region-table revision."""
    stamp = hashlib.sha256(REGIONS_HEADER.read_bytes()).hexdigest()[:12]
    cached = REHEARSAL_HOST.parent.parent / f'rehearsal-host-{stamp}' / 'ps4rfd_host'
    if not cached.exists():
        env = dict(os.environ, PS4RF_TARGET_KREAD='1', PS4RF_TARGET_KREAD_SIM='1')
        done = subprocess.run(['sh', str(REPO / 'native/target/build_host.sh'),
                               str(cached.parent)], env=env, capture_output=True, text=True,
                              timeout=600)
        assert done.returncode == 0, (done.stdout[-2000:], done.stderr[-2000:])
    assert cached.exists()
    return cached


def _run(tmp_path: pathlib.Path, host: pathlib.Path, *, gap: float = 0.0,
         silent: float = 3.0) -> dict:
    tmp_path.mkdir(parents=True, exist_ok=True)
    psk_file = tmp_path / 'psk.bin'
    psk_file.write_bytes(PSK)
    seed = W15.seed_file(tmp_path / 'seed.txt', W15.profile_windows(PROFILE))
    trace = tmp_path / 'sim-trace.json'
    port = free_port()
    out = tmp_path / 'evidence'
    out.mkdir()
    controller = subprocess.Popen(
        [sys.executable, str(REPO / 'tools' / 'hostctl' / 'live_w15.py'), '--listen', '127.0.0.1',
         '--port', str(port), '--psk-file', str(psk_file), '--out', str(out),
         '--store', str(tmp_path / 'store'), '--no-redial-sec', str(silent), '--no-health',
         '--gap-sec', str(gap), '--payload-bin', PAYLOAD['bin_sha256'], '--payload-elf',
         PAYLOAD['elf_sha256'], '--payload-manifest', PAYLOAD['build_manifest_sha256'],
         '--payload-build-id', PAYLOAD['build_id'], '--payload-label', PAYLOAD['label']],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

    deadline = time.monotonic() + 20.0
    while time.monotonic() < deadline:
        probe = socket.socket()
        try:
            probe.bind(('127.0.0.1', port))
        except OSError:
            probe.close()
            break
        probe.close()
        time.sleep(0.05)
    else:
        controller.kill()
        raise AssertionError('the W15 rehearsal controller never opened its listener')

    driver = subprocess.Popen(
        [str(host), '--resident', '--connect', '127.0.0.1', str(port), '--psk-file', str(psk_file),
         '--sessions', '0', '--idle-rounds', '0', '--idle-pause-ms', '250', '--backoff-max-ms',
         '2000', '--lifetime', '600', '--idle', '600', '--label', PAYLOAD['label'], '--context',
         'fw13-52-resident-w15'],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
        env={'PATH': '/usr/bin:/bin', 'PS4RF_KREAD_SIM_SEED': str(seed),
             'PS4RF_KREAD_SIM_TRACE': str(trace)})

    controller_out, controller_err = controller.communicate(timeout=300)
    if controller.returncode != 0:
        driver.kill()
        driver.communicate(timeout=30)
        raise AssertionError((controller_out[-3000:], controller_err[-2000:]))
    try:
        driver_out, driver_err = driver.communicate(timeout=120)
    except subprocess.TimeoutExpired:
        driver.kill()
        driver_out, driver_err = driver.communicate()
        raise AssertionError('the daemon did not end its run; the admin shutdown did not take '
                             f'effect (tail: {driver_out[-400:]!r})') from None
    evidence = json.loads((out / 'w15-resident-research-evidence.json').read_text())
    evidence['_driver_report'] = json.loads(driver_out.strip().splitlines()[-1])
    evidence['_driver_exit'] = driver.returncode
    evidence['_driver_stderr'] = driver_err[-400:]
    evidence['_sim_trace'] = json.loads(trace.read_text()) if trace.exists() else None
    evidence['_store'] = str(tmp_path / 'store')
    return evidence


def test_the_resident_research_rehearsal_passes(tmp_path, rehearsal_host):
    evidence = _run(tmp_path, rehearsal_host)
    assert evidence['verdict'] == 'PASS', evidence.get('stop_reason')
    steps = {step['step']: step for step in evidence['steps']}
    assert set(steps) == {'session_v_verification', 'session_a', 'session_b_research_read',
                          'session_c_isolation', 'after_admin_shutdown'}

    # --- the verification session persisted the evidence a later session leans on
    verification = steps['session_v_verification']['verification']
    assert verification['outcome'] in ('VERIFIED', 'PASS'), verification
    assert verification['evidence_sha256'] and verification['verification_run_id']

    # --- the read: exactly one provider entry, the pinned bytes and hash, the whole event
    read = steps['session_b_research_read']
    assert read['facts']['cleanup'] == {'resources': [], 'state': 'COMPLETE'}
    assert read['facts']['bye'] == 'CLIENT_CLOSE'
    research = read['research']
    assert research['provider_entries'] == 1, research.get('problems')
    assert research['outcome'] in ('READ', 'VERIFIED', 'PASS'), research.get('problems')
    report = research['event_report']
    assert report['verified'] is True and report['checks_failed'] == []
    assert report['region'] == 'amd_iommu'
    assert report['requested_region_index'] == 1, report
    # the host verifier re-derives these as integers (`kreadlive.parse_number`/`parse_address`);
    # the pinned compiled rva of the window is 0x7CE9E9
    assert report['region_rva'] == 0x7CE9E9, report
    assert report['offset'] == 0 and report['length'] == 16
    assert report['returned_length'] == 16
    assert str(report['bytes_hex']).lower() == research['window']['expected_bytes']
    assert str(report['output_sha256']).lower() == research['window']['expected_sha256']
    assert research['window']['expected_sha256'] == \
        '0e5db66bb6e045a242282881beb9525d80f00efdccd3586da7d2692e74d4cc5f'
    # the event also says what the payload never did
    claims = report['claims']
    for claimed in ('host_supplied_address', 'writes_to_kernel', 'retry'):
        assert claims.get(claimed) in (False, 0, 'false', '0'), (claimed, claims)
    assert claims.get('single_callback') in (True, 1, 'true', '1'), claims
    # ... and the callback really ran once, in the simulated dispatch
    assert report['callback_executed'] is True and report['cb_status_name'] == 'OK'
    assert report['cb_status'] == 0
    assert report['resolved_rva'] == 0x7CE9E9 \
        and report['resolved_runtime_va'] not in ('UNMEASURED', '', None)
    # the read is bound to the session it happened in and separated from its verification
    assert research['run_separation']['verification_run_id'] != research['read_run_id']

    # --- §5: the read is archived as exactly one dataset blob + one snapshot index entry
    dataset = research['dataset']
    blob_sha = research['window']['expected_sha256']
    assert dataset['blob']['sha256'] == blob_sha
    assert dataset['blob']['content_matches_record'] is True
    snapshot = dataset['snapshot']
    assert snapshot['sha256'] == blob_sha
    assert (snapshot['region'], snapshot['offset'], snapshot['length']) == ('amd_iommu', 0, 16)
    assert snapshot['profile_sha256'] == evidence['profile_sha256']
    assert snapshot['boot_id'] == evidence['boot_id']
    assert snapshot['kbase'] == hex(report['kbase'])
    assert snapshot['read_run_id'] == research['read_run_id']
    assert snapshot['timestamp'] and snapshot['snapshot_id'] and dataset['index_sha256']
    assert dataset['entries_before_ingest'] == 0 and dataset['entries_after_duplicate'] == 1
    assert dataset['blobs_before_ingest'] == 0 and dataset['blobs_after_duplicate'] == 1
    assert dataset['checks'] and all(dataset['checks'].values()), dataset['checks']
    assert dataset['duplicate']['added'] is False
    assert dataset['duplicate']['deduplicated'] is True
    assert dataset['duplicate']['no_second_blob'] is True
    assert dataset['duplicate']['no_duplicate_snapshot_row'] is True
    assert dataset['duplicate']['snapshot_id'] == dataset['snapshot_id']
    assert dataset['problems'] == []
    # ... and the dataset on disk satisfies its own API, not just the JSON above
    archive = DATASET.ResearchDataset(pathlib.Path(dataset['root']))
    assert archive.root == tmp_path / 'evidence' / 'dataset'
    assert archive.problems() == []
    assert archive.index_sha256() == dataset['index_sha256']
    assert len(archive.index()['snapshots']) == 1
    assert len(list(archive.blob_root.iterdir())) == 1
    assert archive.get_bytes(blob_sha) == bytes.fromhex(research['window']['expected_bytes'])

    # --- §6: exactly one differential input from exactly that snapshot; OBSERVATION only
    w6 = research['w6']
    assert w6['input_count'] == 1
    assert w6['read_run_id'] == research['read_run_id']
    assert w6['snapshot_id'] == dataset['snapshot_id']
    assert pathlib.Path(w6['input_path']).exists()
    assert hashlib.sha256(pathlib.Path(w6['input_path']).read_bytes()).hexdigest() == \
        w6['input_sha256']
    assert pathlib.Path(w6['baseline_path']).exists()
    assert hashlib.sha256(pathlib.Path(w6['baseline_path']).read_bytes()).hexdigest() == \
        w6['baseline_sha256']
    assert json.loads(pathlib.Path(w6['baseline_path']).read_text())['entries'] == []
    assert w6['candidate_count'] == len(w6['candidates']) == 1
    for candidate in w6['candidates']:
        assert candidate['status'] == 'OBSERVATION', candidate
        assert candidate['impact']['w4'] == 'NONE', candidate
    assert w6['all_observation'] is True and w6['all_w4_none'] is True
    assert w6['artifact_forbidden'] == {'fields': [], 'status_words': []}
    assert w6['replay_stable'] is True
    assert w6['replay_output_sha256'] == w6['output_sha256']
    # the stored report is the one the W6 harness validates, and the artifact carries no
    # runtime address / kbase / boot id anywhere
    w6_report = json.loads(pathlib.Path(w6['result_path']).read_text())
    assert W6.candidates_of(w6_report) == w6['candidates']
    assert w6_report['output_sha256'] == w6['output_sha256']
    assert hashlib.sha256(pathlib.Path(w6['result_path']).read_bytes()).hexdigest() == \
        w6['result_sha256']
    artifact_blob = json.dumps(json.loads(pathlib.Path(w6['input_path']).read_text()))
    for forbidden in W6.FORBIDDEN_IN_ARTIFACT:
        assert f'"{forbidden}"' not in artifact_blob, forbidden
    # a replay of the differential over the same inputs yields the same result hash
    replay = W6.run_differential(w6['baseline_path'], w6['input_path'])
    assert replay['output_sha256'] == w6['output_sha256']
    # analysis, not authorization: profile, approval and release documents are byte-identical,
    # and neither the classification matrix nor the read plan moved
    guards = w6['guards']
    assert guards['all_unchanged'] is True and guards['changed'] == []
    for name, entry in guards['entries'].items():
        assert entry['unchanged'] is True, name
        assert entry['sha256_before'] == entry['sha256_after'], name
    assert guards['entries']['profile_file']['sha256_before'] == \
        hashlib.sha256(C.PROFILE_PATH.read_bytes()).hexdigest()
    for name in ('approval_fixture', 'release_fixture'):
        path = pathlib.Path(guards['entries'][name]['path'])
        assert path.exists(), name
        assert hashlib.sha256(path.read_bytes()).hexdigest() == \
            guards['entries'][name]['sha256_before'], name

    # --- session C: nothing carried over, the release consumed, the read refused
    isolation = steps['session_c_isolation']
    reuse = isolation['reuse']
    assert reuse['refused_already_consumed'] is True, reuse
    assert reuse['provider_entries'] in (0, None)
    assert reuse['consumed_query'] is True
    marker = reuse['consumed_marker']
    for field in ('release_id', 'release_sha256', 'approval_sha256', 'boot_id', 'profile_sha256',
                  'read_run_id', 'read_session_id', 'consumed_at'):
        assert marker.get(field), f'the consumption marker carries no {field}'
    assert marker['release_id'] == research['release_id']
    assert marker['approval_sha256'] == research['approval_sha256']
    assert marker['boot_id'] == evidence['boot_id']
    assert marker['profile_sha256'] == evidence['profile_sha256']
    assert marker['read_run_id'] == research['read_run_id']
    assert marker['read_session_id'] == read['facts']['session_id']
    assert isolation['facts']['cleanup'] == {'resources': [], 'state': 'COMPLETE'}
    assert isolation['facts']['bye'] == 'ADMIN_SHUTDOWN'
    facts = isolation['isolation']
    assert facts['consumed_release_ids'] == [research['release_id']]

    # --- one lifetime, four sessions, fresh session-bound values, stable identity
    comparison = evidence['comparison']
    assert comparison['problems'] == []
    for field in ('session_id', 'nonce_sha256', 'transcript_sha256',
                  'directional_keys_fingerprint'):
        values = list(comparison['fresh'][field].values())
        assert len(set(values)) == len(values), f'{field} was reused: {values}'
    for field in ('build_id', 'platform', 'agent_version'):
        values = list(comparison['stable'][field].values())
        assert len({json.dumps(v) for v in values}) == 1, f'{field} drifted: {values}'

    # --- the agent stayed resident and then ended, exactly as the lifecycle says
    assert steps['after_admin_shutdown']['redialled_within_s'] is None
    report = evidence['_driver_report']
    assert report['exit_reason'] == 'ADMIN_SHUTDOWN' and report['cleanup_state'] == 'COMPLETE'
    assert report['recovery_required'] == 0 and report['held_after_cleanup'] == 0
    assert evidence['_driver_exit'] == 0, evidence['_driver_stderr']

    # --- agent-side counters: the read really was one bounded window of the simulated image
    trace = evidence['_sim_trace']
    assert trace is not None, 'the simulated image produced no trace'
    assert trace['seeded_bytes_read'] >= 16, trace
    assert trace['bytes_read'] <= 4096, trace          # one bounded read, not a sweep
    assert trace['seeded_windows'] >= 2, trace         # bootstrap window + the read window


def test_a_second_lifetime_sees_a_fresh_release_and_fresh_evidence(tmp_path, rehearsal_host):
    """Nothing of the first run leaks into the second: new boot binding, new ids, new store."""
    first = _run(tmp_path / 'one', rehearsal_host)
    second = _run(tmp_path / 'two', rehearsal_host)
    assert first['verdict'] == 'PASS' and second['verdict'] == 'PASS'
    steps_one = {s['step']: s for s in first['steps']}
    steps_two = {s['step']: s for s in second['steps']}
    one, two = steps_one['session_b_research_read']['research'], \
        steps_two['session_b_research_read']['research']
    for field in ('release_id', 'release_sha256', 'read_run_id'):
        assert one[field] != two[field], f'{field} was reused across lifetimes'
    assert steps_one['session_b_research_read']['facts']['session_id'] != \
        steps_two['session_b_research_read']['facts']['session_id']
    # ... and both read the same pinned window, from their own store
    assert one['window']['expected_bytes'] == two['window']['expected_bytes']


