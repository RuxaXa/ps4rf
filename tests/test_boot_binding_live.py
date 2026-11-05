"""W11 offline proof for the read-only userland boot binding.

Three layers, all offline:

1. the collector source itself (no privileged primitive, no hex constant, no kernel address),
2. the verifier/derivation chain (``tools/hostctl/boot.py`` + ``tools/profiles/bootid.py``),
3. a real end-to-end session against the host build of the agent with the boot module enabled:
   a stable source binds the promoted profile, a drifting source makes the agent STOP with
   ``BOOT_SOURCE_NOT_STABLE``, and an absent source makes it STOP with ``BOOT_READ_FAILED``.
"""

from __future__ import annotations

import json
import os
import pathlib
import shutil
import subprocess
import sys
import tempfile

import pytest

REPO_ROOT = pathlib.Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from tools.hostctl import boot                                        # noqa: E402
from tools.profiles import bootid                                      # noqa: E402

TARGET = REPO_ROOT / 'native' / 'target'
PROFILE = REPO_ROOT / 'profiles' / 'fw1352' / 'profile-13.52.json'
CAPTURE_BOOTTIME = '1789910256.860896'
CAPTURE_BOOT_ID = 'BOOT-19d2c790b0769502'
# W17F: the promoted profile now derives a new boot identity. Only the CURRENT promoted-profile
# derivation is re-pinned; the historical capture identity above stays byte-identical for the
# recorded W11 runs.
PROMOTED_BOOT_ID = 'BOOT-eae1a180366f96a5'


# ------------------------------------------------------------------ source level

def _code_only(text: str) -> str:
    """Strip comments: the module *documents* what it must not contain, the code must match."""
    import re
    text = re.sub(r'/\*.*?\*/', ' ', text, flags=re.S)
    return re.sub(r'//[^\n]*', ' ', text)


def test_boot_module_has_no_privileged_primitive_and_no_hex_constant():
    text = _code_only((TARGET / 'ps4rf_boot.c').read_text())
    # 'kexec(' (a call) is forbidden; the claim string "no_kexec" in the event body is not code
    # 'sysctlbyname(' is the *call* form: the module only names the path in its report, the
    # platform layer performs the call (W11.1 keeps every sysctl access in one place)
    for needle in ('kexec(', 'rdmsr', 'wrmsr', 'get_kernel_base', 'syscall(', 'sysctlbyname(',
                   '0xffff', 'lstar', 'prison'):
        assert needle not in text.lower(), f'{needle!r} must not appear in the boot module code'
    # the boot instant only comes through the platform layer's instrumented diagnostics
    assert 'ps4rf_platform_get' in text
    assert text.count('boot_diag') >= 2, 'both readings go through the diagnostic slot'
    assert 'wall_sec' in text
    assert 'classify' in text, 'the classification must be computed from measured values'


def test_boot_header_declares_the_userland_source_and_the_run_states():
    header = (TARGET / 'ps4rf_boot.h').read_text()
    assert 'PS4RF_BOOT_SOURCE "sysctl:kern.boottime"' in header
    for state in ('PS4RF_BOOT_RUN_OK', 'PS4RF_BOOT_RUN_READ_FAILED', 'PS4RF_BOOT_RUN_NOT_STABLE',
                  'PS4RF_BOOT_RUN_IMPLAUSIBLE'):
        assert state in header
    assert 'PS4RF_BOOT_PAUSE_US' in header


def test_platform_exposes_the_read_only_boot_source_on_both_sides():
    for name in ('ps4rf_platform_ps4.c', 'ps4rf_platform_host.c'):
        text = (TARGET / name).read_text()
        assert 'boot_timeval' in text, f'{name} must provide the W11 boot source'
        assert 'wall_sec' in text, f'{name} must provide the wall clock for the plausibility check'
    ps4 = (TARGET / 'ps4rf_platform_ps4.c').read_text()
    assert 'kern.boottime' in ps4, 'the console side must read the boottime sysctl'
    assert 'sceKernelGettimeofday' in ps4, 'the wall clock comes from the userland SDK call'


def test_agent_guard_is_compiled_for_the_boot_profile_only():
    agent = (TARGET / 'ps4rf_agent.c').read_text()
    assert '#ifdef PS4RF_TARGET_BOOTID' in agent
    assert 'ps4rf_boot_collect(&g_boot_info)' in agent
    assert 'ps4rf_boot_event(&g_boot_info, rt->build_id, label)' in agent
    assert 'boot_done = 1;' in agent, 'the one-shot guard must be set before the collection'


# ------------------------------------------------------------------ verifier chain

def test_verifier_self_test_and_derivation_contract():
    assert boot.verify_boot_event_selftest() == []
    assert bootid.self_test() == []


def _method(key: str, raw_hex: str = 'f0dcaf6a00000000e0220d0000000000', **overrides) -> dict:
    import hashlib
    body = {'method': key, 'size_query_attempted': True, 'size_query_rc': 0, 'size_query_errno': 0,
            'reported_size': str(len(raw_hex) // 2), 'read_attempted': True, 'read_rc': 0,
            'read_errno': 0, 'requested_size': 64, 'returned_size': str(len(raw_hex) // 2),
            'raw_len': len(raw_hex) // 2, 'raw_hex': raw_hex,
            'raw_sha256': hashlib.sha256(bytes.fromhex(raw_hex)).hexdigest(),
            'classification': 'BOOT_SYSCTL_SUCCESS', 'classification_id': 0}
    body.update(overrides)
    return body


def _clean_event(**overrides) -> dict:
    event = {
        'msg': 'EVENT', 'event': 'boot.binding', 'schema': 'ps4rf.boot.binding.diag.v1',
        'status': 'OK', 'source': 'sysctl:kern.boottime', 'source_kind': 'userland-sysctl-readonly',
        'no_kernel_access': True, 'no_kexec': True, 'no_kernel_address': True,
        'no_rva_sent_to_host': True, 'userland_only': True,
        'run_status': 0, 'run_status_name': 'OK', 'preferred_path': 'sysctlbyname',
        'methods': {'sysctlbyname': _method('sysctlbyname'), 'sysctl_mib': _method('sysctl_mib')},
        'read1': {'sec': '1789910256', 'usec': '860896'},
        'read2': {'sec': '1789910256', 'usec': '860896'},
        'reads_identical': True, 'stability': 'STABLE', 'timeval_sizeof': 16,
        'plausible': True, 'boottime_after_wall_clock': False, 'wall_clock_ok': True,
        'console_wall_sec': '1789910400', 'errno_observable': True, 'label': 'ps4rfd-live-w11d',
    }
    event.update(overrides)
    return event


def test_clean_event_binds_the_promoted_profile():
    profile = json.loads(PROFILE.read_text())
    sha = profile['canonical_sha256']
    event = _clean_event()
    report = boot.verify_boot_event(event, profile=profile, profile_sha256=sha, now=1_800_000_000)
    assert report['verified'], report['problems']
    assert report['boot_binding_short']['boot_id'] == PROMOTED_BOOT_ID
    assert report['labels'] == ['MEASURED_THIS_BOOT']
    assert report['binding_view']['valid_for_this_boot'] is True
    assert report['methods']['sysctlbyname']['derived_class'] == 'BOOT_SYSCTL_SUCCESS'
    # fail-closed variants (W11.1: measured values decide, a claim never does)
    for change, note in (
            ({'read2': {'sec': '1789910256', 'usec': '860897'}, 'run_status': 2,
              'run_status_name': 'BOOT_SOURCE_NOT_STABLE', 'stability': 'BOOT_SOURCE_NOT_STABLE',
              'reads_identical': False}, 'unstable reads are a diagnosis, never a binding'),
            ({'label': bootid.LABEL_SIMULATED_REBOOT_VECTOR}, 'simulated label'),
            ({'no_kernel_access': False}, 'kernel access claimed'),
            ({'source': 'kernel:variable'}, 'unapproved source'),
            ({'timeval_sizeof': 8}, 'ABI mismatch'),
            ({'read1': {'sec': '0', 'usec': '0'}, 'read2': {'sec': '0', 'usec': '0'}},
             'uninitialised timeval')):
        broken = _clean_event(**change)
        outcome = boot.verify_boot_event(broken, profile=profile, profile_sha256=sha,
                                        now=1_800_000_000)
        if 'diagnosis' in note:
            assert outcome['verified'] and outcome.get('no_boot_id'), note
        else:
            assert not outcome['verified'], note
    # a mutated measurement with a clean claim must be caught: the host re-derives everything
    claimed_clean = _clean_event()
    claimed_clean['methods'] = dict(claimed_clean['methods'])
    claimed_clean['methods']['sysctlbyname'] = _method('sysctlbyname', raw_hex='', raw_len=0,
                                                       returned_size=8, reported_size=8)
    outcome = boot.verify_boot_event(claimed_clean, profile=profile, profile_sha256=sha,
                                     now=1_800_000_000)
    assert not outcome['verified'] or outcome.get('no_boot_id'), \
        'a short result must never pass as a complete timeval'


# ------------------------------------------------------------------ end to end

def _build_host_agent(workdir: pathlib.Path) -> pathlib.Path:
    env = dict(os.environ, PS4RF_TARGET_BOOTID='1')
    res = subprocess.run([str(TARGET / 'build_host.sh'), str(workdir / 'host-build')],
                         capture_output=True, text=True, env=env, cwd=str(REPO_ROOT))
    if res.returncode != 0:
        pytest.skip(f'host build unavailable: {res.stderr[-200:]}')
    return workdir / 'host-build' / 'ps4rfd_host'


KNOBS = ('PS4RF_HOST_BOOTDIAG', 'PS4RF_HOST_BOOTDIAG_DRIFT_USEC', 'PS4RF_HOST_BOOTTIME',
         'PS4RF_HOST_BOOTTIME_DRIFT_USEC')


def _run_selftest(agent: pathlib.Path, outdir: pathlib.Path, psk: pathlib.Path,
                  env_extra: dict) -> dict:
    # hermetic: ambient stand-in knobs must never leak from one case into another
    env = dict(os.environ)
    for knob in KNOBS:
        env.pop(knob, None)
    env.update(env_extra)
    res = subprocess.run([sys.executable, '-m', 'tools.hostctl.cli', 'selftest',
                          '--w11-boot-binding', '--psk-file', str(psk),
                          '--agent-binary', str(agent), '--out', str(outdir)],
                         capture_output=True, text=True, env=env, cwd=str(REPO_ROOT))
    evidence = outdir / 'w8-evidence.json'
    assert evidence.exists(), f'no evidence written: {res.stdout[-400:]} {res.stderr[-400:]}'
    return json.loads(evidence.read_text())


@pytest.fixture(scope='module')
def w11_env(tmp_path_factory):
    workdir = tmp_path_factory.mktemp('w11-e2e')
    agent = _build_host_agent(workdir)
    psk = workdir / 'psk.bin'
    psk.write_bytes(os.urandom(32))
    return {'agent': agent, 'psk': psk, 'workdir': workdir}


CAPTURE_DIAG = 'name=0:0:16:16:f0dcaf6a00000000e0220d0000000000;mib=0:0:16:16:f0dcaf6a00000000e0220d0000000000'


def test_e2e_stable_source_binds_the_promoted_profile(w11_env):
    doc = _run_selftest(w11_env['agent'], w11_env['workdir'] / 'stable', w11_env['psk'],
                        {'PS4RF_HOST_BOOTDIAG': CAPTURE_DIAG})
    assert doc['verdict'] == 'PASS', [c['name'] for c in doc['checks'] if not c['ok']]
    event = doc['boot_binding_event']
    assert event['event'] == 'boot.binding'
    assert event['schema'] == 'ps4rf.boot.binding.diag.v1'
    assert event['read1'] == event['read2']
    assert event['no_kernel_access'] is True and event['no_kexec'] is True
    assert int(event['timeval_sizeof']) == 16, 'the ABI contract is a 16 byte struct timeval'
    verified = doc['boot_binding_verified']
    assert verified['verified'] is True, verified['problems']
    assert verified['boot_binding_short']['boot_id'] == CAPTURE_BOOT_ID
    assert doc['boot_binding_profile_sha256'] == json.loads(PROFILE.read_text())['canonical_sha256']
    assert doc['boot_binding_view']['valid_for_this_boot'] is True
    assert doc['bye']['reason'] == 'CLIENT_CLOSE'
    assert bootid.LABEL_SIMULATED_REBOOT_VECTOR not in json.dumps(doc)


def test_e2e_drifting_source_is_a_decisive_diagnosis(w11_env):
    doc = _run_selftest(w11_env['agent'], w11_env['workdir'] / 'drift', w11_env['psk'],
                        {'PS4RF_HOST_BOOTDIAG': CAPTURE_DIAG,
                         'PS4RF_HOST_BOOTDIAG_DRIFT_USEC': '1'})
    event = doc['boot_binding_event']
    assert event['read1'] != event['read2'], 'the drifting source must be visible'
    assert event['run_status_name'] == 'BOOT_SOURCE_NOT_STABLE'
    assert doc['bye']['reason'] == 'BOOT_SOURCE_NOT_STABLE', 'the agent stops itself'
    verified = doc['boot_binding_verified']
    assert verified['verified'] is True, verified['problems']
    assert verified['no_boot_id'] is True
    assert verified['derived_run_status']['name'] == 'BOOT_SOURCE_NOT_STABLE'
    assert 'boot_binding_short' not in verified, 'no boot id may be derived from a drifting source'


def test_e2e_both_paths_not_found_is_a_decisive_diagnosis(w11_env):
    doc = _run_selftest(w11_env['agent'], w11_env['workdir'] / 'nosrc', w11_env['psk'],
                        {'PS4RF_HOST_BOOTDIAG': 'name=2:2:0:0:;mib=2:2:0:0:'})
    event = doc['boot_binding_event']
    assert event['run_status_name'] == 'BOOT_READ_FAILED'
    assert event['methods']['sysctlbyname']['classification'] == 'BOOT_SYSCTL_NAME_NOT_FOUND'
    assert event['methods']['sysctl_mib']['classification'] == 'BOOT_SYSCTL_MIB_NOT_FOUND'
    assert doc['bye']['reason'] == 'BOOT_READ_FAILED'
    verified = doc['boot_binding_verified']
    assert verified['verified'] is True and verified['no_boot_id'] is True
    assert doc['verdict'] == 'PASS', 'a decisive diagnosis is a successful W11.1 run'
    assert 'boot_binding_short' not in verified, \
        'no boot id may be derived without a measured value'


def test_e2e_partial_eight_bytes_is_reported_and_never_accepted(w11_env):
    doc = _run_selftest(w11_env['agent'], w11_env['workdir'] / 'partial', w11_env['psk'],
                        {'PS4RF_HOST_BOOTDIAG': 'name=0:0:8:8:f0dcaf6a00000000;mib=2:2:0:0:'})
    event = doc['boot_binding_event']
    assert event['run_status_name'] == 'BOOT_SOURCE_PARTIAL'
    assert event['methods']['sysctlbyname']['classification'] == 'BOOT_SYSCTL_SHORT_RESULT'
    assert event['complete_timeval'] is False
    verified = doc['boot_binding_verified']
    assert verified['no_boot_id'] is True and 'boot_binding_short' not in verified
    assert verified['verified'] is True
    assert doc['bye']['reason'] == 'BOOT_SOURCE_PARTIAL'


def test_e2e_conflicting_paths_produce_no_boot_id(w11_env):
    doc = _run_selftest(w11_env['agent'], w11_env['workdir'] / 'conflict', w11_env['psk'],
                        {'PS4RF_HOST_BOOTDIAG': 'name=0:0:16:16:f0dcaf6a00000000e0220d0000000000;'
                                                'mib=0:0:16:16:f0dcaf6a00000000e1220d0000000000'})
    event = doc['boot_binding_event']
    assert event['run_status_name'] == 'BOOT_SOURCE_CONFLICT'
    assert event['both_paths_identical'] is False
    verified = doc['boot_binding_verified']
    assert verified['no_boot_id'] is True and 'boot_binding_short' not in verified
    assert doc['bye']['reason'] == 'BOOT_SOURCE_CONFLICT'


def test_e2e_only_the_mib_path_works_and_becomes_the_documented_contract(w11_env):
    doc = _run_selftest(w11_env['agent'], w11_env['workdir'] / 'onlymib', w11_env['psk'],
                        {'PS4RF_HOST_BOOTDIAG': 'name=2:22:0:0:;' + CAPTURE_DIAG.split(';')[1]})
    event = doc['boot_binding_event']
    assert event['methods']['sysctlbyname']['classification'] == 'BOOT_SYSCTL_INVALID_ARGUMENT'
    assert event['preferred_path'] == 'sysctl_mib'
    assert doc['verdict'] == 'PASS', [c['name'] for c in doc['checks'] if not c['ok']]
    verified = doc['boot_binding_verified']
    assert verified['verified'] is True, verified['problems']
    assert verified['boot_binding_short']['boot_id'] == CAPTURE_BOOT_ID
    assert 'sysctl_mib' in str(verified.get('preferred_source_contract'))
