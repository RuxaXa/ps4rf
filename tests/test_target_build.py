"""W8 target build gate (P4/W8): offline proof before any live contact.

What this file asserts, in the order of the W8 brief:

1. the target operation table is generated from the frozen core (never hand maintained),
   is deterministic and matches registry + W3 interface + W7 router matrix exactly,
2. the frozen wire sources carry no target conditional, so the payload cannot have a wire
   variant of its own,
3. the dispatch path has exactly one provider entry site and refuses every non-wired route
   before it,
4. the wire catalogues (HELLO/HELLO_ACK/transcript/AUTH/keys/AEAD/framing/max-frame/JCS)
   replay clean when compiled with the *target codegen flags* (btver2), not only with the
   host defaults,
5. the artefact gates are green for a produced target build (0 relocations, no privileged
   symbol, no CR0/kexec, no loader port, exactly one endpoint),
6. the approved smoke sequence is exactly the approved operation set, and the offline
   end-to-end session (host controller + agent) completes green.

Tests that need the libPS4 SDK only run when the SDK is present (``PS4RF_LIBPS4_SDK``
environment variable or the audit path); build-host tests need gcc/make.
"""

from __future__ import annotations

import json
import os
import pathlib
import re
import shutil
import subprocess

import pytest
from tools.primitive_iface import schema as SCHEMA

REPO_ROOT = pathlib.Path(__file__).resolve().parents[1]
TARGET = REPO_ROOT / 'native' / 'target'
NATIVE = REPO_ROOT / 'native'
DEFAULT_SDK = pathlib.Path('/home/hermes/fw900-sdk-audit/libPS4')
CATALOGS = ['../tests/fixtures/crypto/vectors-v1.json',
            '../tests/fixtures/parity/vectors-v1.json',
            '../tests/fixtures/parity/w2-negative-v1.json']


def _strip_comments(text: str) -> str:
    text = re.sub(r'/\*.*?\*/', ' ', text, flags=re.S)
    return re.sub(r'//[^\n]*', ' ', text)


def sdk_path() -> pathlib.Path | None:
    import os
    env = os.environ.get('PS4RF_LIBPS4_SDK')
    candidate = pathlib.Path(env) if env else DEFAULT_SDK
    if (candidate / 'crt0.s').exists() and (candidate / 'libPS4.a').exists():
        return candidate
    return None


# --------------------------------------------------------------- 1. table generation

def test_optable_is_generated_from_the_frozen_core():
    proc = subprocess.run(['python3', str(TARGET / 'gen_optable.py'), '--check'],
                          cwd=REPO_ROOT, capture_output=True, text=True)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert 'up to date' in proc.stdout


def test_optable_table_equals_frozen_sources():
    """Parse the generated header and compare it against registry + W3 + W7."""
    import sys
    sys.path.insert(0, str(REPO_ROOT))
    from core.rpc.registry import default_registry
    from tools.dispatch import matrix as MATRIX
    from tools.primitive_iface.schema import OPS_BY_NAME

    text = (TARGET / 'ps4rf_optable_data.h').read_text()
    rows = re.findall(r'^\s*\{\s*"([^"]+)",\s*"([^"]*)",\s*"([^"]*)",\s*"([^"]*)",\s*'
                      r'(PS4RF_ROUTE_\w+),\s*(PS4RF_TARGET_\w+),\s*(\d),\s*(\d)\s*\},',
                      text, re.M)
    assert len(rows) == len(SCHEMA.OPS), f'expected {len(SCHEMA.OPS)} rows, parsed {len(rows)}'
    by_name = {name: (family, capability, reason, route, target, mutating, recovery_safe)
               for name, family, capability, reason, route, target, mutating, recovery_safe in rows}
    assert sorted(by_name) == sorted(OPS_BY_NAME), 'table and interface disagree'
    registry = default_registry()
    for op, (family, capability, reason, route, target, mutating, recovery_safe) in by_name.items():
        spec = OPS_BY_NAME[op]
        entry = MATRIX.route_for(op)
        assert registry.has(op)
        assert family == spec.family
        assert capability == (spec.capability or '')
        # W14: the generated target catalog singles out the wired privileged provider via
        # the documented target-side override (the host route is unchanged).
        want_route = MATRIX.TARGET_ROUTE_OVERRIDES.get(op, entry['route'])
        assert route == f'PS4RF_ROUTE_{want_route.upper()}', op
        assert bool(int(mutating)) == bool(spec.mutating)
        assert bool(int(recovery_safe)) == bool(spec.recovery_safe)
        if target == 'PS4RF_TARGET_WIRED':
            # W14: the single wired privileged provider is the named target-side override;
            # every other wired operation must still be a stub route.
            assert want_route in (MATRIX.ROUTE_STUB, MATRIX.ROUTE_PRIVILEGED_PROVIDER), \
                f'{op} wired on a non-wirable route'
            assert reason == ''
        else:
            assert reason, f'{op} deferred without a reason'
    wired = [n for n, r in by_name.items() if r[4] == 'PS4RF_TARGET_WIRED']
    # W17F: derive the wired surface from the authoritative designations -- the generator's
    # stub-wired set plus exactly the named target-side overrides. No historical count, no
    # blanket allowance (the per-row route checks above already bound each member).
    import importlib.util as _ilu
    _spec = _ilu.spec_from_file_location('ps4rf_gen_optable_probe', TARGET / 'gen_optable.py')
    _gen = _ilu.module_from_spec(_spec)
    _spec.loader.exec_module(_gen)
    expected_wired = sorted(set(_gen.TARGET_WIRED_OPS) | set(MATRIX.TARGET_ROUTE_OVERRIDES))
    assert sorted(wired) == expected_wired, \
        f'wired surface {sorted(wired)} != expected {expected_wired}'
    # W14: the one wired privileged provider is kernel.read (route override, target wired)
    assert 'kernel.read' in by_name and by_name['kernel.read'][4] == 'PS4RF_TARGET_WIRED'
    assert by_name['kernel.read'][3] == 'PS4RF_ROUTE_PRIVILEGED_PROVIDER'
    assert by_name['kernel.snapshot'][4] == 'PS4RF_TARGET_DEFERRED'


# ------------------------------------------------------- 2. no wire variant on target

def test_frozen_wire_sources_have_no_target_conditionals():
    """The payload must not be able to compile a different wire than the frozen one."""
    for name in ('ps4rf_protocol.c', 'ps4rf_protocol.h', 'jcs.c', 'jcs.h',
                 'sha256.c', 'sha256.h', 'chacha20poly1305.c', 'chacha20poly1305.h'):
        text = (NATIVE / 'src' / name).read_text()
        for needle in ('PS4RF_TARGET_PS4', 'PS4RF_TARGET_HOST', '#ifdef __orbis__',
                       '#if defined(__ORBIS__)'):
            assert needle not in text, f'{name} carries a target conditional: {needle}'


def test_target_agent_reuses_frozen_wire_entry_points():
    text = (TARGET / 'ps4rf_agent.c').read_text()
    for entry in ('ps4rf_agent_handshake', 'ps4rf_channel_init',
                  'ps4rf_frame_encode', 'ps4rf_frame_parse_header', 'ps4rf_channel_open',
                  'ps4rf_canonical_bytes', 'ps4rf_transcript_hash', 'ps4rf_derive_keys',
                  'ps4rf_nonce_prefix'):
        assert entry in text, f'target agent does not use {entry}'


# ------------------------------------------------------- 3. single dispatch path

def test_router_has_exactly_one_provider_entry_site():
    text = (TARGET / 'ps4rf_router.c').read_text()
    assert text.count('ps4rf_ev_note_entry(') == 1
    assert len(re.findall(r'ps4rf_provider_enter\(rt\);\s*/\* <- the single provider entry site \*/',
                          text)) == 1
    # the entry must sit behind the wired-route decision
    entry_pos = text.index('ps4rf_provider_enter(rt)')
    assert text.index('row->target != PS4RF_TARGET_WIRED') < entry_pos


def test_session_loop_and_daemon_source_gates_are_green():
    """W14 §5.1 + §2/§3: the manifest gate proves both properties from the sources alone.

    ``gate_kread`` proves the session loop holds no read path on a linked console artefact; this
    one proves it (and the daemon's structural properties) without any artefact, so the property
    is enforced by the suite and not only at console build time.
    """
    import importlib.util
    spec = importlib.util.spec_from_file_location('build_manifest_source_gate',
                                                  TARGET / 'build_manifest.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    findings = module.gate_agent_source(REPO_ROOT)
    assert findings['problems'] == [], findings['problems']
    assert all(findings['checks']['session_loop'].values()), findings['checks']['session_loop']
    assert all(findings['checks']['resident_daemon'].values()), \
        findings['checks']['resident_daemon']
    assert all(findings['checks']['session_isolation'].values()), \
        findings['checks']['session_isolation']
    assert all(findings['checks']['recovery_semantics'].values()), \
        findings['checks']['recovery_semantics']
    # the gate must be wired into the manifest verdict, not merely callable
    assert "problems.extend(agent_source['problems'])" in \
        (TARGET / 'build_manifest.py').read_text()


def test_no_kernel_symbols_in_target_sources():
    """No privileged path may exist in the payload sources outside the W9 attestation module.

    W9 links exactly two SDK entry points -- kexec() as the single privileged transition and
    get_kernel_base() as the userland cross-check value -- and both may only appear in the
    attestation module (ps4rf_attest.c, plus the honest host stand-ins in
    ps4rf_attest_host.c). Everywhere else the old rule holds unchanged, and the two names stay
    forbidden inside the attestation module as well for everything except that declaration.
    """
    forbidden = ('jailbreak', 'disable_aslr', 'gpuvm', 'keymgr', 'ccp_', 'samu', 'sbl_',
                 '__readcr0', 'kernel_write', 'sceKernelGetKernelBase', 'kpayload')
    # Each privileged wave brings exactly one privileged module plus its honest host stand-in:
    # W9 the attestation, W11.2 the fixed read-only boot identity read, W12 the bounded
    # kernel.read provider. Everything else still forbids a kernel transition.
    privileged_modules = {'ps4rf_attest.c', 'ps4rf_attest_host.c',
                          'ps4rf_bootread.c', 'ps4rf_bootread_host.c',
                          'ps4rf_kread.c', 'ps4rf_kread_host.c',
                          # W17: the recipe reads through ONE leaf and ONE privileged transition;
                          # the console platform layer and its honest host stand-in are the only
                          # two files that may name them (no other file gained a transition).
                          'ps4rf_recipe_target.c', 'ps4rf_recipe_target.h',
                          'ps4rf_recipe_host.c'}
    w9_module = privileged_modules
    # The two documented entry points are matched as *calls/declarations*: field names such as
    # kexec_rc are not a kernel transition, and they stay allowed as pure report data.
    w9_entry = (r'\bkexec\s*\(', r'\bget_kernel_base\s*\(')
    for path in list(TARGET.glob('*.c')) + list(TARGET.glob('*.h')) + \
            list((TARGET / 'compat_ps4').glob('*.h')):
        if path.name in ('ps4rf_optable_data.h', 'ps4rf_kread_regions.h'):
            continue          # generated data tables: the optable *records* the frozen operation
                              # names, the W12/W16 region table *records* the reviewed region ids
                              # (W16 added the CCP/keymgr window ids). Neither carries a call, a
                              # transition or a privileged instruction -- every hand-written
                              # target source stays scanned by the loop below.
        code = _strip_comments(path.read_text())
        for needle in forbidden:
            # word-boundary match: ps4rf_attest_kpayload is this wave's own callback, while a
            # bare kpayload (the SDK's kernel payload macros) stays forbidden
            assert not re.search(r'\b' + re.escape(needle), code), \
                f'{path.name} contains {needle} in code'
        for pattern in w9_entry:
            found = len(re.findall(pattern, code))
            if path.name in w9_module:
                assert found <= 2, f'{path.name} uses {pattern} {found} times'
            else:
                assert found == 0, f'{path.name} calls {pattern} outside the W9 module'
    # the privileged module is the only place a kernel transition can come from
    offenders = [p.name for p in TARGET.glob('*.c')
                 if p.name not in w9_module and re.search(r'\bkexec\s*\(', p.read_text())]
    assert offenders == [], f'kexec called outside the W9 module: {offenders}'


# ----------------------------------------------------- 4. wire parity, target codegen

def _cpu_supports_btver2() -> bool:
    try:
        flags = pathlib.Path('/proc/cpuinfo').read_text()
    except OSError:
        return False
    return 'sse4a' in flags   # the one Jaguar feature that a modern host may lack


@pytest.mark.skipif(shutil.which('gcc') is None or shutil.which('make') is None,
                    reason='host toolchain missing')
@pytest.mark.skipif(not _cpu_supports_btver2(),
                    reason='this host cannot execute btver2 code')
def test_wire_catalogs_replay_with_target_codegen_flags(tmp_path):
    """Same catalog replay as W2, but compiled the way the console payload is compiled."""
    cflags = ('-std=c99 -Os -march=btver2 -Wall -Wextra -fPIC -fno-builtin '
              '-D_DEFAULT_SOURCE -D_POSIX_C_SOURCE=200809L')
    build = tmp_path / 'btver2'
    proc = subprocess.run(['make', 'all', f'BUILD={build}', f'CFLAGS={cflags}'],
                          cwd=NATIVE, capture_output=True, text=True)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    run = subprocess.run([str(build / 'ps4rf_parity'), *CATALOGS], cwd=NATIVE,
                         capture_output=True, text=True)
    assert run.returncode == 0, run.stdout[-4000:] + run.stderr[-2000:]
    assert 'parity verdict: PASS' in run.stdout
    assert [line for line in run.stdout.splitlines() if line.startswith('FAIL')] == []
    for stage in ('canonicalization', 'transcript', 'hkdf', 'aad', 'nonce', 'aead',
                  'frame_header', 'wire_frame', 'handshake'):
        assert f'{stage} ' in run.stdout


# --------------------------------------------------------- 5. artefact gates

def test_target_build_manifest_gates_when_present():
    manifest = REPO_ROOT / 'native' / 'build' / 'target-ps4' / 'build_manifest.json'
    if not manifest.exists():
        pytest.skip('no target build in native/build/target-ps4 (the gate script builds it)')
    doc = json.loads(manifest.read_text())
    assert doc['verdict'] == 'PASS', doc['problems']
    assert doc['gates']['relocations_zero'] is True
    assert doc['relocations'] == []
    assert doc['gates']['forbidden_symbols'] == []
    assert doc['gates']['forbidden_code'] == []
    assert doc['gates']['loader_port'] == []
    assert doc['gates']['host_target']['ok'] is True
    assert doc['undefined_symbols'] == []
    assert doc['elf']['type'].startswith('DYN')
    assert doc['runtime_dependencies']['no_dynamic_linking'] is True


def test_console_kread_build_gate_passes_when_the_sdk_is_present(tmp_path):
    """The artefact gate must be *exercised*, not assumed.

    It went stale for a whole wave while no test ran it: the stage-A trigger block, the per-session
    one-shot re-arm and the WIRE-CATALOG R3 route row were all still expected in their old shape,
    so a build that was correct by design failed the gate (and a build that regressed could have
    passed a check nobody ran). This test builds the console KREAD artefact -- twice, that is the
    script's own reproducibility proof -- and requires the manifest verdict PASS with the W14 gate
    blocks recorded.
    """
    sdk = sdk_path()
    if sdk is None:
        pytest.skip('no libPS4 SDK (PS4RF_LIBPS4_SDK or the audit path)')
    if shutil.which('gcc') is None or shutil.which('objcopy') is None:
        pytest.skip('no host toolchain')
    psk = tmp_path / 'psk.bin'
    psk.write_bytes(os.urandom(32))          # a scratch key for the offline build, never a secret
    out = tmp_path / 'target-ps4'
    out.mkdir()
    run = subprocess.run(['sh', str(TARGET / 'build_ps4.sh'), str(out), str(sdk), str(psk)],
                         cwd=REPO_ROOT, capture_output=True, text=True,
                         env=dict(os.environ, PS4RF_TARGET_KREAD='1'))
    assert run.returncode == 0, run.stdout + run.stderr
    assert 'reproducible twice' in run.stdout, run.stdout
    doc = json.loads((out / 'build_manifest.json').read_text())
    assert doc['verdict'] == 'PASS', doc['problems']
    assert doc['problems'] == []
    assert doc['relocations'] == [] and doc['undefined_symbols'] == []
    gates = doc['gates']
    assert all(gates['agent_source']['checks']['session_loop'].values()), \
        gates['agent_source']['checks']['session_loop']
    assert all(gates['agent_source']['checks']['resident_daemon'].values()), \
        gates['agent_source']['checks']['resident_daemon']
    # the restated W14 expectations inside gate_kread: per-session re-arm, no reset, host route
    assert gates['kread']['one_shot']['session_entry_rearms'] == 1
    assert gates['kread']['one_shot']['guard_resets_outside_the_session_entry'] == 0
    assert gates['kread']['parity']['host_route_untouched'] is True
    # W17F: exact SET parity against the manifest's own expected set (no magic single-op pin and
    # no blanket allowance for arbitrary future overrides).
    assert sorted(map(tuple, gates['kread']['parity']['target_route_override_pairs'])) \
        == [tuple(p) for p in gates['kread']['parity']['expected_target_route_override_pairs']]
    assert gates['kread']['request_side']['agent_block_found'] is False


@pytest.mark.skipif(shutil.which('gcc') is None or shutil.which('objcopy') is None,
                    reason='host toolchain missing')
def test_console_w17_build_gate_passes_when_the_sdk_is_present(tmp_path):
    """Phase 4 of the W17 wave: the artefact that carries the two generic primitives.

    The build compiles the console image with both providers and requires the manifest verdict PASS,
    the W17 gate recording that *both* operations are reached through the real dispatch, and the
    reproducibility proof the script performs internally (two builds, byte-identical). The gate is
    the artefact's own proof: route metadata is not accepted, the linked dispatch path is read.
    """
    sdk = sdk_path()
    if sdk is None:
        pytest.skip('no libPS4 SDK (PS4RF_LIBPS4_SDK or the audit path)')
    psk = tmp_path / 'psk.bin'
    psk.write_bytes(os.urandom(32))
    out = tmp_path / 'target-w17'
    out.mkdir()
    env = dict(os.environ, PS4RF_TARGET_ATTEST='1', PS4RF_TARGET_BOOTID='1',
               PS4RF_TARGET_KREAD='1', PS4RF_TARGET_BOOTBIND='1', PS4RF_TARGET_RECIPE='1',
               PS4RF_TARGET_IOCTL='1', PS4RF_AGENT_HOST='192.168.1.148',
               PS4RF_AGENT_PORT='9028', PS4RF_AGENT_LABEL='ps4rfd-live-w17',
               PS4RF_AGENT_CONTEXT='fw13-52-w17-recipe-ioctl')
    run = subprocess.run(['sh', str(TARGET / 'build_ps4.sh'), str(out), str(sdk), str(psk)],
                         cwd=REPO_ROOT, capture_output=True, text=True, env=env)
    assert run.returncode == 0, run.stdout + run.stderr
    assert 'reproducible twice' in run.stdout, run.stdout
    doc = json.loads((out / 'build_manifest.json').read_text())
    assert doc['verdict'] == 'PASS', doc['problems']
    assert doc['relocations'] == [] and doc['undefined_symbols'] == []
    w17 = doc['gates']['w17']
    # this configuration carries the lifetime boot-binding gate as well, and the manifest records
    # it as part of the artefact's identity
    assert w17['providers'] == ['binding', 'ioctl', 'recipe'], w17['providers']
    assert w17['binding_gate'] is True
    assert w17['problems'] == [], w17['problems']
    # the linked dispatch path reaches every provider seam, not just the table row
    assert all(w17['provider_calls'].values()), w17['provider_calls']
    assert w17['transfer_buffer']['bytes'] >= w17['transfer_buffer']['required']
    # and the request surface carries exactly the reviewed arguments
    assert sorted(w17['args']['kernel.snapshot.recipe']) == ['indices', 'recipe_ref']
    assert sorted(w17['args']['ioctl.invoke']) == ['blob', 'command', 'data', 'mode']
    assert w17['addressish_args'] == [] and w17['generic_call_args'] == []


def test_loader_port_never_appears_in_target_sources():
    for path in list(TARGET.glob('*.c')) + list(TARGET.glob('*.h')) + \
            list(TARGET.glob('*.sh')) + list(TARGET.glob('*.py')):
        text = path.read_text()
        # 9090 may only appear as the *documented forbidden* loader port in the manifest
        # script's scan constant, never as a configured endpoint
        if path.name == 'build_manifest.py':
            assert 'LOADER_PORT = 9090' in text
            continue
        assert '9090' not in text, f'{path.name} mentions the loader port'


# ------------------------------------------------- 6. the approved live sequence

APPROVED_OPS = {
    'session.ping', 'session.status', 'telemetry.read',
    'memory.alloc', 'memory.free',
    'sync.gate.create', 'sync.gate.arrive', 'sync.gate.wait', 'sync.gate.status',
    'sync.gate.release', 'sync.gate.destroy',
    'sync.barrier.create', 'sync.barrier.wait', 'sync.barrier.release', 'sync.barrier.destroy',
}


def test_smoke_sequence_is_the_approved_scope():
    import sys
    sys.path.insert(0, str(REPO_ROOT))
    from tools.hostctl import smoke

    ops = [step.op for step in smoke.sequence()]
    assert ops[:5] == ['session.ping', 'session.status', 'telemetry.read',
                       'memory.alloc', 'memory.free']
    assert set(ops) - {'kernel.read'} <= APPROVED_OPS, 'sequence left the approved scope'
    assert ops.count('kernel.read') == 1
    negative = [step for step in smoke.sequence() if step.op == 'kernel.read'][0]
    assert negative.expect_status == 'ERROR'
    assert negative.expect_code == 'OPERATION_DEFERRED'
    assert negative.expect_detail_contains == 'not implemented by the native stub provider'
    # no privileged operation beyond the single negative probe
    privileged = {'kernel.read', 'kernel.write', 'kernel.dump.full', 'kernel.snapshot',
                  'kernel.exec'}
    assert [op for op in ops if op in privileged] == ['kernel.read']


def test_deferred_operations_never_report_provider_entry():
    import sys
    sys.path.insert(0, str(REPO_ROOT))
    from tools.hostctl import smoke
    assert smoke.provider_entry_observed('kernel.read', {
        'status': 'ERROR', 'error': {'code': 'OPERATION_DEFERRED',
                                     'detail': 'provider_entry=false route=deferred_privilege'}}) is False
    assert smoke.provider_entry_observed('session.ping', {'status': 'OK', 'result': {'pong': True}}) is True
    assert smoke.detail_provider_entry_false({'error': {'detail': 'x provider_entry=false y'}}) is True


# ------------------------------------------------- 7. offline end-to-end (host build)

@pytest.mark.skipif(shutil.which('gcc') is None, reason='host toolchain missing')
def test_offline_controller_agent_end_to_end(tmp_path):
    """Host build of the agent + the host controller, full sequence, no console contact."""
    build = tmp_path / 'host'
    proc = subprocess.run(['sh', str(TARGET / 'build_host.sh'), str(build)],
                          cwd=REPO_ROOT, capture_output=True, text=True)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    psk = tmp_path / 'psk.bin'
    psk.write_bytes(bytes(range(32)))
    out = tmp_path / 'evidence'
    run = subprocess.run(['python3', '-m', 'tools.hostctl.cli', 'selftest',
                          '--psk-file', str(psk), '--agent-binary', str(build / 'ps4rfd_host'),
                          '--out', str(out)],
                         cwd=REPO_ROOT, capture_output=True, text=True)
    assert run.returncode == 0, run.stdout + run.stderr
    doc = json.loads((out / 'w8-evidence.json').read_text())
    assert doc['verdict'] == 'PASS'
    assert [check for check in doc['checks'] if not check['ok']] == []
    from tools.hostctl import smoke as _smoke
    assert len(doc['requests']) == len(_smoke.sequence())
    assert doc['bye'] is not None and doc['bye']['reason'] == 'CLIENT_CLOSE'
    # W17F: the attestation's counts are compared against the *generated* table, not against a
    # historical number -- the host build must know the same surface the generator produced.
    header = (TARGET / 'ps4rf_optable_data.h').read_text()
    generated = {name: int(re.search(rf'PS4RF_OP_{name}_COUNT (\d+)u', header).group(1))
                 for name in ('TABLE', 'WIRED', 'DEFERRED')}
    caps = doc['attestation']['capabilities']
    assert caps['wired_count'] == generated['WIRED'], caps
    assert caps['deferred_count'] == generated['DEFERRED'], caps
    # W14: the host side keeps deferring kernel.read (host route unchanged) -- the operation is
    # served only by the host's own release-authorized path (tools/hostctl/kreadlive.py), never
    # by the generic dispatch path. On the target the same request enters the single wired
    # provider; tests/test_w13c2_wire_arguments.py drives that path directly.
    negative = [r for r in doc['requests'] if r['operation'] == 'kernel.read'][0]
    assert negative['provider_entry'] is False
    # the pre-shared key material never appears in the evidence
    blob = json.dumps(doc)
    assert bytes(range(32)).hex() not in blob
    import base64
    assert base64.b64encode(bytes(range(32))).decode() not in blob


def test_target_sources_only_write_to_the_approved_paths():
    """The payload must not contain file writes, shell-outs or console persistence."""
    suspicious = ('fopen(', 'system(', 'sceKernelMount', 'pfs', 'sceAppInstUtil',
                  'sceSysUtilSendNotification', 'klog')
    for path in TARGET.glob('*.c'):
        if path.name in ('ps4rf_platform_host.c', 'ps4rfd_host.c'):
            continue          # host build only: stdio for the offline self test
        text = path.read_text()
        for needle in suspicious:
            assert needle not in text, f'{path.name} uses {needle}'


def test_the_resident_console_entry_point_runs_the_daemon_under_its_guard():
    """W14: the artefact that goes to the console must *be* the resident agent.

    The single-session entry point is still what the other profiles build, so the resident path is
    behind ``PS4RF_TARGET_RESIDENT``; the source-level checks here are the ones that do not need the
    SDK, and `build_ps4.sh` runs the same questions as a gate on the real artefact (``--resident``).
    """
    target = (TARGET / 'ps4rfd_target.c').read_text()
    assert '#ifdef PS4RF_TARGET_RESIDENT' in target
    resident_block = target.split('#ifdef PS4RF_TARGET_RESIDENT', 1)[1].split('#else', 1)[0]
    assert 'ps4rf_daemon_run' in resident_block, 'the resident entry point must enter the daemon'
    assert 'net_connect' not in resident_block, 'the daemon owns the dial-out loop, not this file'
    assert 'PS4RF_TARGET_MAX_SESSIONS' in resident_block
    assert 'PS4RF_TARGET_BACKOFF_MAX_MS' in resident_block
    # the other profiles keep exactly the entry point they had
    single_block = target.split('#else', 1)[1]
    assert 'ps4rf_agent_run(fd, psk, PS4RF_TARGET_LABEL' in single_block
    # and the daemon itself still only dials out: no listener appears anywhere in the module
    daemon = (TARGET / 'ps4rf_daemon.c').read_text()
    listener = re.compile(r'\b(?:net_listen|listen|bind|accept)\s*\(')
    match = listener.search(daemon)
    assert match is None, f'the daemon must not listen ({match.group(0)})'
    # the console build has no report channel: no console output in the target sources (snprintf
    # into a local buffer is not a channel, and the frozen modules are allowed to format)
    console_output = re.compile(r'(?<![a-z])printf\(|fwrite\(|klog')
    for path in TARGET.glob('*.c'):
        if path.name in ('ps4rf_platform_host.c', 'ps4rfd_host.c'):
            continue          # host build only
        match = console_output.search(path.read_text())
        assert match is None, f'{path.name} writes to a console channel ({match.group(0)})'
