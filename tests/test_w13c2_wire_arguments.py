"""W13-C2 / WIRE-CATALOG R2 -- the kernel.read argument contract.

Three layers, all against production code:

1. the checked-in generated table (``tests/harness/optable_args_check.c`` reads it): the operation's
   argument slice must be exactly region_index/offset/length, all required integers;
2. the normative sources: the W3 schema, the operation row (name, capability, route), the agent's
   parse location and the host's exact wire body;
3. the live error itself, against the real agent over a real session (``PS4RF_TARGET_KREAD=1`` host
   build, whose stub ``kexec``/``get_kernel_base`` keep it safe): the nested triplet is accepted and
   reaches the provider, while the flat body (the W13-C1 mistake), the retired ``addr``/``size``
   pair, missing fields, wrong types and unknown fields are refused by the router.
"""
from __future__ import annotations

import json
import pathlib
import re
import socket
import subprocess

import pytest

REPO = pathlib.Path(__file__).resolve().parents[1]
TARGET = REPO / 'native' / 'target'
HARNESS = REPO / 'tests' / 'harness' / 'optable_args_check.c'
BUILD_DIR = pathlib.Path.home() / '.hermes/cache/scratch/ps4rf-w13-c2/test-harness'

TRIPLET = ['region_index', 'offset', 'length']
FORBIDDEN = ('addr', 'address', 'va', 'kernel_va', 'ptr', 'source', 'size')

#: bodies the router must refuse (response code ARGUMENT_INVALID)
REJECTED_BODIES = {
    'flat_body_keys': {'operation': 'kernel.read', 'region_index': 1, 'offset': 0, 'length': 16},
    'legacy_addr_size': {'addr': 0, 'size': 16},
    'triplet_plus_addr': {'region_index': 1, 'offset': 0, 'length': 16, 'addr': 1},
    'triplet_plus_size': {'region_index': 1, 'offset': 0, 'length': 16, 'size': 16},
    'missing_region_index': {'offset': 0, 'length': 16},
    'missing_offset': {'region_index': 1, 'length': 16},
    'missing_length': {'region_index': 1, 'offset': 0},
    'wrong_type': {'region_index': '1', 'offset': 0, 'length': 16},
    'unknown_field': {'region_index': 1, 'offset': 0, 'length': 16, 'address': 4096},
    'empty': {},
}
#: the cases whose refusal is the trigger's own explicit ARGUMENT_INVALID (missing or unreadable)
EXPLICIT_REFUSALS = ('flat_body_keys', 'legacy_addr_size', 'missing_region_index', 'missing_offset',
                     'missing_length', 'wrong_type', 'empty')


@pytest.fixture(scope='module')
def table() -> dict:
    BUILD_DIR.mkdir(parents=True, exist_ok=True)
    binary = BUILD_DIR / 'optable_args_check'
    result = subprocess.run(
        ['gcc', '-std=c11', '-O1', '-Wall', '-Wextra', '-Wno-unused-parameter',
         '-I', str(TARGET), '-I', str(REPO / 'native/src'), '-o', str(binary),
         str(HARNESS), str(REPO / 'native/src/jcs.c')],
        capture_output=True, text=True)
    assert result.returncode == 0, f'table harness build failed:\n{result.stderr}'
    assert not result.stderr.strip(), f'table harness build emitted warnings:\n{result.stderr}'
    run = subprocess.run([str(binary)], capture_output=True, text=True)
    assert run.returncode == 0, run.stderr
    return json.loads(run.stdout.strip().splitlines()[-1])


def test_generated_table_holds_exactly_the_bounded_triplet(table):
    assert table['kernel_read_count'] == 3
    assert [row['name'] for row in table['args']] == TRIPLET
    assert all(row['required'] == 1 for row in table['args']), 'a bounded field became optional'
    assert all(row['type'] == 1 for row in table['args']), 'a bounded field is not an integer'
    assert not any(name in [row['name'] for row in table['args']] for name in FORBIDDEN)


def test_schema_and_generated_table_agree_on_the_contract(table):
    schema = (REPO / 'tools' / 'primitive_iface' / 'schema.py').read_text()
    block = re.search(r"Op\('kernel\.read'.*?defer_reason=[^)]*\)", schema, re.S).group(0)
    args = re.findall(r"f\('([^']+)', 'int', (True|False)", block)
    assert args == [('region_index', 'True'), ('offset', 'True'), ('length', 'True')]
    header = (TARGET / 'ps4rf_optable_data.h').read_text()
    rows = re.findall(r'\{"([^"]+)", PS4RF_T_\w+, (\d)\},  /\* kernel\.read \*/', header)
    assert rows == [('region_index', '1'), ('offset', '1'), ('length', '1')]
    assert 'if (!found) return 0;' in header, 'unknown fields stopped failing closed'


# W14 (WIRE-CATALOG R3): the operation, its capability and the wire framing stay; the
# target-side route becomes the one wired privileged provider (dispatcher, not a loop hook).
def test_operation_capability_and_framing_are_unchanged():
    header = (TARGET / 'ps4rf_optable_data.h').read_text()
    assert '{"kernel.read", "kernel", "kernel.read"' in header
    assert 'PS4RF_ROUTE_PRIVILEGED_PROVIDER, PS4RF_TARGET_WIRED' in header
    assert 'kernel.read.bounded' not in header
    rows_with_route = [line for line in header.splitlines()
                       if 'PS4RF_ROUTE_PRIVILEGED_PROVIDER' in line and line.strip().startswith('{')]
    privileged = {line.split('"')[1] for line in rows_with_route}
    assert privileged == {'kernel.read', 'kernel.snapshot.recipe', 'ioctl.invoke'}, privileged
    assert len(rows_with_route) == 3, 'exactly three named operations may use the privileged route'
    wire = (REPO / 'native' / 'src' / 'ps4rf_protocol.c').read_text().lower()
    assert 'kread' not in wire


def test_agent_reads_body_arguments_and_refuses_explicitly():
    # W14: the agent's session loop holds NO kernel.read state, NO parse and NO call site. The
    # only productive path is the dispatcher's provider entry; the manifest gate refuses a
    # regression of this property.
    def code_only(text: str) -> str:
        """Comments may document the removal; only real code counts."""
        text = re.sub(r'/\*.*?\*/', ' ', text, flags=re.S)
        return re.sub(r'//[^\n]*', ' ', text)

    agent = code_only((TARGET / 'ps4rf_agent.c').read_text())
    assert 'kernel.read' not in agent, 'the agent still names the operation (special trigger)'
    assert 'kread' not in agent.lower(), 'kernel.read state is still in the session loop'
    assert 'ps4rf_kread' not in agent, 'the session loop still reaches the provider module'
    stub = code_only((TARGET / 'ps4rf_stub.c').read_text())
    assert stub.count('ps4rf_kread_run(') == 1, 'the provider must have exactly one run site'
    assert 'region_index' in stub and 'offset' in stub and 'length' in stub
    module = (TARGET / 'ps4rf_kread.c').read_text()
    assert 'jval_get' not in module, 'host input reached the provider module'
    assert 'PS4RF_KREAD_RUN_ARGUMENTS_INVALID' in module


def test_host_builds_exactly_the_approved_wire_body():
    """The body the session builds must be {operation, arguments:{triplet}} and nothing else."""
    session = (REPO / 'tools' / 'hostctl' / 'session.py').read_text()
    assert "body: dict = {'operation': op, 'arguments': arguments or {}}" in session
    from tools.hostctl import kreadlive as KL
    arguments, problems = KL.wire_request_for({'region': 'amd_iommu', 'region_index': 1,
                                               'offset': 0, 'length': 16})
    assert problems == []
    body = {'operation': KL.TRIGGER_OPERATION, 'arguments': arguments}
    assert body == {'operation': 'kernel.read',
                    'arguments': {'region_index': 1, 'offset': 0, 'length': 16}}
    assert not any(name in json.dumps(body) for name in
                   ('"addr"', '"address"', '"size"', 'pointer', '"va"'))


# --- the live error, reproduced against the real agent ------------------------------------------

@pytest.fixture(scope='module')
def kread_agent(tmp_path_factory) -> pathlib.Path:
    out = tmp_path_factory.mktemp('w13c2-host') / 'host'
    env = {'PS4RF_TARGET_KREAD': '1', 'PATH': '/usr/bin:/bin'}
    proc = subprocess.run(['sh', str(TARGET / 'build_host.sh'), str(out)], cwd=REPO,
                          capture_output=True, text=True, env=env)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    return out / 'ps4rfd_host'


def _field(payload, name):
    """The event as recorded (the sink stores the parsed body; tolerate either shape)."""
    if isinstance(payload, dict):
        if name in payload:
            return payload[name]
        for value in payload.values():
            found = _field(value, name)
            if found is not None:
                return found
    return None


def _run_one_request(binary: pathlib.Path, tmp_path: pathlib.Path, body: dict):
    """One session, one kernel.read request; returns (response, event)."""
    import sys
    import time
    sys.path.insert(0, str(REPO))
    from core.canonical import canonical_bytes
    from core.rpc import wire as WIRE
    from tools.hostctl.endpoint import SocketEndpoint
    from tools.hostctl.session import HostSession

    listener = socket.socket()
    listener.bind(('127.0.0.1', 0))
    listener.listen(1)
    port = listener.getsockname()[1]
    psk = tmp_path / 'psk.bin'
    psk.write_bytes(bytes(range(1, 33)))
    agent = subprocess.Popen(
        [str(binary), '--connect', '127.0.0.1', str(port), '--psk-file', str(psk),
         '--label', 'w13c2-args', '--context', 'offline-w13c2', '--lifetime', '60', '--idle', '30'],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    conn = None
    try:
        conn, _ = listener.accept()
        conn.settimeout(30)
        session = HostSession(SocketEndpoint(conn, timeout=30), psk.read_bytes(), accept_event=True)
        session.handshake()
        session.recv_ready()
        rid = 'REQ-' + 'c2' * 16
        if 'operation' not in body:
            response = session.request('kernel.read', body, request_id=rid)
        else:
            # The flat body cannot be produced through the public request API by design -- that API
            # always nests the arguments. Drive the session's own reader so the frame on the wire is
            # exactly the flat body the live attempt 2 sent.
            message = {'header': {'request_id': rid}, 'body': body}
            session.ep.send_all(WIRE.encode_frame(session._ch_h2a, 'REQUEST',
                                                  canonical_bytes(message)))
            response = None
            while True:
                mtype, rseq, plaintext, raw = session._recv_frame()
                routed = session._route(mtype, rseq, plaintext, raw, rid=rid)
                if routed is None:
                    continue
                if routed.get('bye'):
                    break
                response = json.loads(routed['plaintext'])
                break
        # W14: the read record rides the RESPONSE -- the agent has no second output path for it.
        session.close()
        record = response if _field(response, 'run_status_name') is not None else None
        return response, record
    finally:
        if conn is not None:
            conn.close()
        listener.close()
        if agent.poll() is None:
            agent.kill()


def test_nested_arguments_reach_the_provider(kread_agent, tmp_path):
    response, event = _run_one_request(
        kread_agent, tmp_path, {'region_index': 1, 'offset': 0, 'length': 16})
    # W14: the bounded read is served by the dispatcher's wired provider, so the response is a
    # success whose record carries the verdict of the read (the host stand-in has no kernel).
    assert response['status'] == 'OK', response
    assert event is not None, 'no kernel.read record in the response'
    assert _field(response, 'provider') == 'ps4rfd-kread-privileged'
    # The host stand-in has no kernel: kexec fails and the zeroed block must not read as a
    # successful callback, so validate() answers RESULT_INVALID. That is the positive proof that
    # the parse ACCEPTED the nested arguments and the bounded run was entered -- an argument
    # problem would have been refused earlier as ARGUMENT_INVALID.
    assert _field(event, 'run_status_name') == 'RESULT_INVALID', json.dumps(event)[:400]
    assert not _field(event, 'callback_executed')
    assert _field(event, 'cb_status_name') == 'NOT_EXECUTED'
    assert _field(event, 'bytes_hex') == ''


@pytest.mark.parametrize('name', sorted(REJECTED_BODIES))
def test_contract_violations_are_refused(kread_agent, tmp_path, name):
    body = REJECTED_BODIES[name]
    response, event = _run_one_request(kread_agent, tmp_path, body)
    assert response['status'] == 'ERROR'
    assert response['error']['code'] == 'ARGUMENT_INVALID', f'{name}: {response}'
    # W14: the router refuses before the single provider entry, so the bounded read is never
    # entered -- no record, no callback, no bytes, nobody's sentinel read as a value.
    assert event is None, f'{name}: a refusal must not look like a read: {json.dumps(event)[:200]}'
