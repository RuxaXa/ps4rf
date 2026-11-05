"""Self-verifying checks for the parity vector catalog (P4/W2 prep).

The catalog must be (a) byte-reproducible from its generator, (b) derived from
the frozen sources currently on disk, (c) consistent with the crypto catalog's
shared TEST-ONLY session, and (d) reflective of the observed frozen behaviour:
every behavioural section is recomputed here and compared by deep equality.
"""
from __future__ import annotations

import hashlib
import importlib.util
import json
import pathlib
import sys

REPO_ROOT = pathlib.Path(__file__).resolve().parents[1]
FIXTURES = REPO_ROOT / 'tests' / 'fixtures'
PARITY_FILE = FIXTURES / 'parity' / 'vectors-v1.json'
CRYPTO_FILE = FIXTURES / 'crypto' / 'vectors-v1.json'


def _load_generator():
    spec = importlib.util.spec_from_file_location(
        'ps4rf_parity_gen', FIXTURES / 'parity' / 'gen_parity.py')
    assert spec is not None and spec.loader is not None, 'generator not loadable'
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)
    return mod


GEN = _load_generator()
FILE_BYTES = PARITY_FILE.read_bytes()
FILE = json.loads(FILE_BYTES)
CRYPTO = json.loads(CRYPTO_FILE.read_bytes())


def test_catalog_is_byte_reproducible():
    assert GEN.render(GEN.build()) == FILE_BYTES


def test_frozen_sources_match_files_on_disk():
    assert FILE['frozen_sources'], 'no frozen sources recorded'
    for rel, digest in FILE['frozen_sources'].items():
        actual = hashlib.sha256((REPO_ROOT / rel).read_bytes()).hexdigest()
        assert actual == digest, f'frozen module changed: {rel}'


def test_shared_session_material_matches_crypto_catalog():
    proto = CRYPTO['protocol']
    mine = FILE['session']
    assert mine['test_only_material']['psk_hex'] == proto['test_only_material']['psk_hex']
    assert mine['test_only_material']['agent_nonce_hex'] == proto['test_only_material']['agent_nonce_hex']
    assert mine['test_only_material']['host_nonce_hex'] == proto['test_only_material']['host_nonce_hex']
    assert mine['test_only_material']['session_id'] == proto['test_only_material']['session_id']
    assert mine['transcript_sha256'] == proto['transcript_sha256']
    assert mine['keys'] == proto['keys']
    assert mine['nonce_prefixes'] == proto['nonce_prefixes']


def test_frames_follow_the_direction_fsm():
    assert FILE['direction_fsm']['host_to_agent'] == ['REQUEST']
    assert set(FILE['direction_fsm']['agent_to_host']) == {'RESPONSE', 'EVENT', 'BYE'}
    for frame in FILE['frames']:
        if frame['direction'] == 'host-to-agent':
            assert frame['message_type'] == 'REQUEST', frame['id']
        else:
            assert frame['message_type'] in ('RESPONSE', 'BYE'), frame['id']
    seqs = [(f['direction'], f['sequence']) for f in FILE['frames']]
    assert seqs == [('host-to-agent', 0), ('host-to-agent', 1),
                    ('agent-to-host', 0), ('agent-to-host', 1), ('agent-to-host', 2)]


def test_frames_recompute_from_frozen_channels():
    assert FILE['frames'] == GEN._frames(GEN._session())


def test_registry_vectors_recompute():
    assert FILE['registry'] == GEN._registry_cases()


def test_pool_vectors_recompute():
    from core.rpc.pool import TaskState
    assert FILE['pool']['cases'] == GEN._pool_cases()
    assert FILE['pool']['task_states'] == [t.value for t in TaskState]


def test_agent_vectors_recompute():
    assert FILE['agent'] == GEN._agent_cases()


def test_channel_vectors_recompute():
    assert FILE['channel'] == GEN._channel_cases(GEN._session())


def test_pool_and_hang_metadata():
    assert FILE['pool']['task_states'] == ['QUEUED', 'RUNNING', 'COMPLETED', 'CANCELED_AT_RECOVERY']
    assert FILE['hang']['exception_class'] == 'MockHangReleased'
    assert 'Exception' in FILE['hang']['bases']
    applied = [d['decision'] for d in FILE['w0_decisions_applied']]
    assert applied == ['D8', 'D9', 'D12', 'D13'], 'W0 decisions must stay visible in the catalog'


def test_sections_cover_the_frozen_verdicts():
    pool = {c['id']: c['observed'] for c in FILE['pool']['cases']}
    assert pool['capacity_and_too_many_inflight']['submit_b'] == 'TOO_MANY_INFLIGHT'
    assert pool['poisoned_and_no_token_leak']['submit_after_poison'] == 'POISONED'
    assert pool['poisoned_and_no_token_leak']['available_tokens'] == 2
    assert pool['worker_crash_leaves_task_pending_until_finish']['available_tokens_after_crash'] == 1
    agent = {c['id']: c['observed'] for c in FILE['agent']['cases']}
    sent = agent['canceled_request_emits_recovery_required']['sent']
    assert sent[0]['payload'] == {'status': 'ERROR', 'error': {'code': 'SESSION_RECOVERY_REQUIRED'}}
    assert agent['canceled_request_emits_recovery_required']['pending_count'] == 0
    assert agent['worker_crash_records_evidence']['evidence'][0]['result'] == 'WORKER_CRASH'
    chan = {c['id']: c for c in FILE['channel']['cases']}
    assert chan['open_wrong_message_type_rejected']['exception'] == 'AuthenticationFailed'
    assert chan['cross_direction_open_rejected']['exception'] == 'AuthenticationFailed'
    assert chan['open_sequence_gap_rejected']['exception'] == 'ReplayDetected'


def test_wire_mapping_v1_is_defined_and_single_sourced():
    wire = FILE['wire_frame']
    assert wire['wire_spec_version'] == 1
    assert wire['header_bytes'] == 13
    assert wire['header_layout'].startswith('4-byte big-endian ciphertext length')
    assert 'DEFINED' in wire['type_table_status']
    assert wire['type_table'] == {'0x01': 'REQUEST', '0x02': 'RESPONSE', '0x03': 'EVENT',
                                  '0x04': 'BYE', '0x05': 'READY'}
    assert wire['type_table_inverse_source'].endswith('(core/rpc/wire.py)')
    assert wire['reserved_types'] == ['EVENT', 'READY']
    assert wire['active_types_w2'] == ['REQUEST', 'RESPONSE', 'BYE']
    assert wire['source'].startswith('docs/spec-history/Pasted_text(5).txt')
    applied = {d['decision']: d for d in FILE['w0_decisions_applied']}
    assert set(applied) == {'D8', 'D9', 'D12', 'D13'}
    assert 'no library exception escapes' in applied['D9']['effect']


def test_frame_wire_bytes_decode_back_to_the_recorded_plaintext():
    """Byte-level pin: every recorded wire frame decodes to its recorded plaintext."""
    from core.rpc.handshake import DirectionChannel
    from core.rpc.wire import FRAME_HEADER_BYTES, decode_frame

    th = GEN._session()['_th_bytes']
    keys = GEN.derive_keys(GEN.PSK, GEN.AGENT_NONCE, GEN.HOST_NONCE, th)
    channels = {}
    for direction in (GEN.Direction.HOST_TO_AGENT, GEN.Direction.AGENT_TO_HOST):
        key = (keys.k_agent_to_host if direction is GEN.Direction.AGENT_TO_HOST
               else keys.k_host_to_agent)
        prefix = GEN.nonce_prefix(GEN.PSK, GEN.AGENT_NONCE, GEN.HOST_NONCE, th, direction)
        channels[direction] = DirectionChannel(key, prefix, GEN.SESSION_ID, direction,
                                              suite='AEAD_CHACHA20_POLY1305',
                                              max_frame_bytes=1048576, protocol_version=1)
    direction_of = {'host-to-agent': GEN.Direction.HOST_TO_AGENT,
                    'agent-to-host': GEN.Direction.AGENT_TO_HOST}
    assert FILE['frames'], 'no frames recorded'
    for frame in FILE['frames']:
        wire = bytes.fromhex(frame['wire_hex'])
        assert wire[:FRAME_HEADER_BYTES].hex() == frame['header_hex'], frame['id']
        assert int.from_bytes(wire[:4], 'big') == frame['frame_len'], frame['id']
        assert wire[4] == frame['frame_type_byte'], frame['id']
        mtype, sequence, plaintext = decode_frame(channels[direction_of[frame['direction']]], wire)
        assert (mtype, sequence) == (frame['message_type'], frame['sequence']), frame['id']
        assert plaintext.hex() == frame['canonical_hex'], frame['id']


def test_catalog_has_no_paths_or_production_material():
    text = FILE_BYTES.decode('utf-8')
    for needle in ('/home/', 'REPO_ROOT', 'PRIVATE KEY', 'password'):
        assert needle not in text, f'catalog leaks {needle!r}'
