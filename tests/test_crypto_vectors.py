"""Self-verification for the P4/W1 crypto/handshake vector catalog.

Guarantees:
* the committed catalog is byte-reproducible from the committed generator;
* every RFC constant in the catalog re-verifies against independent
  implementations (cryptography / hashlib / hmac / rfc8785);
* the catalog's protocol + boundary sections still match the frozen modules
  (and the embedded module hashes match the files on disk);
* the two carried findings (AAD direction string, sequence ceiling) stay pinned.
"""
from __future__ import annotations

import hashlib
import importlib.util
import json
import pathlib

REPO = pathlib.Path(__file__).resolve().parents[1]
CRYPTO_DIR = REPO / 'tests' / 'fixtures' / 'crypto'
VECTORS = CRYPTO_DIR / 'vectors-v1.json'


def _load_generator():
    spec = importlib.util.spec_from_file_location('ps4rf_crypto_gen', CRYPTO_DIR / 'gen_vectors.py')
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


gen = _load_generator()
FILE = json.loads(VECTORS.read_text())


def test_catalog_is_byte_reproducible():
    assert gen.render(gen.build()) == VECTORS.read_bytes()


def test_rfc_constants_verify_against_independent_implementations():
    # raises AssertionError on any mismatch
    gen._check_rfc(FILE['rfc_vectors'])


def test_frozen_module_hashes_match_catalog():
    for rel, sha in FILE['frozen_sources'].items():
        assert hashlib.sha256((REPO / rel).read_bytes()).hexdigest() == sha, rel


def test_protocol_section_matches_frozen_implementation():
    assert gen._protocol_vectors() == FILE['protocol']


def test_boundaries_section_matches_frozen_implementation():
    assert gen._boundaries() == FILE['boundaries']


def test_sequence_ceiling_finding_is_pinned():
    from core.canonical import UnsafeNumber, canonical_bytes
    from core.rpc.handshake import Direction, build_aad

    sid = FILE['protocol']['test_only_material']['session_id']
    assert canonical_bytes([2 ** 53 - 1])
    assert build_aad(1, sid, 2 ** 53 - 1, Direction.AGENT_TO_HOST, 'REQUEST')
    for bad in (lambda: canonical_bytes([2 ** 53]),
                lambda: build_aad(1, sid, 2 ** 53, Direction.AGENT_TO_HOST, 'REQUEST')):
        try:
            bad()
            raise AssertionError('expected UnsafeNumber at the sequence ceiling')
        except UnsafeNumber:
            pass


def test_aad_direction_finding_is_pinned():
    ds = FILE['protocol']['direction_strings']
    assert ds['enum_str'] == 'Direction.AGENT_TO_HOST'
    assert ds['enum_value'] == 'agent-to-host'
    aads = {a['id']: a['aad_hex'] for a in FILE['protocol']['aad']}
    assert aads['h2a_request_seq0'] != aads['h2a_request_seq0_raw_value_string']
    # the enum form is what the frozen DirectionChannel emits
    assert bytes.fromhex(aads['h2a_request_seq0']).startswith(b'{"direction":"Direction.HOST_TO_AGENT"')


def test_frames_follow_spec_f16_direction_rule():
    frames = {f['id']: f for f in FILE['protocol']['frames']}
    for ident, f in frames.items():
        if ident.startswith('h2a_'):
            assert f['message_type'] == 'REQUEST', ident
        else:
            assert f['message_type'] in ('RESPONSE', 'EVENT', 'BYE'), ident
    assert frames['a2h_response_seq0']['sequence'] == 0
    assert frames['a2h_bye_seq1']['sequence'] == 1


def test_catalog_has_no_paths_or_production_material():
    text = VECTORS.read_text()
    assert 'TEST-ONLY' in text
    assert FILE['schema'] == 'ps4rf-crypto-vectors-v1'
    for forbidden in ('/home/', '/root/', '/tmp/', 'C:\\\\', '.venv', 'site-packages'):
        assert forbidden not in text, forbidden
