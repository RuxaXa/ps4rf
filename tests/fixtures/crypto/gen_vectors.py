#!/usr/bin/env python3
"""PS4RF crypto/handshake vector catalog (P4/W1 prep, offline, deterministic).

Generates ``vectors-v1.json`` next to this file from two sources:

1. RFC test vectors (RFC 8439 sec. 2.8.2, RFC 5869 A.1-A.3, RFC 4231 sec. 4.2-4.8,
   RFC 8785 sec. 3.2.2 / Appendix B) embedded below as machine-extracted constants
   (provenance in README.md). Every constant is re-verified at generation time
   against an independent implementation (cryptography / hashlib / hmac / rfc8785);
   any mismatch aborts the build.
2. The frozen host implementation ``core/canonical.py`` + ``core/rpc/handshake.py``:
   handshake transcript, key derivation, proofs, nonce prefixes, AADs, sealed
   frames, the full handshake byte exchange, and boundary/error behaviour.

The output is meant to be consumed byte-exactly by the future native (C)
implementation; the harness contract is in ``docs/P4-W1-TESTVECTORS-SPEC.md``.

Run (from the repo root, venv on PATH):
    PATH="$PWD/.venv/bin:$PATH" python tests/fixtures/crypto/gen_vectors.py

Determinism: no timestamps, no absolute paths, sorted keys, trailing newline.
All keys/nonces below are TEST-ONLY constants (never used outside this catalog).
"""
from __future__ import annotations

import hashlib
import hmac as hmac_mod
import json
import math
import pathlib
import queue
import struct
import sys
import threading

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
import rfc8785

REPO_ROOT = pathlib.Path(__file__).resolve().parents[3]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from core.canonical import UnsafeNumber, canonical_bytes  # noqa: E402
from core.rpc.handshake import (  # noqa: E402
    EFFECTIVE_LAST_SEQ, LAST_SEQ, MAX_HANDSHAKE_BYTES, TAG_LEN, AuthenticationFailed,
    Direction, DirectionChannel, FrameLimitExceeded, ProtocolError, ReplayDetected,
    SequenceExhausted, _send_hs, agent_handshake, build_aad, derive_keys,
    host_handshake, nonce_prefix, proof, transcript_hash,
)

OUT_NAME = 'vectors-v1.json'
SCHEMA = 'ps4rf-crypto-vectors-v1'

# RFC constants: machine-extracted from the RFC texts (see README.md for the
# source URLs + sha256 of the fetched plain-text files and the extraction notes).
RFC_CONSTANTS = json.loads(
    r'''{
 "_provenance": {
  "rfc4231": {
   "bytes": 17725,
   "sha256": "72178527ce93500e730bc8eb182b857e583096d652b64ece0879c52ba1df973b",
   "url": "https://www.rfc-editor.org/rfc/rfc4231.txt"
  },
  "rfc5869": {
   "bytes": 25854,
   "sha256": "7a40eb3835b35fc947eb12a2ed614db079d43b26e50dbc537c31fba16397089c",
   "url": "https://www.rfc-editor.org/rfc/rfc5869.txt"
  },
  "rfc8439": {
   "bytes": 88847,
   "sha256": "25bef70fbf7a07ff45c2fe4cb7c6ce954eac687413d8610603268b4e4415324c",
   "url": "https://www.rfc-editor.org/rfc/rfc8439.txt"
  },
  "rfc8785": {
   "bytes": 41879,
   "sha256": "63d52294eb0e3f0014174288186d388b4ddbf2c67d1ce8af1d9726eb0c3ab240",
   "url": "https://www.rfc-editor.org/rfc/rfc8785.txt"
  }
 },
 "rfc4231_hmac_sha256": [
  {
   "case": 1,
   "data": "4869205468657265",
   "key": "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
   "mac": "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"
  },
  {
   "case": 2,
   "data": "7768617420646f2079612077616e7420666f72206e6f7468696e673f",
   "key": "4a656665",
   "mac": "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
  },
  {
   "case": 3,
   "data": "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
   "key": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
   "mac": "773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe"
  },
  {
   "case": 4,
   "data": "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd",
   "key": "0102030405060708090a0b0c0d0e0f10111213141516171819",
   "mac": "82558a389a443c0ea4cc819899f2083a85f0faa3e578f8077a2e3ff46729665b"
  },
  {
   "case": 6,
   "data": "54657374205573696e67204c6172676572205468616e20426c6f636b2d53697a65204b6579202d2048617368204b6579204669727374",
   "key": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
   "mac": "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54"
  },
  {
   "case": 7,
   "data": "5468697320697320612074657374207573696e672061206c6172676572207468616e20626c6f636b2d73697a65206b657920616e642061206c6172676572207468616e20626c6f636b2d73697a6520646174612e20546865206b6579206e6565647320746f20626520686173686564206265666f7265206265696e6720757365642062792074686520484d414320616c676f726974686d2e",
   "key": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
   "mac": "9b09ffa71b942fcb27635fbcd5b0e944bfdc63644f0713938a7f51535c3a35e2"
  }
 ],
 "rfc5869_hkdf_sha256": [
  {
   "L": 42,
   "case": 1,
   "ikm": "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
   "info": "f0f1f2f3f4f5f6f7f8f9",
   "okm": "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865",
   "prk": "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5",
   "salt": "000102030405060708090a0b0c"
  },
  {
   "L": 82,
   "case": 2,
   "ikm": "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f",
   "info": "b0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff",
   "okm": "b11e398dc80327a1c8e7f78c596a49344f012eda2d4efad8a050cc4c19afa97c59045a99cac7827271cb41c65e590e09da3275600c2f09b8367793a9aca3db71cc30c58179ec3e87c14c01d5c1f3434f1d87",
   "prk": "06a6b88c5853361a06104c9ceb35b45cef760014904671014a193f40c15fc244",
   "salt": "606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeaf"
  },
  {
   "L": 42,
   "case": 3,
   "ikm": "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
   "info": "",
   "okm": "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8",
   "prk": "19ef24a32c717b167f33a91d6f648bdf96596776afdb6377ac434c1c293ccb04",
   "salt": ""
  }
 ],
 "rfc8439_aead": {
  "aad": "50515253c0c1c2c3c4c5c6c7",
  "ciphertext": "d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d63dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b3692ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc3ff4def08e4b7a9de576d26586cec64b6116",
  "key": "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f",
  "nonce": "070000004041424344454647",
  "plaintext": "4c616469657320616e642047656e746c656d656e206f662074686520636c617373206f66202739393a204966204920636f756c64206f6666657220796f75206f6e6c79206f6e652074697020666f7220746865206675747572652c2073756e73637265656e20776f756c642062652069742e",
  "source": "RFC 8439 \u00a72.8.2",
  "tag": "1ae10b594f09e26a7e902ecbd0600691"
 },
 "rfc8785_appendix_b": [
  {
   "ieee754": "0000000000000000",
   "json": "0",
   "verified": true
  },
  {
   "ieee754": "8000000000000000",
   "json": "0",
   "verified": true
  },
  {
   "ieee754": "0000000000000001",
   "json": "5e-324",
   "verified": true
  },
  {
   "ieee754": "8000000000000001",
   "json": "-5e-324",
   "verified": true
  },
  {
   "ieee754": "7fefffffffffffff",
   "json": "1.7976931348623157e+308",
   "verified": true
  },
  {
   "ieee754": "ffefffffffffffff",
   "json": "-1.7976931348623157e+308",
   "verified": true
  },
  {
   "ieee754": "4340000000000000",
   "json": "9007199254740992",
   "verified": true
  },
  {
   "ieee754": "c340000000000000",
   "json": "-9007199254740992",
   "verified": true
  },
  {
   "ieee754": "4430000000000000",
   "json": "295147905179352830000",
   "verified": true
  },
  {
   "ieee754": "44b52d02c7e14af5",
   "json": "9.999999999999997e+22",
   "verified": true
  },
  {
   "ieee754": "44b52d02c7e14af6",
   "json": "1e+23",
   "verified": true
  },
  {
   "ieee754": "44b52d02c7e14af7",
   "json": "1.0000000000000001e+23",
   "verified": true
  },
  {
   "ieee754": "444b1ae4d6e2ef4e",
   "json": "999999999999999700000",
   "verified": true
  },
  {
   "ieee754": "444b1ae4d6e2ef4f",
   "json": "999999999999999900000",
   "verified": true
  },
  {
   "ieee754": "444b1ae4d6e2ef50",
   "json": "1e+21",
   "verified": true
  },
  {
   "ieee754": "3eb0c6f7a0b5ed8c",
   "json": "9.999999999999997e-7",
   "verified": true
  },
  {
   "ieee754": "3eb0c6f7a0b5ed8d",
   "json": "0.000001",
   "verified": true
  },
  {
   "ieee754": "41b3de4355555553",
   "json": "333333333.3333332",
   "verified": true
  },
  {
   "ieee754": "41b3de4355555554",
   "json": "333333333.33333325",
   "verified": true
  },
  {
   "ieee754": "41b3de4355555555",
   "json": "333333333.3333333",
   "verified": true
  },
  {
   "ieee754": "41b3de4355555556",
   "json": "333333333.3333334",
   "verified": true
  },
  {
   "ieee754": "41b3de4355555557",
   "json": "333333333.33333343",
   "verified": true
  },
  {
   "ieee754": "becbf647612f3696",
   "json": "-0.0000033333333333333333",
   "verified": true
  },
  {
   "ieee754": "43143ff3c1cb0959",
   "json": "1424953923781206.2",
   "verified": true
  }
 ],
 "rfc8785_sample": {
  "canonical": "{\"literals\":[null,true,false],\"numbers\":[333333333.3333333,1e+30,4.5,0.002,1e-27],\"string\":\"\u20ac$\\u000f\\nA'B\\\"\\\\\\\\\\\"/\"}",
  "canonical_utf8_hex": "7b226c69746572616c73223a5b6e756c6c2c747275652c66616c73655d2c226e756d62657273223a5b3333333333333333332e333333333333332c31652b33302c342e352c302e3030322c31652d32375d2c22737472696e67223a22e282ac245c75303030665c6e4127425c225c5c5c5c5c222f227d",
  "input_json": "{\n       \"numbers\": [333333333.33333329, 1E30, 4.50,\n                   2e-3, 0.000000000000000000000000001],\n       \"string\": \"\\u20ac$\\u000F\\u000aA'\\u0042\\u0022\\u005c\\\\\\\"\\/\",\n       \"literals\": [null, true, false]\n     }"
 }
}'''
)


# --------------------------------------------------------------------------
# 1. RFC anchors: verify the embedded constants against independent impls
# --------------------------------------------------------------------------

def _check_rfc(rc: dict) -> None:
    a = rc['rfc8439_aead']
    key, nonce = bytes.fromhex(a['key']), bytes.fromhex(a['nonce'])
    aad, pt = bytes.fromhex(a['aad']), bytes.fromhex(a['plaintext'])
    ct, tag = bytes.fromhex(a['ciphertext']), bytes.fromhex(a['tag'])
    got = ChaCha20Poly1305(key).encrypt(nonce, pt, aad)
    assert got == ct + tag, 'RFC 8439 §2.8.2 encryption mismatch'
    assert ChaCha20Poly1305(key).decrypt(nonce, ct + tag, aad) == pt, 'RFC 8439 decrypt mismatch'

    for c in rc['rfc5869_hkdf_sha256']:
        ikm, salt = bytes.fromhex(c['ikm']), bytes.fromhex(c['salt'])
        info, prk, okm = bytes.fromhex(c['info']), bytes.fromhex(c['prk']), bytes.fromhex(c['okm'])
        eff = salt if salt else b'\x00' * 32
        assert hmac_mod.new(eff, ikm, hashlib.sha256).digest() == prk, f"RFC 5869 case {c['case']} PRK"
        assert HKDF(algorithm=hashes.SHA256(), length=c['L'], salt=(salt or None),
                    info=info).derive(ikm) == okm, f"RFC 5869 case {c['case']} OKM"

    for c in rc['rfc4231_hmac_sha256']:
        assert hmac_mod.new(bytes.fromhex(c['key']), bytes.fromhex(c['data']),
                            hashlib.sha256).digest() == bytes.fromhex(c['mac']), \
            f"RFC 4231 case {c['case']}"

    s = rc['rfc8785_sample']
    assert rfc8785.dumps(json.loads(s['input_json'])).decode() == s['canonical'], 'RFC 8785 §3.2.2 sample'
    for row in rc['rfc8785_appendix_b']:
        val = struct.unpack('>d', bytes.fromhex(row['ieee754']))[0]
        assert rfc8785.dumps(val).decode() == row['json'], f"RFC 8785 App. B {row['ieee754']}"


# --------------------------------------------------------------------------
# 2. Protocol vectors: derive everything from the frozen modules
# --------------------------------------------------------------------------

PSK = bytes(range(32))               # TEST ONLY
AGENT_NONCE = bytes(range(16))       # TEST ONLY  00..0f
HOST_NONCE = bytes(range(16, 32))    # TEST ONLY  10..1f
SESSION_ID = 'SES-0123456789ABCDEF'

HELLO = {
    'msg': 'HELLO',
    'label': 'ps4rf-handshake-v1',
    'agent_version': 'vector-0.1.0',
    'transport': 'vector-transport',
    'context': 'vector-context',
    'provider': 'vector-provider',
    'nonce': AGENT_NONCE.hex(),
    'recovery_required': False,
}
HELLO_ACK = {
    'msg': 'HELLO_ACK',
    'protocol_version': 1,
    'session_id': SESSION_ID,
    'nonce': HOST_NONCE.hex(),
    'auth_required': True,
    'aead': 'AEAD_CHACHA20_POLY1305',
    'limits': {'max_chunk_bytes': 1048576, 'max_ir_bytes': 262144},
}


def _probe(sequence: int, tag: str) -> dict:
    """Shape-neutral plaintext for AEAD-layer parity (message shapes live in the
    parity catalog; this catalog only pins the cryptographic layer)."""
    return {'probe': 'aead-frame', 'sequence': sequence, 'tag': tag}


class _EP:
    """In-memory endpoint pair for the frozen handshake functions."""

    def __init__(self, out_q: queue.Queue, in_q: queue.Queue):
        self.out_q, self.in_q = out_q, in_q
        self.sent = []
        self._buf = b''

    def send_all(self, data: bytes) -> None:
        self.sent.append(bytes(data))
        self.out_q.put(bytes(data))

    def recv_exact(self, n: int) -> bytes:
        while len(self._buf) < n:
            self._buf += self.in_q.get(timeout=5)
        out, self._buf = self._buf[:n], self._buf[n:]
        return out


def _protocol_vectors() -> dict:
    th = transcript_hash(HELLO, HELLO_ACK)
    keys = derive_keys(PSK, AGENT_NONCE, HOST_NONCE, th)
    p_a2h = nonce_prefix(PSK, AGENT_NONCE, HOST_NONCE, th, Direction.AGENT_TO_HOST)
    p_h2a = nonce_prefix(PSK, AGENT_NONCE, HOST_NONCE, th, Direction.HOST_TO_AGENT)

    aads = []
    for ident, direction, mtype, seq in [
        ('h2a_request_seq0', Direction.HOST_TO_AGENT, 'REQUEST', 0),
        ('h2a_request_seq1', Direction.HOST_TO_AGENT, 'REQUEST', 1),
        ('a2h_response_seq0', Direction.AGENT_TO_HOST, 'RESPONSE', 0),
        ('a2h_event_seq0', Direction.AGENT_TO_HOST, 'EVENT', 0),
        ('a2h_bye_seq0', Direction.AGENT_TO_HOST, 'BYE', 0),
    ]:
        aads.append({'id': ident, 'direction': 'enum', 'message_type': mtype, 'sequence': seq,
                     'aad_hex': build_aad(1, SESSION_ID, seq, direction, mtype).hex()})
    aads.append({'id': 'h2a_request_seq0_raw_value_string', 'direction': 'raw-value',
                 'message_type': 'REQUEST', 'sequence': 0,
                 'aad_hex': build_aad(1, SESSION_ID, 0, Direction.HOST_TO_AGENT.value, 'REQUEST').hex()})

    def chan(key, prefix, direction, max_frame_bytes=1048576):
        return DirectionChannel(key, prefix, SESSION_ID, direction,
                                suite='AEAD_CHACHA20_POLY1305',
                                max_frame_bytes=max_frame_bytes, protocol_version=1)

    # Message types follow the spec F16 direction rule: host->agent carries
    # REQUEST; agent->host carries RESPONSE/EVENT/BYE. Plaintexts here are
    # deliberately shape-neutral (message shapes are pinned in the parity catalog).
    frames = []
    ch = chan(keys.k_host_to_agent, p_h2a, Direction.HOST_TO_AGENT)
    for seq_expected in (0, 1):
        pt = canonical_bytes(_probe(seq_expected, 'host-to-agent'))
        seq, ct = ch.seal('REQUEST', pt)
        frames.append({'id': f'h2a_request_seq{seq}', 'direction': 'host-to-agent',
                       'message_type': 'REQUEST', 'sequence': seq,
                       'nonce_hex': (p_h2a + seq.to_bytes(8, 'big')).hex(),
                       'plaintext_hex': pt.hex(), 'ciphertext_hex': ct.hex(),
                       'frame_len': len(ct)})
    ch2 = chan(keys.k_agent_to_host, p_a2h, Direction.AGENT_TO_HOST)
    for mtype, seq_expected in (('RESPONSE', 0), ('BYE', 1)):
        pt = canonical_bytes(_probe(seq_expected, 'agent-to-host'))
        seq, ct = ch2.seal(mtype, pt)
        frames.append({'id': f'a2h_{mtype.lower()}_seq{seq}', 'direction': 'agent-to-host',
                       'message_type': mtype, 'sequence': seq,
                       'nonce_hex': (p_a2h + seq.to_bytes(8, 'big')).hex(),
                       'plaintext_hex': pt.hex(), 'ciphertext_hex': ct.hex(),
                       'frame_len': len(ct)})

    # full handshake byte exchange (frozen agent_handshake <-> host_handshake)
    q_a2h, q_h2a = queue.Queue(), queue.Queue()
    agent_ep, host_ep = _EP(q_a2h, q_h2a), _EP(q_h2a, q_a2h)
    result = {}

    def _host():
        result['host_keys'], result['host_hello'] = host_handshake(host_ep, PSK, HELLO_ACK)

    t = threading.Thread(target=_host, daemon=True)
    t.start()
    agent_keys, ack_seen = agent_handshake(agent_ep, PSK, HELLO)
    t.join(timeout=5)
    assert not t.is_alive(), 'host handshake did not finish'
    assert ack_seen == HELLO_ACK and result['host_hello'] == HELLO
    assert agent_keys.k_hs == result['host_keys'].k_hs, 'agent/host k_hs mismatch'
    assert [f['id'] for f in frames] == ['h2a_request_seq0', 'h2a_request_seq1',
                                         'a2h_response_seq0', 'a2h_bye_seq1']

    exchange = {
        'agent_sent': [{'id': 'hello', 'hex': agent_ep.sent[0].hex()},
                       {'id': 'auth', 'hex': agent_ep.sent[1].hex()}],
        'host_sent': [{'id': 'hello_ack', 'hex': host_ep.sent[0].hex()},
                      {'id': 'auth_ack', 'hex': host_ep.sent[1].hex()}],
        'hello_canonical_hex': canonical_bytes(HELLO).hex(),
        'hello_ack_canonical_hex': canonical_bytes(HELLO_ACK).hex(),
        'auth_mac_hex': proof(keys.k_hs, 'agent', th).hex(),
        'auth_ack_mac_hex': proof(keys.k_hs, 'host', th).hex(),
    }

    return {
        'test_only_material': {
            'warning': 'TEST-ONLY constants; never valid as production keys.',
            'psk_hex': PSK.hex(), 'agent_nonce_hex': AGENT_NONCE.hex(),
            'host_nonce_hex': HOST_NONCE.hex(), 'session_id': SESSION_ID,
        },
        'objects': {'hello': HELLO, 'hello_ack': HELLO_ACK,
                    'probe_frames': _probe(0, 'host-to-agent')},
        'transcript_sha256': th.hex(),
        'keys': {'k_hs': keys.k_hs.hex(), 'k_agent_to_host': keys.k_agent_to_host.hex(),
                 'k_host_to_agent': keys.k_host_to_agent.hex()},
        'proofs': {'agent': proof(keys.k_hs, 'agent', th).hex(),
                   'host': proof(keys.k_hs, 'host', th).hex()},
        'nonce_prefixes': {'agent_to_host': p_a2h.hex(), 'host_to_agent': p_h2a.hex()},
        'direction_strings': {
            'enum_str': str(Direction.AGENT_TO_HOST),
            'enum_value': Direction.AGENT_TO_HOST.value,
            'note': ('frozen build_aad uses str(direction); with the Direction enum this '
                     'yields "Direction.AGENT_TO_HOST". AAD bytes below encode the frozen '
                     'behaviour; see docs/P4-W1-TESTVECTORS-SPEC.md finding F1.'),
        },
        'aad': aads,
        'frames': frames,
        'exchange': exchange,
        'constants': {'TAG_LEN': TAG_LEN, 'MAX_HANDSHAKE_BYTES': MAX_HANDSHAKE_BYTES,
                      'LAST_SEQ': LAST_SEQ, 'EFFECTIVE_LAST_SEQ': EFFECTIVE_LAST_SEQ,
                      'default_max_frame_bytes': 1048576,
                      'aead_suites': ['AEAD_CHACHA20_POLY1305', 'AES_256_GCM']},
    }


def _boundaries() -> list:
    out = []

    def case(ident, desc, fn):
        try:
            val = fn()
            out.append({'id': ident, 'description': desc, 'outcome': 'ok', 'result': val})
        except Exception as exc:  # noqa: BLE001 — the class name is the vector
            out.append({'id': ident, 'description': desc, 'outcome': 'raises',
                        'exception': type(exc).__name__})

    case('canonical_int_2p53', 'int at 2**53 violates the safe-number policy',
         lambda: canonical_bytes({'a': 2 ** 53}).hex())
    case('canonical_int_minus_2p53', 'int at -2**53 violates the safe-number policy',
         lambda: canonical_bytes({'a': -(2 ** 53)}).hex())
    case('canonical_int_2p53_minus_1_ok', 'largest safe integer is accepted',
         lambda: canonical_bytes([2 ** 53 - 1]).hex())
    case('canonical_float_nan', 'NaN is refused before serialization',
         lambda: canonical_bytes({'a': float('nan')}).hex())
    case('canonical_float_inf', 'Infinity is refused before serialization',
         lambda: canonical_bytes({'a': float('inf')}).hex())
    case('canonical_float_integer_valued_1e30', '1e30 is integer-valued and beyond SAFE_MAX',
         lambda: canonical_bytes([1e30]).hex())
    case('canonical_float_neg_zero', '-0.0 serializes as 0 (JCS)',
         lambda: canonical_bytes([-0.0]).hex())
    case('canonical_float_4_5_ok', 'plain fraction accepted', lambda: canonical_bytes([4.5]).hex())
    case('canonical_nonstring_key', 'non-string JSON object key is refused',
         lambda: canonical_bytes({1: 'x'}).hex())

    case('aad_seq_2p53_minus_1_ok', 'AAD still encodable at the safe-number ceiling',
         lambda: build_aad(1, SESSION_ID, 2 ** 53 - 1, Direction.AGENT_TO_HOST, 'REQUEST').hex())
    case('aad_seq_2p53_rejected', 'one past the ceiling: AAD becomes unencodable',
         lambda: build_aad(1, SESSION_ID, 2 ** 53, Direction.AGENT_TO_HOST, 'REQUEST').hex())

    th = transcript_hash(HELLO, HELLO_ACK)
    case('derive_keys_bad_secret_len', '31-byte secret refused',
         lambda: derive_keys(b'x' * 31, AGENT_NONCE, HOST_NONCE, th) and None)
    case('derive_keys_bad_nonce_len', '15-byte agent nonce refused',
         lambda: derive_keys(PSK, AGENT_NONCE[:15], HOST_NONCE, th) and None)
    case('channel_bad_suite', 'unknown AEAD suite refused',
         lambda: DirectionChannel(b'k' * 32, b'abcd', SESSION_ID, Direction.AGENT_TO_HOST,
                                  suite='ROT13').seal('REQUEST', b'x'))
    case('channel_bad_key_len', 'short channel key refused',
         lambda: DirectionChannel(b'short', b'abcd', SESSION_ID, Direction.AGENT_TO_HOST))

    def oversize_then_ok():
        c = DirectionChannel(bytes(range(32)), b'abcd', SESSION_ID, Direction.AGENT_TO_HOST,
                             max_frame_bytes=64)
        try:
            c.seal('REQUEST', b'x' * 49)
            raise AssertionError('expected FrameLimitExceeded')
        except FrameLimitExceeded:
            pass
        seq, ct = c.seal('REQUEST', b'ok')
        return {'next_seq': seq, 'next_ciphertext_hex': ct.hex()}
    case('seal_oversize_consumes_no_sequence', 'oversize reject leaves the sequence counter untouched',
         oversize_then_ok)

    def wrong_seq_then_ok():
        k, p = bytes(range(32)), b'abcd'
        a = DirectionChannel(k, p, SESSION_ID, Direction.AGENT_TO_HOST, max_frame_bytes=1024)
        b = DirectionChannel(k, p, SESSION_ID, Direction.AGENT_TO_HOST, max_frame_bytes=1024)
        _seq0, ct0 = a.seal('REQUEST', b'first')
        a.seal('REQUEST', b'second')
        first = None
        try:
            b.open('REQUEST', 1, ct0)
        except ReplayDetected:
            first = 'ReplayDetected'
        assert first == 'ReplayDetected'
        assert b.open('REQUEST', 0, ct0) == b'first'
        return {'first_open': first, 'then_seq0_ok': True}
    case('open_wrong_sequence_then_correct', 'duplicate/skip detected; correct sequence still opens',
         wrong_seq_then_ok)

    def tampered_then_ok():
        k, p = bytes(range(32)), b'abcd'
        a = DirectionChannel(k, p, SESSION_ID, Direction.AGENT_TO_HOST, max_frame_bytes=1024)
        b = DirectionChannel(k, p, SESSION_ID, Direction.AGENT_TO_HOST, max_frame_bytes=1024)
        _seq0, ct0 = a.seal('REQUEST', b'payload')
        bad = bytearray(ct0)
        bad[-1] ^= 0x01
        first = None
        try:
            b.open('REQUEST', 0, bytes(bad))
        except AuthenticationFailed:
            first = 'AuthenticationFailed'
        assert first == 'AuthenticationFailed'
        assert b.open('REQUEST', 0, ct0) == b'payload'
        return {'tampered_open': first, 'then_untampered_ok': True}
    case('open_tampered_tag_then_ok', 'tag tamper refused with the PS4RF exception (D9); untampered '
         'frame still opens', tampered_then_ok)

    def oversize_ct():
        b = DirectionChannel(bytes(range(32)), b'abcd', SESSION_ID, Direction.AGENT_TO_HOST,
                             max_frame_bytes=64)
        b.open('REQUEST', 0, bytes(65))
    case('open_oversize_ciphertext', 'ciphertext beyond max_frame_bytes refused', oversize_ct)

    def sequence_exhausted():
        c = DirectionChannel(bytes(range(32)), b'abcd', SESSION_ID, Direction.AGENT_TO_HOST,
                             max_frame_bytes=1024)
        c._send = EFFECTIVE_LAST_SEQ + 1  # internal counter probe (documented)
        c.seal('REQUEST', b'x')
    case('seal_sequence_exhausted', 'send counter past EFFECTIVE_LAST_SEQ refused (D8; internal '
         'probe)', sequence_exhausted)

    def ceiling_then_exhausted():
        c = DirectionChannel(bytes(range(32)), b'abcd', SESSION_ID, Direction.AGENT_TO_HOST,
                             max_frame_bytes=1024)
        c._send = EFFECTIVE_LAST_SEQ
        seq, _ct = c.seal('REQUEST', b'last-valid')
        assert seq == EFFECTIVE_LAST_SEQ
        second = None
        try:
            c.seal('REQUEST', b'next')
        except SequenceExhausted:
            second = 'SequenceExhausted'
        assert second == 'SequenceExhausted'
        return {'last_valid_sequence': seq, 'then': second}
    case('seal_at_effective_ceiling_then_exhausted', 'last valid sequence seals; the next one fails '
         'closed with no wraparound (D8)', ceiling_then_exhausted)

    def handshake_oversize():
        class _NullEP:
            def send_all(self, data):
                raise AssertionError('oversize payload must not reach the socket')

            def recv_exact(self, n):
                raise AssertionError('no read expected')
        _send_hs(_NullEP(), {'x': 'a' * 70000})
    case('handshake_frame_oversize', 'handshake frame beyond 64 KiB refused before the socket',
         handshake_oversize)

    return out


def build() -> dict:
    rc = json.loads(json.dumps(RFC_CONSTANTS))  # copy
    _check_rfc(rc)
    proto = _protocol_vectors()
    return {
        'schema': SCHEMA,
        'frozen_sources': {
            'core/canonical.py': hashlib.sha256((REPO_ROOT / 'core/canonical.py').read_bytes()).hexdigest(),
            'core/rpc/handshake.py': hashlib.sha256((REPO_ROOT / 'core/rpc/handshake.py').read_bytes()).hexdigest(),
        },
        'rfc_vectors': rc,
        'protocol': proto,
        'boundaries': _boundaries(),
    }


def render(vectors: dict) -> bytes:
    return (json.dumps(vectors, indent=1, sort_keys=True, ensure_ascii=False) + '\n').encode('utf-8')


def main() -> int:
    vectors = build()
    out = pathlib.Path(__file__).resolve().parent / OUT_NAME
    data = render(vectors)
    out.write_bytes(data)
    print(f'wrote {out} ({len(data)} bytes)')
    print(f'  schema={vectors["schema"]} rfc_cases={len(vectors["rfc_vectors"]["rfc4231_hmac_sha256"])}'
          f'+{len(vectors["rfc_vectors"]["rfc5869_hkdf_sha256"])}+1'
          f' appB={len(vectors["rfc_vectors"]["rfc8785_appendix_b"])}'
          f' frames={len(vectors["protocol"]["frames"])} boundaries={len(vectors["boundaries"])}')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
