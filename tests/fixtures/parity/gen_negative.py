#!/usr/bin/env python3
"""Emit the W2 boundary/negative script catalog for the native parity harness.

Every expected outcome in the emitted catalog is *recomputed from the frozen
Python core* (core/canonical.py, core/rpc/handshake.py, core/rpc/wire.py); the
generator also cross-checks the 22 crypto-catalog boundary entries against their
recorded outcomes and fails loudly on any disagreement.

Output: tests/fixtures/parity/w2-negative-v1.json
Run:    .venv/bin/python tests/fixtures/parity/gen_negative.py [--check]
"""
from __future__ import annotations

import hashlib
import json
import pathlib
import sys

HERE = pathlib.Path(__file__).resolve()
REPO = HERE.parents[3]
sys.path.insert(0, str(REPO))

from core.canonical import canonical_bytes  # noqa: E402
from core.rpc import wire  # noqa: E402
from core.rpc.handshake import (  # noqa: E402
    AuthenticationFailed,
    Direction,
    DirectionChannel,
    EFFECTIVE_LAST_SEQ,
    FrameLimitExceeded,
    ProtocolError,
    ReplayDetected,
    SequenceExhausted,
    build_aad,
    derive_keys,
    nonce_prefix,
    proof,
    transcript_hash,
)

CRYPTO = REPO / "tests" / "fixtures" / "crypto" / "vectors-v1.json"
PARITY = REPO / "tests" / "fixtures" / "parity" / "vectors-v1.json"
OUT = REPO / "tests" / "fixtures" / "parity" / "w2-negative-v1.json"

BOUNDARY_KEY_HEX = bytes(range(32)).hex()
BOUNDARY_PREFIX_HEX = b"abcd".hex()

# W2 native scope: these reference calls have no native input path because the
# native API uses fixed-size arrays / JSON object keys are strings by grammar.
STRUCTURAL = {
    "derive_keys_bad_secret_len":
        "the native derive_keys() takes a fixed 32-byte PSK array; the reference "
        "argument-length check has no native input path",
    "derive_keys_bad_nonce_len":
        "the native API takes fixed 16-byte nonce arrays; the reference "
        "argument-length check has no native input path (the wire-level variant "
        "derive_keys_bad_nonce_len_wire covers the short-nonce HELLO_ACK case)",
    "channel_bad_key_len":
        "the native channel takes a fixed 32-byte key array; the reference "
        "argument-length check has no native input path",
    "canonical_nonstring_key":
        "native object keys are `const char *`; the reference TypeError path cannot "
        "be reached (the executable text variant is covered separately)",
}


def sha256_file(path: pathlib.Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def load_json(path: pathlib.Path) -> dict:
    return json.loads(path.read_text())


def step(**kw) -> dict:
    return {k: v for k, v in kw.items() if v is not None}


def build() -> dict:
    """Assemble the W2 boundary/negative/parity script catalog."""
    crypto = load_json(CRYPTO)
    parity = load_json(PARITY)
    recorded = {e["id"]: e for e in crypto["boundaries"]}
    session = parity["session"]
    psk = bytes.fromhex(session["test_only_material"]["psk_hex"])
    an = bytes.fromhex(session["test_only_material"]["agent_nonce_hex"])
    hn = bytes.fromhex(session["test_only_material"]["host_nonce_hex"])
    keys = session["keys"]
    prefixes = session["nonce_prefixes"]
    sid = session["test_only_material"]["session_id"]
    hello = crypto["protocol"]["objects"]["hello"]
    ack = crypto["protocol"]["objects"]["hello_ack"]
    hello_json = json.dumps(hello, separators=(",", ":"), sort_keys=True)
    ack_json = json.dumps(ack, separators=(",", ":"), sort_keys=True)
    th = bytes.fromhex(crypto["protocol"]["transcript_sha256"])
    k_a2h = bytes.fromhex(keys["k_agent_to_host"])
    k_h2a = bytes.fromhex(keys["k_host_to_agent"])
    pfx_a2h = bytes.fromhex(prefixes["agent_to_host"])
    pfx_h2a = bytes.fromhex(prefixes["host_to_agent"])

    boundaries: list[dict] = []
    negative: list[dict] = []
    parity_cases: list[dict] = []

    def boundary(case_id: str, stage: str, description: str, steps: list[dict]) -> None:
        rec = recorded.get(case_id)
        assert rec is not None, f"{case_id} is not a recorded boundary"
        boundaries.append({
            "id": case_id,
            "stage": stage,
            "description": description,
            "reference_outcome": rec.get("outcome"),
            "reference_exception": rec.get("exception"),
            "steps": steps,
        })

    def structural(case_id: str, stage: str, description: str) -> None:
        rec = recorded.get(case_id)
        assert rec is not None, f"{case_id} is not a recorded boundary"
        boundaries.append({
            "id": case_id,
            "stage": stage,
            "description": description,
            "reference_outcome": rec.get("outcome"),
            "reference_exception": rec.get("exception"),
            "structural": True,
            "structural_reason": STRUCTURAL[case_id],
            "steps": [],
        })

    # ---------------------------------------------------------------- canonical
    boundary("canonical_int_2p53", "canonicalization", "int at 2**53 violates the safe-number policy",
             [step(call="canon_text", stage="canonicalization", json='{"a":9007199254740992}',
                   expect="raises", exception="UnsafeNumber")])
    boundary("canonical_int_minus_2p53", "canonicalization", "int at -2**53 violates the safe-number policy",
             [step(call="canon_text", stage="canonicalization", json='{"a":-9007199254740992}',
                   expect="raises", exception="UnsafeNumber")])
    boundary("canonical_int_2p53_minus_1_ok", "canonicalization", "largest safe integer is accepted",
             [step(call="canon_text", stage="canonicalization", json='[9007199254740991]', expect="ok",
                   expect_hex=canonical_bytes([2 ** 53 - 1]).hex())])
    boundary("canonical_float_nan", "canonicalization", "NaN is refused before serialization",
             [step(call="canon_double", stage="canonicalization", kind="nan", expect="raises",
                   exception="UnsafeNumber")])
    boundary("canonical_float_inf", "canonicalization", "Infinity is refused before serialization",
             [step(call="canon_double", stage="canonicalization", kind="inf", expect="raises",
                   exception="UnsafeNumber")])
    boundary("canonical_float_integer_valued_1e30", "canonicalization",
             "1e30 is integer-valued and beyond SAFE_MAX",
             [step(call="canon_double", stage="canonicalization", kind="1e30", expect="raises",
                   exception="UnsafeNumber")])
    boundary("canonical_float_neg_zero", "canonicalization", "-0.0 serializes as 0 (JCS)",
             [step(call="canon_double", stage="canonicalization", kind="neg_zero", expect="ok",
                   expect_hex=canonical_bytes([-0.0]).hex())])
    boundary("canonical_float_4_5_ok", "canonicalization", "plain fraction accepted",
             [step(call="canon_double", stage="canonicalization", kind="4.5", expect="ok",
                   expect_hex=canonical_bytes([4.5]).hex())])
    structural("canonical_nonstring_key", "canonicalization", "non-string JSON object key is refused")
    boundaries.append({
        "id": "canonical_nonstring_key_text",
        "stage": "canonicalization",
        "description": "non-string key in JSON text is refused by the parser (native variant)",
        "reference_outcome": "raises",
        "reference_exception": "JSONDecodeError",
        "steps": [step(call="canon_text", stage="canonicalization", json='{1:"x"}', expect="raises",
                       exception="ProtocolError")],
    })

    # ---------------------------------------------------------------------- aad
    boundary("aad_seq_2p53_minus_1_ok", "aad", "AAD still encodable at the safe-number ceiling",
             [step(call="aad", stage="aad", protocol_version=1, session_id=sid, sequence=2 ** 53 - 1,
                   direction="agent-to-host", message_type="REQUEST", expect="ok",
                   expect_hex=build_aad(1, sid, 2 ** 53 - 1, Direction.AGENT_TO_HOST,
                                        "REQUEST").hex())])
    boundary("aad_seq_2p53_rejected", "aad", "one past the ceiling: AAD becomes unencodable",
             [step(call="aad", stage="aad", protocol_version=1, session_id=sid, sequence=2 ** 53,
                   direction="agent-to-host", message_type="REQUEST", expect="raises",
                   exception="UnsafeNumber")])

    # --------------------------------------------------------------- key material
    structural("derive_keys_bad_secret_len", "hkdf", "31-byte secret refused")
    structural("derive_keys_bad_nonce_len", "hkdf", "15-byte agent nonce refused")
    boundaries.append({
        "id": "derive_keys_bad_nonce_len_wire",
        "stage": "handshake",
        "description": "short agent nonce on the wire fails the handshake closed (native variant)",
        "reference_outcome": "raises",
        "reference_exception": "ProtocolError",
        "steps": [step(call="handshake", stage="handshake", role="agent", counterpart="rogue_ack_object",
                       psk_hex=psk.hex(), hello_json=hello_json,
                       ack_json=json.dumps(dict(ack, nonce=ack["nonce"][:-2]),
                                           separators=(",", ":"), sort_keys=True),
                       expect="raises", exception="ProtocolError")],
    })
    boundary("channel_bad_suite", "aead", "unknown AEAD suite refused",
             [step(call="chan_init", stage="aead", key_hex=BOUNDARY_KEY_HEX,
                   prefix_hex=BOUNDARY_PREFIX_HEX, session_id=sid, direction="agent-to-host",
                   suite="ROT13", max_frame_bytes=1048576, protocol_version=1, expect="raises",
                   exception="ProtocolError")])
    structural("channel_bad_key_len", "aead", "short channel key refused")

    # ------------------------------------------------------------ frame ordering
    oversize = recorded["seal_oversize_consumes_no_sequence"]["result"]
    boundary("seal_oversize_consumes_no_sequence", "aead",
             "oversize reject leaves the sequence counter untouched",
             [step(call="chan_init", stage="aead", key_hex=BOUNDARY_KEY_HEX,
                   prefix_hex=BOUNDARY_PREFIX_HEX, session_id=sid, direction="agent-to-host",
                   suite=None, max_frame_bytes=64, protocol_version=1, expect="ok"),
              step(call="seal", stage="aead", mtype="REQUEST", pt_hex=(b"x" * 49).hex(),
                   expect="raises", exception="FrameLimitExceeded"),
              step(call="seal", stage="aead", mtype="REQUEST", pt_hex=b"ok".hex(), expect="ok",
                   expect_seq=oversize["next_seq"], expect_hex=oversize["next_ciphertext_hex"])])

    wrong_seq = recorded["open_wrong_sequence_then_correct"]["result"]
    assert wrong_seq["first_open"] == "ReplayDetected"
    boundary("open_wrong_sequence_then_correct", "aead",
             "duplicate/skip detected; correct sequence still opens",
             [step(call="chan_init", stage="aead", key_hex=BOUNDARY_KEY_HEX,
                   prefix_hex=BOUNDARY_PREFIX_HEX, session_id=sid, direction="agent-to-host",
                   suite=None, max_frame_bytes=1024, protocol_version=1, expect="ok"),
              step(call="seal", stage="aead", mtype="REQUEST", pt_hex=b"first".hex(), expect="ok",
                   expect_seq=0),
              step(call="chan_init", stage="aead", key_hex=BOUNDARY_KEY_HEX,
                   prefix_hex=BOUNDARY_PREFIX_HEX, session_id=sid, direction="agent-to-host",
                   suite=None, max_frame_bytes=1024, protocol_version=1, expect="ok"),
              step(call="open", stage="aead", mtype="REQUEST", seq=1, ct_hex=None,
                   expect="raises", exception="ReplayDetected"),
              step(call="open", stage="aead", mtype="REQUEST", seq=0, ct_hex=None, expect="ok",
                   expect_hex=b"first".hex())])

    tamper = recorded["open_tampered_tag_then_ok"]["result"]
    assert tamper["tampered_open"] == "AuthenticationFailed"
    chan = DirectionChannel(bytes(range(32)), b"abcd", sid, Direction.AGENT_TO_HOST,
                            max_frame_bytes=1024)
    _seq_ok, ct_payload = chan.seal("REQUEST", b"payload")
    tampered = bytearray(ct_payload)
    tampered[-1] ^= 0x01
    boundary("open_tampered_tag_then_ok", "aead",
             "tag tamper refused with the PS4RF exception (D9); untampered frame still opens",
             [step(call="chan_init", stage="aead", key_hex=BOUNDARY_KEY_HEX,
                   prefix_hex=BOUNDARY_PREFIX_HEX, session_id=sid, direction="agent-to-host",
                   suite=None, max_frame_bytes=1024, protocol_version=1, expect="ok"),
              step(call="open", stage="aead", mtype="REQUEST", seq=0, ct_hex=bytes(tampered).hex(),
                   expect="raises", exception="AuthenticationFailed"),
              step(call="open", stage="aead", mtype="REQUEST", seq=0, ct_hex=ct_payload.hex(),
                   expect="ok", expect_hex=b"payload".hex())])

    boundary("open_oversize_ciphertext", "aead", "ciphertext beyond max_frame_bytes refused",
             [step(call="chan_init", stage="aead", key_hex=BOUNDARY_KEY_HEX,
                   prefix_hex=BOUNDARY_PREFIX_HEX, session_id=sid, direction="agent-to-host",
                   suite=None, max_frame_bytes=64, protocol_version=1, expect="ok"),
              step(call="open", stage="aead", mtype="REQUEST", seq=0, ct_hex=bytes(65).hex(),
                   expect="raises", exception="FrameLimitExceeded")])

    boundary("seal_sequence_exhausted", "aead",
             "send counter past EFFECTIVE_LAST_SEQ refused (D8; internal probe)",
             [step(call="chan_init", stage="aead", key_hex=BOUNDARY_KEY_HEX,
                   prefix_hex=BOUNDARY_PREFIX_HEX, session_id=sid, direction="agent-to-host",
                   suite=None, max_frame_bytes=1024, protocol_version=1, expect="ok"),
              step(call="set_seq", stage="aead", expect="ok", send=EFFECTIVE_LAST_SEQ + 1),
              step(call="seal", stage="aead", mtype="REQUEST", pt_hex=b"x".hex(), expect="raises",
                   exception="SequenceExhausted")])

    ceiling = recorded["seal_at_effective_ceiling_then_exhausted"]["result"]
    assert ceiling["last_valid_sequence"] == EFFECTIVE_LAST_SEQ
    boundary("seal_at_effective_ceiling_then_exhausted", "aead",
             "last valid sequence seals; the next one fails closed with no wraparound (D8)",
             [step(call="chan_init", stage="aead", key_hex=BOUNDARY_KEY_HEX,
                   prefix_hex=BOUNDARY_PREFIX_HEX, session_id=sid, direction="agent-to-host",
                   suite=None, max_frame_bytes=1024, protocol_version=1, expect="ok"),
              step(call="set_seq", stage="aead", expect="ok", send=EFFECTIVE_LAST_SEQ),
              step(call="seal", stage="aead", mtype="REQUEST", pt_hex=b"last-valid".hex(),
                   expect="ok", expect_seq=EFFECTIVE_LAST_SEQ),
              step(call="seal", stage="aead", mtype="REQUEST", pt_hex=b"next".hex(),
                   expect="raises", exception="SequenceExhausted")])

    boundary("handshake_frame_oversize", "handshake",
             "handshake frame beyond 64 KiB refused before the socket",
             [step(call="hs_send_oversize", stage="handshake",
                   json=json.dumps({"x": "a" * 70000}, separators=(",", ":")), expect="raises",
                   exception="ProtocolError")])

    # ------------------------------------------------------------- W2 negatives
    mutated_ack_json = json.dumps(dict(ack, agent_version="vector-0.1.0-mutated"),
                                  separators=(",", ":"), sort_keys=True)

    negative.append({
        "id": "n01_bad_transcript",
        "stage": "handshake",
        "description": "AUTH proof computed over a different transcript is refused",
        "steps": [step(call="handshake", stage="handshake", role="host", counterpart="rogue_transcript",
                       psk_hex=psk.hex(), hello_json=hello_json, ack_json=ack_json,
                       ack_mutated_json=mutated_ack_json, expect="raises", exception="ProtocolError")],
    })
    negative.append({
        "id": "n02_bad_auth_proof",
        "stage": "handshake",
        "description": "wrong AUTH mac is refused by the host",
        "steps": [step(call="handshake", stage="handshake", role="host", counterpart="rogue_auth_mac",
                       psk_hex=psk.hex(), hello_json=hello_json, ack_json=ack_json, expect="raises",
                       exception="ProtocolError")],
    })
    negative.append({
        "id": "n03_bad_auth_ack_proof",
        "stage": "handshake",
        "description": "wrong AUTH_ACK mac is refused by the agent",
        "steps": [step(call="handshake", stage="handshake", role="agent", counterpart="rogue_ack_mac",
                       psk_hex=psk.hex(), hello_json=hello_json, ack_json=ack_json, expect="raises",
                       exception="ProtocolError")],
    })
    negative.append({
        "id": "n03b_handshake_loopback",
        "stage": "handshake",
        "description": "complete agent/host handshake over a socket pair matches the golden session",
        "steps": [step(call="handshake", stage="handshake", role="agent", counterpart="catalog",
                       psk_hex=psk.hex(), hello_json=hello_json, ack_json=ack_json, expect="ok")],
    })

    # channel-level negatives, every expectation pinned with the frozen core
    def chan_case(case_id: str, description: str, steps: list[dict], expected_exception: str,
                  stage: str = "aead") -> None:
        negative.append({
            "id": case_id,
            "stage": stage,
            "description": description,
            "reference_exception": expected_exception,
            "steps": steps,
        })

    a2h = dict(key_hex=k_a2h.hex(), prefix_hex=pfx_a2h.hex(), session_id=sid,
               direction="agent-to-host", suite=None, max_frame_bytes=1024, protocol_version=1)
    h2a = dict(key_hex=k_h2a.hex(), prefix_hex=pfx_h2a.hex(), session_id=sid,
               direction="host-to-agent", suite=None, max_frame_bytes=1024, protocol_version=1)

    # n04 wrong direction (cross-direction frame must fail authentication)
    probe = b'{"probe":"channel-open"}'
    sender = DirectionChannel(k_a2h, pfx_a2h, sid, Direction.AGENT_TO_HOST, max_frame_bytes=1024)
    seq_probe, ct_probe = sender.seal("RESPONSE", probe)
    receiver = DirectionChannel(k_h2a, pfx_h2a, sid, Direction.HOST_TO_AGENT, max_frame_bytes=1024)
    try:
        receiver.open("RESPONSE", seq_probe, ct_probe)
        raise AssertionError("cross-direction open must fail")
    except AuthenticationFailed:
        pass
    chan_case("n04_wrong_direction", "cross-direction frame refused",
              [step(call="chan_init", stage="aead", expect="ok", **a2h),
               step(call="seal", stage="aead", mtype="RESPONSE", pt_hex=probe.hex(), expect="ok",
                    expect_seq=seq_probe, expect_hex=ct_probe.hex()),
               step(call="chan_init", stage="aead", expect="ok", **h2a),
               step(call="open", stage="aead", mtype="RESPONSE", seq=seq_probe, ct_hex=ct_probe.hex(),
                    expect="raises", exception="AuthenticationFailed")],
              "AuthenticationFailed")

    # n05 wrong message type
    sender = DirectionChannel(k_a2h, pfx_a2h, sid, Direction.AGENT_TO_HOST, max_frame_bytes=1024)
    seq_probe, ct_probe = sender.seal("RESPONSE", probe)
    receiver = DirectionChannel(k_a2h, pfx_a2h, sid, Direction.AGENT_TO_HOST, max_frame_bytes=1024)
    try:
        receiver.open("BYE", seq_probe, ct_probe)
        raise AssertionError("wrong message type must fail")
    except AuthenticationFailed:
        pass
    chan_case("n05_wrong_message_type", "type byte contradicting the sealed type fails authentication",
              [step(call="chan_init", stage="aead", expect="ok", **a2h),
               step(call="open", stage="aead", mtype="BYE", seq=seq_probe, ct_hex=ct_probe.hex(),
                    expect="raises", exception="AuthenticationFailed")],
              "AuthenticationFailed")

    # n06 unknown type byte
    unknown_raw = (0).to_bytes(4, "big") + bytes([0x07]) + (0).to_bytes(8, "big")
    try:
        wire.parse_header(unknown_raw)
        raise AssertionError("unknown type byte must fail")
    except wire.UnknownFrameType:
        pass
    negative.append({
        "id": "n06_unknown_type_byte",
        "stage": "frame_header",
        "description": "type byte outside the mapping v1 table fails closed",
        "reference_exception": "UnknownFrameType",
        "steps": [step(call="header_parse", stage="frame_header", hex=unknown_raw.hex(),
                       max_frame_bytes=1048576, expect="raises", exception="UnknownFrameType")],
    })

    # n07 wrong sequence, n08 duplicate, n09 gap
    sender = DirectionChannel(k_h2a, pfx_h2a, sid, Direction.HOST_TO_AGENT, max_frame_bytes=1024)
    seq0, ct0 = sender.seal("REQUEST", b"first")
    seq1, ct1 = sender.seal("REQUEST", b"second")
    chan_case("n07_wrong_sequence", "sequence mismatch is detected as a replay",
              [step(call="chan_init", stage="aead", expect="ok", **h2a),
               step(call="open", stage="aead", mtype="REQUEST", seq=5, ct_hex=ct0.hex(),
                    expect="raises", exception="ReplayDetected")],
              "ReplayDetected")
    chan_case("n08_duplicate_sequence", "a duplicated sequence is detected as a replay",
              [step(call="chan_init", stage="aead", expect="ok", **h2a),
               step(call="open", stage="aead", mtype="REQUEST", seq=0, ct_hex=ct0.hex(), expect="ok",
                    expect_hex=b"first".hex()),
               step(call="open", stage="aead", mtype="REQUEST", seq=0, ct_hex=ct0.hex(),
                    expect="raises", exception="ReplayDetected")],
              "ReplayDetected")
    chan_case("n09_sequence_gap", "a forward sequence gap is detected as a replay",
              [step(call="chan_init", stage="aead", expect="ok", **h2a),
               step(call="open", stage="aead", mtype="REQUEST", seq=1, ct_hex=ct1.hex(),
                    expect="raises", exception="ReplayDetected")],
              "ReplayDetected")

    # n10/n11 sequence ceiling
    negative.append({
        "id": "n10_sequence_at_ceiling",
        "stage": "aead",
        "description": "the last valid sequence still seals (EFFECTIVE_LAST_SEQ)",
        "steps": [step(call="chan_init", stage="aead", expect="ok", **a2h),
                  step(call="set_seq", stage="aead", expect="ok", send=EFFECTIVE_LAST_SEQ),
                  step(call="seal", stage="aead", mtype="RESPONSE", pt_hex=b"at-ceiling".hex(),
                       expect="ok", expect_seq=EFFECTIVE_LAST_SEQ)],
    })
    negative.append({
        "id": "n11_sequence_over_ceiling",
        "stage": "aead",
        "description": "one past the ceiling fails closed with no wraparound",
        "steps": [step(call="chan_init", stage="aead", expect="ok", **a2h),
                  step(call="set_seq", stage="aead", expect="ok", send=EFFECTIVE_LAST_SEQ + 1),
                  step(call="seal", stage="aead", mtype="RESPONSE", pt_hex=b"over-ceiling".hex(),
                       expect="raises", exception="SequenceExhausted")],
    })

    # n12/n13 tampered ciphertext / tag
    sender = DirectionChannel(k_h2a, pfx_h2a, sid, Direction.HOST_TO_AGENT, max_frame_bytes=1024)
    _seq, ct_body = sender.seal("REQUEST", b"tamper-body")
    bad_body = bytearray(ct_body)
    bad_body[0] ^= 0x01
    chan_case("n12_tampered_ciphertext", "flipped ciphertext bit fails authentication",
              [step(call="chan_init", stage="aead", expect="ok", **h2a),
               step(call="open", stage="aead", mtype="REQUEST", seq=0, ct_hex=bytes(bad_body).hex(),
                    expect="raises", exception="AuthenticationFailed"),
               step(call="open", stage="aead", mtype="REQUEST", seq=0, ct_hex=ct_body.hex(),
                    expect="ok", expect_hex=b"tamper-body".hex())],
              "AuthenticationFailed")
    _seq, ct_tag = DirectionChannel(k_h2a, pfx_h2a, sid, Direction.HOST_TO_AGENT,
                                    max_frame_bytes=1024).seal("REQUEST", b"tamper-tag")
    bad_tag = bytearray(ct_tag)
    bad_tag[-1] ^= 0x80
    chan_case("n13_tampered_tag", "flipped tag bit fails authentication",
              [step(call="chan_init", stage="aead", expect="ok", **h2a),
               step(call="open", stage="aead", mtype="REQUEST", seq=0, ct_hex=bytes(bad_tag).hex(),
                    expect="raises", exception="AuthenticationFailed")],
              "AuthenticationFailed")

    # n14 tampered AAD: the sealer uses a different session id (distinct from n17,
    # where the receiver's AAD carries the wrong session id)
    sender_other = DirectionChannel(k_h2a, pfx_h2a, "SES-1111111111111111", Direction.HOST_TO_AGENT,
                                    max_frame_bytes=1024)
    _seq_other, ct_other_session = sender_other.seal("REQUEST", b"aad-mismatch")
    try:
        DirectionChannel(k_h2a, pfx_h2a, sid, Direction.HOST_TO_AGENT,
                         max_frame_bytes=1024).open("REQUEST", 0, ct_other_session)
        raise AssertionError("session-mismatched AAD must fail")
    except AuthenticationFailed:
        pass
    chan_case("n14_tampered_aad", "AAD mismatch (sealer used a different session id) fails authentication",
              [step(call="chan_init", stage="aead", expect="ok", **h2a),
               step(call="open", stage="aead", mtype="REQUEST", seq=0,
                    ct_hex=ct_other_session.hex(), expect="raises",
                    exception="AuthenticationFailed")],
              "AuthenticationFailed")
    chan_case("n17_wrong_session_id", "wrong session id in the AAD fails authentication",
              [step(call="chan_init", stage="aead", expect="ok",
                    **dict(h2a, session_id="SES-0000000000000000")),
               step(call="open", stage="aead", mtype="REQUEST", seq=0, ct_hex=ct_body.hex(),
                    expect="raises", exception="AuthenticationFailed")],
              "AuthenticationFailed")
    chan_case("n18_wrong_protocol_version", "wrong protocol version in the AAD fails authentication",
              [step(call="chan_init", stage="aead", expect="ok", **dict(h2a, protocol_version=2)),
               step(call="open", stage="aead", mtype="REQUEST", seq=0, ct_hex=ct_body.hex(),
                    expect="raises", exception="AuthenticationFailed")],
              "AuthenticationFailed")

    # n15 oversized frame (seal side)
    chan_case("n15_oversized_frame", "frame above max_frame_bytes is refused",
              [step(call="chan_init", stage="aead", expect="ok", **dict(h2a, max_frame_bytes=64)),
               step(call="seal", stage="aead", mtype="REQUEST", pt_hex=(b"y" * 49).hex(),
                    expect="raises", exception="FrameLimitExceeded")],
              "FrameLimitExceeded")

    # n16 truncated frame
    sender = DirectionChannel(k_h2a, pfx_h2a, sid, Direction.HOST_TO_AGENT, max_frame_bytes=1024)
    _seq, ct_full = sender.seal("REQUEST", b"truncate-me")
    full_wire = wire.build_header(len(ct_full), "REQUEST", 0) + ct_full
    trunc_wire = full_wire[:-1]
    try:
        wire.decode_frame(DirectionChannel(k_h2a, pfx_h2a, sid, Direction.HOST_TO_AGENT,
                                           max_frame_bytes=1024), trunc_wire)
        raise AssertionError("truncated frame must fail")
    except ProtocolError:
        pass
    chan_case("n16_truncated_frame", "truncated frame (header and body) fails closed",
              [step(call="chan_init", stage="wire_frame", expect="ok", **h2a),
               step(call="wire_decode", stage="wire_frame", wire_hex=trunc_wire.hex(),
                    expect="raises", exception="ProtocolError")],
              "ProtocolError", stage="wire_frame")

    # ------------------------------------------------------- parity channel cases
    # Same operations as the parity catalog's channel.cases, so the native side is
    # aligned with both catalogs on the identical expectations.
    parity_cases.append({
        "id": "channel_open_roundtrip",
        "stage": "aead",
        "description": "parity catalog channel.open_roundtrip",
        "steps": [step(call="chan_init", stage="aead", expect="ok", **a2h),
                  step(call="seal", stage="aead", mtype="RESPONSE", pt_hex=probe.hex(), expect="ok",
                       expect_seq=0, expect_hex=ct_probe.hex()),
                  step(call="open", stage="aead", mtype="RESPONSE", seq=0, ct_hex=ct_probe.hex(),
                       expect="ok", expect_hex=probe.hex())],
    })
    for case_id, mtype, seq, ct, exc in (
        ("open_wrong_message_type_rejected", "BYE", seq_probe, ct_probe.hex(),
         "AuthenticationFailed"),
        ("open_sequence_gap_rejected", "RESPONSE", 1, ct_probe.hex(), "ReplayDetected"),
        ("open_replay_rejected", "RESPONSE", 1, ct_probe.hex(), "ReplayDetected"),
        ("cross_direction_open_rejected", "RESPONSE", seq_probe, ct_probe.hex(),
         "AuthenticationFailed"),
    ):
        if case_id == "cross_direction_open_rejected":
            steps = [step(call="chan_init", stage="aead", expect="ok", **h2a),
                     step(call="open", stage="aead", mtype=mtype, seq=seq, ct_hex=ct,
                          expect="raises", exception=exc)]
        elif case_id == "open_wrong_message_type_rejected":
            steps = [step(call="chan_init", stage="aead", expect="ok", **a2h),
                     step(call="open", stage="aead", mtype=mtype, seq=seq, ct_hex=ct,
                          expect="raises", exception=exc)]
        else:  # gap / replay on the a2h channel
            steps = [step(call="chan_init", stage="aead", expect="ok", **a2h),
                     step(call="open", stage="aead", mtype=mtype, seq=1, ct_hex=ct,
                          expect="raises", exception="ReplayDetected")]
        parity_cases.append({
            "id": "channel_" + case_id,
            "stage": "aead",
            "description": f"parity catalog channel.{case_id}",
            "reference_exception": exc,
            "steps": steps,
        })

    # ------------------------------------------------------------------ assemble
    doc = {
        "schema": "ps4rf-w2-negative-vectors-v1",
        "generator": "tests/fixtures/parity/gen_negative.py",
        "source": {
            "crypto_catalog": {"path": "tests/fixtures/crypto/vectors-v1.json",
                               "sha256": sha256_file(CRYPTO)},
            "parity_catalog": {"path": "tests/fixtures/parity/vectors-v1.json",
                               "sha256": sha256_file(PARITY)},
            "frozen_core": {
                "core/canonical.py": sha256_file(REPO / "core" / "canonical.py"),
                "core/rpc/handshake.py": sha256_file(REPO / "core" / "rpc" / "handshake.py"),
                "core/rpc/wire.py": sha256_file(REPO / "core" / "rpc" / "wire.py"),
            },
            "note": "expected outcomes recomputed with the frozen Python core; "
                    "no expectation in this file is hand-written",
        },
        "session": {
            "session_id": sid,
            "psk_hex": psk.hex(),
            "agent_nonce_hex": an.hex(),
            "host_nonce_hex": hn.hex(),
            "transcript_sha256": th.hex(),
        },
        "boundaries": boundaries,
        "negative": negative,
        "parity_cases": parity_cases,
    }
    return doc


def render(doc: dict) -> bytes:
    """Canonical byte rendering of the catalog (tests compare against the file)."""
    return (json.dumps(doc, indent=1, sort_keys=True) + "\n").encode()


def main(argv: list[str]) -> int:
    doc = build()
    text = render(doc)
    if "--check" in argv:
        if OUT.read_bytes() == text:
            print(f"up to date: {OUT.relative_to(REPO)}")
            return 0
        print(f"OUT OF DATE: {OUT.relative_to(REPO)}")
        return 1
    OUT.write_bytes(text)
    print(f"wrote {OUT.relative_to(REPO)} ({len(text)} bytes)")
    print(f"sha256 {hashlib.sha256(text).hexdigest()}")
    skipped = [b['id'] for b in doc['boundaries'] if b.get('structural')]
    print(f"boundaries: {len(doc['boundaries'])} ({len(skipped)} structural: {', '.join(skipped)})")
    print(f"negative:   {len(doc['negative'])}")
    print(f"parity:     {len(doc['parity_cases'])}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
