# Crypto / handshake vector fixtures (P4/W1 prep)

`vectors-v1.json` is the byte-exact acceptance catalog for the future native
(C) implementation of the PS4RF handshake and frame layer. It is generated
**offline** from two sources and is fully self-verifying.

| File | sha256 |
|---|---|
| `vectors-v1.json` | `452ecc195f49329325e3ba0557ce1327e10d8e4f71b9e3e06a36a8c6721edd8b` |
| `gen_vectors.py`  | `b5184748ce7c43b4c244055d5f789782297d0ed7bac44c90743156b9c7f2c88d` |

Frozen sources the catalog is derived from (also recorded inside the file):

| Module | sha256 |
|---|---|
| `core/canonical.py` | `e35983f1c77cbea889c9b298d17ec99d1728095f8d1a800e2fe1ff80086bcb2d` |
| `core/rpc/handshake.py` | `ac745544a65364623c7b41d3255f5ed5d0f601075155a6a4d3b1b53dd3d105bd` |

If either module changes, the catalog must be regenerated — `tests/test_crypto_vectors.py`
fails until it is.

## Regeneration (must be byte-identical)

```sh
cd <repo-root>
PATH="$PWD/.venv/bin:$PATH" python tests/fixtures/crypto/gen_vectors.py
```

Determinism rules: no timestamps, no absolute paths, no hostnames; sorted JSON
keys; `indent=1`; `ensure_ascii=False`; single trailing newline. The generator
re-verifies every RFC constant against an independent implementation
(`cryptography`, `hashlib`, `hmac`, `rfc8785`) and aborts on any mismatch.

## RFC sources (fetched plain text, provenance)

| RFC | Contains | sha256 of `https://www.rfc-editor.org/rfc/rfc<N>.txt` |
|---|---|---|
| 8439 | §2.8.2 AEAD_CHACHA20_POLY1305 example/test vector | `25bef70fbf7a07ff45c2fe4cb7c6ce954eac687413d8610603268b4e4415324c` |
| 5869 | A.1–A.3 HKDF-SHA256 test cases (PRK + OKM) | `7a40eb3835b35fc947eb12a2ed614db079d43b26e50dbc537c31fba16397089c` |
| 4231 | §4.2–4.8 HMAC test cases (SHA-256 rows) | `72178527ce93500e730bc8eb182b857e583096d652b64ece0879c52ba1df973b` |
| 8785 | §3.2.2 canonicalization sample + Appendix B number table | `63d52294eb0e3f0014174288186d388b4ddbf2c67d1ce8af1d9726eb0c3ab240` |

The constants were machine-extracted from those texts (script: `parse_rfcs3.py`,
scratch-only) and cross-checked at generation time; nothing was transcribed by
hand.

## Content classes

1. `rfc_vectors` — pure RFC anchors, independent of this repo. Includes the
   8439 nonce construction (`32-bit fixed-common part ‖ IV`), 5869 cases 1–3
   (case 3 has zero-length salt/info), 4231 cases 1,2,3,4,6,7, the 8785 sample
   and 24 Appendix B rows.
2. `protocol` — derived from the **frozen** modules: HELLO/HELLO_ACK objects,
   `transcript_sha256`, three derived keys, agent/host proofs, both nonce
   prefixes, AAD bytes for both directions, four sealed frames (with nonce,
   plaintext and ciphertext), the complete four-message handshake byte exchange
   (produced by running the real `agent_handshake` against `host_handshake`
   over an in-memory endpoint pair) and the constants (`TAG_LEN`,
   `MAX_HANDSHAKE_BYTES`, `LAST_SEQ`, `EFFECTIVE_LAST_SEQ`, default
   `max_frame_bytes`, suites).
3. `boundaries` — 22 negative/boundary behaviours (safe-number policy, AAD
   sequence ceiling, key/nonce length checks, unknown suite, oversize-seal
   *without* sequence consumption, replay detection, tag tamper, oversize open,
   exhausted sequence counter, sealing at the effective ceiling without
   wraparound, handshake frame > 64 KiB). Outcome is either an
   `ok` result (hex of the produced bytes) or the **exception class name** the
   frozen implementation raises.

## Notes and findings (carry into W2)

* **F1 — AAD direction string → owner decision D7: keep the frozen bytes.** The
  frozen `build_aad` embeds `str(direction)`. With the `Direction` enum that is
  the literal `"Direction.AGENT_TO_HOST"` / `"Direction.HOST_TO_AGENT"` (not the
  enum *value* `"agent-to-host"` / `"host-to-agent"`). Both variants are in the
  catalog (`h2a_request_seq0` vs `h2a_request_seq0_raw_value_string`). **Binding
  (W0/D7):** the current core generation stays on `str(direction)`; this is a
  documented compatibility wart. No change to `.value` inside the frozen core —
  a change would only happen in an explicitly versioned core/wire revision with
  new golden vectors.
* **F2 — sequence ceiling → owner decision D8: enforce the effective ceiling.**
  `build_aad` carries `sequence` as a JSON integer, so `canonical_bytes` →
  safe-number policy caps encodable sequences at `2**53 - 1`
  (`EFFECTIVE_LAST_SEQ`), while the frame header's 8-byte field allows
  `LAST_SEQ = 2**64 - 2`. **Binding (W0/D8):** `EFFECTIVE_LAST_SEQ = 2**53 - 1`
  is the enforced ceiling in `seal()`/`open()` (Core/Wire Revision R1); reaching
  it raises `SequenceExhausted`, the session closes, there is **no wraparound**.
  No AAD format change during the freeze. Pinned by
  `aad_seq_2p53_minus_1_ok`, `aad_seq_2p53_rejected`,
  `seal_sequence_exhausted`, `seal_at_effective_ceiling_then_exhausted`.
* **F3 — authentication failures → owner decision D9:** mapped centrally in
  `core.rpc.handshake.open_authenticated` to `AuthenticationFailed`.
  `open_tampered_tag_then_ok` records the PS4RF exception class, not the library
  exception.
* **Direction rule (spec F16, cited in the frames).** Message types follow the
  spec's state machine: `host→agent` carries `REQUEST`; `agent→host` carries
  `RESPONSE`/`EVENT`/`BYE`. The sealed frames here use **shape-neutral**
  plaintexts (this catalog pins the crypto layer only); the message *shapes*
  are pinned in the parity catalog (`tests/fixtures/parity/`). `EVENT` appears
  only as an AAD-level message type — the spec never defines its body shape.
* **Test-only material.** PSK/nonces/session id in the catalog are fixed public
  test constants (`test_only_material.warning`), never production keys.
* RFC 4231 case 5 is intentionally absent: it publishes only a truncated
  128-bit output, not a full HMAC-SHA-256 value.
* The RFC 8785 §3.2.2 sample cannot be fed through `core.canonical` verbatim
  (it contains `1E30`, which the safe-number policy rejects); it anchors the JCS
  *algorithm* via `rfc8785`, while the protocol cases pin the core's stricter
  domain.
* Semantically-named placeholder strings (`vector-transport`,
  `vector-context`, `vector-provider`) exist to exercise JCS key sorting and
  type coverage; they are not claims about the final field values.

## Related

* Harness contract for the native side: `docs/P4-W1-TESTVECTORS-SPEC.md`
* Options/trade-offs for the SDK decision: `docs/P4-W1-DRAFT-PAYLOAD-SDK-OPTIONS.md`
* Self-verification: `tests/test_crypto_vectors.py`
