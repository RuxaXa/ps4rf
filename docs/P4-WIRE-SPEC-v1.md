# PS4RF Wire Specification v1 (frame layer)

Status: **normative for P4/W2** — decided by the PS4RF Project Owner / Research
Lead (W0 decisions D8, D9, D12, D13, 2026-10-05), implemented in `core/rpc/wire.py`
(single source of truth for the table) and pinned by
`tests/fixtures/parity/vectors-v1.json` + `tests/test_wire_frames.py`.

## 1. Frame layout

Post-handshake, both directions, identical layout:

```
+--------+--------+------------------+--------------------+
| len 4B | type 1B| sequence 8B      | ciphertext (len B) |
| big-end|        | big-endian       | AEAD, tag included  |
+--------+--------+------------------+--------------------+
```

* `len` — ciphertext length in bytes (AEAD tag included). Checked **before any
  allocation**; `len > max_frame_bytes` → `FrameLimitExceeded` (a `ProtocolError`).
* `type` — see §2, the only allowed byte values.
* `sequence` — per-direction counter, starts at 0, must equal the receiver's
  expected value (no gaps, no replay: `ReplayDetected`).
* The AAD binds `sequence` (JCS integer) and the message type of the frame; the
  type byte therefore selects the AAD type. A byte that contradicts the sealed
  type fails authentication (§5).

Header size: 13 bytes. Total frame: `13 + len`.

## 2. Frame type byte mapping v1 (normative)

| byte | message type | status in v0.1 |
|---|---|---|
| `0x01` | `REQUEST`  | active (host → agent) |
| `0x02` | `RESPONSE` | active (agent → host) |
| `0x03` | `EVENT`    | **reserved** — not sent, no body defined |
| `0x04` | `BYE`      | active (agent → host) |
| `0x05` | `READY`    | **reserved** — mock compatibility only |

* The mapping is **in-repo property** (D12). No older normative table exists, so
  no historical byte identity is invented.
* Every implementation — host core, mock, future native agent — must use the one
  shared table (`FRAME_TYPE_NAMES` / `FRAME_TYPE_BYTES` in `core/rpc/wire.py`) in
  both directions (`_send_frame()` / `recv_frame()` equivalents). Partial or
  duplicated tables are a specification violation.
* **Any other byte value** → `UnknownFrameType` (`ProtocolError`): protocol
  error, session fails closed, no reply attempt. No skipping, no resynchronizing.
* `EVENT`/`READY` are reserved: sending one raises `ReservedFrameType`
  (fail closed); receiving one is a session-FSM decision, not a framing error.
  * `EVENT` — no body is defined in v0.1; the agent does not send it (D13).
  * `READY` — the host may tolerate it for existing mock compatibility; the
    native W2 agent need not send it. `READY` receives active wire semantics only
    once shape, encryption status, capability content and state transition are
    fully specified. Until then no implementation may invent its content (D13).
* W2 byte-parity scope: `REQUEST`, `RESPONSE`, `BYE` (in that role assignment),
  including header, ciphertext and canonical plaintext for the catalog frames.

## 3. Direction rule (spec F16)

| direction | allowed message types |
|---|---|
| host → agent | `REQUEST` |
| agent → host | `RESPONSE`, `EVENT` (reserved), `BYE` |

A message type outside the inbound set of the receiving side → `ProtocolError`,
connection closed immediately (fail-close). The direction rule is semantic and
independent of who initiated TCP (§see W0/D5: the agent connects out; the
semantic roles do not change).

## 4. Sequence ceiling (D8)

* `EFFECTIVE_LAST_SEQ = 2**53 - 1` — the AAD carries `sequence` as a JCS JSON
  integer, so the safe-number limit is the effective ceiling; the 8-byte header
  field does **not** extend it.
* Enforcement in `seal()`/`open()`: the sequence `2**53 - 1` is the last valid
  one; sealing/receiving beyond it raises `SequenceExhausted`, the session closes
  and there is **no wraparound**.
* `LAST_SEQ = 2**64 - 2` stays documented as the header's representable space
  only; it is not the usable ceiling.
* No AAD format change during the freeze.

## 5. Error behaviour (fail-close matrix)

| condition | exception | session |
|---|---|---|
| unknown type byte | `UnknownFrameType` | closed, no reply |
| length > max_frame_bytes | `FrameLimitExceeded` | closed, no reply |
| sequence gap / replay | `ReplayDetected` | closed |
| sequence past effective ceiling | `SequenceExhausted` | closed, no wraparound |
| AEAD authentication failure (bad tag, type byte / AAD mismatch, wrong direction key) | `AuthenticationFailed` | closed |
| reserved type sent | `ReservedFrameType` | local refusal, nothing on the wire |
| message type outside inbound set | `ProtocolError` | closed, no reply |

All of these are `ProtocolError` subclasses. **D9:** the mapping from the
cryptography library's `InvalidTag` to `AuthenticationFailed` happens in exactly
one shared core helper (`core.rpc.handshake.open_authenticated`); mock and native
must both behave this way and no library-specific exception may escape the RPC
layer.

## 6. Verification

* Byte-level: `tests/fixtures/parity/vectors-v1.json` `frames[]` carries
  `header_hex` and `wire_hex` for five frames; `tests/test_parity_vectors.py`
  decodes each one back to the recorded plaintext/message type/sequence.
* Table/behaviour: `tests/test_wire_frames.py` (table pinning, reserved policy,
  unknown byte, direction FSM, ceiling, authentication mapping).
* Crypto layer: `tests/fixtures/crypto/vectors-v1.json` +
  `tests/test_crypto_vectors.py` (AAD boundary at `EFFECTIVE_LAST_SEQ`).

## 7. Out of scope in v1

* `READY` body/state semantics (reserved until fully specified).
* `EVENT` body shape (reserved, not sent).
* Listing daemon / inbound transport (deferred to P5; P4 uses connect-out, D5).
* Kernel-level additions (P4 is userland only; see §70 text in
  `docs/spec-history/70-capability-gated-native-primitive-additions.md`).
