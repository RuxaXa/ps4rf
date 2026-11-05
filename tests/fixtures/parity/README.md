# Parity vector catalog (W2 prep)

`vectors-v1.json` is the **message- and behaviour-level acceptance basis** for the
native agent (P4/W2: "Agent skeleton & handshake parity"). It complements the
crypto catalog (`../crypto/vectors-v1.json`, RFC/primitive level) and pins what
the repo does *after* the W0 decisions: the frame type byte table, the effective
sequence ceiling and the authentication-failure mapping are now fixed contract
(Core/Wire Revision R1, decisions D8/D9/D12/D13), everything else is observed
frozen behaviour plus the message shapes the spec's session loop uses.

| File | sha256 |
|---|---|
| `vectors-v1.json` | `0c3bae40f283b98cdac62ff3d18c27e6b783b6fbbe507bb24dd3b8ab453d6933` |
| `gen_parity.py`  | `c90da7b04a75e387c021df0243e2b85f227930114b6a65a5c83a204a0d45d85a` |
| `w2-negative-v1.json` | `ced134c621e1aaab2014ba62ede3964131c560ffb0d22dd2d839f102f706e080` |
| `gen_negative.py` | see `sha256sum tests/fixtures/parity/gen_negative.py` |

## W2 boundary/negative script catalog

`w2-negative-v1.json` is the machine-readable execution form used by the native
parity harness (`native/src/parity_harness.c`). It carries three sections:

- `boundaries` — the 22 recorded crypto-catalog boundary cases rewritten as
  executable steps plus two native-only variants (`canonical_nonstring_key_text`,
  `derive_keys_bad_nonce_len_wire`). Four cases are marked `structural` because
  the native API takes fixed-size arrays / `const char *` keys, so the reference's
  argument-length and non-string-key checks have no native input path:
  `canonical_nonstring_key`, `derive_keys_bad_secret_len`,
  `derive_keys_bad_nonce_len`, `channel_bad_key_len`.
- `negative` — the 18 fail-close cases required by the W2 work order
  (transcript/AUTH/AUTH_ACK proofs, direction, message type, unknown type byte,
  sequence errors, ceiling, tamper cases, oversized/truncated frames, session id,
  protocol version) plus one positive handshake loopback.
- `parity_cases` — the five `channel.cases` of this catalog as scripts.

Every expectation is recomputed by `gen_negative.py` from the frozen core
(`core/canonical.py`, `core/rpc/handshake.py`, `core/rpc/wire.py`); the generator
fails loudly if a recomputed boundary outcome disagrees with the crypto catalog's
recorded outcome. `tests/test_negative_vectors.py` asserts byte reproducibility
and the cross-check, so no expectation can be hand-edited unnoticed.

Run the native side (from `native/`):

```bash
make check   # harness against both catalogs + this one
```

Regenerate (from the repo root, venv on PATH):

```bash
PATH="$PWD/.venv/bin:$PATH" python tests/fixtures/parity/gen_parity.py
```

Determinism: no timestamps, no absolute paths, sorted keys, single trailing
newline. Pool/crash/cancel cases avoid timing races by driving the frozen
`BoundedPool` exclusively through `threading.Event`s; the observed verdicts do
not depend on wall-clock ordering. `tests/test_parity_vectors.py` recomputes
every section and compares by deep equality, and verifies the recorded frozen
module hashes against the files on disk (any core drift forces regeneration).

## Sections

* **`session`** — TEST-ONLY PSK/nonces/session id, transcript hash, three keys and
  both nonce prefixes. Deliberately *identical* to the crypto catalog's session
  block (asserted during generation), so both catalogs describe one session.
* **`direction_fsm`** — spec F16: `host→agent` carries `REQUEST`; `agent→host`
  carries `RESPONSE`/`EVENT`/`BYE`; a wrong-direction message closes the session
  (fail-close).
* **`frames`** — five byte-level frames: two inbound `REQUEST`s (`session.ping`,
  `memory.alloc`), outbound `RESPONSE` OK, outbound `RESPONSE` ERROR
  (`TOO_MANY_INFLIGHT`), and `BYE`. Each entry carries the message object, its
  canonical plaintext, the nonce, the sealed ciphertext, the frame length, the
  **type byte**, the **13-byte header** and the **complete wire frame**
  (`wire_hex`) as pinned by wire mapping v1. *Shapes* come from the spec's
  session loop (`header.request_id`, `header.in_reply_to`, `{"status": …}`) —
  citation per entry; *encoding and sealing* come from frozen
  `core/canonical.py` + `core/rpc/handshake.py`; the *framing* comes from
  `core/rpc/wire.py` (single-sourced type table).
* **`wire_frame`** — the post-handshake framing from the spec's `recv_frame`:
  `4B big-endian length ‖ 1 type byte ‖ 8B big-endian sequence ‖ ciphertext`,
  length checked before allocation, unknown type byte → `UnknownFrameType`
  (`ProtocolError`, session fails closed), type byte / AAD mismatch →
  `AuthenticationFailed` (D9), direction check in the session loop →
  `ProtocolError` + close. The type-byte table is **defined in-repo** as wire
  mapping v1 (D12): `0x01` REQUEST, `0x02` RESPONSE, `0x03` EVENT, `0x04` BYE,
  `0x05` READY — `EVENT`/`READY` reserved, not sent in v0.1, W2 active set is
  REQUEST/RESPONSE/BYE (D13).
* **`channel`** — `DirectionChannel` semantics: open round-trip, wrong message
  type, sequence gap, replay, cross-direction — observed exception classes.
* **`registry`** — `RequestIdRegistry`: id pattern, malformed ids, duplicate
  (pending and completed), `respond_once` idempotence, LRU eviction of the
  completed cache (size 2 in the vector).
* **`pool`** — `BoundedPool`: capacity → `TOO_MANY_INFLIGHT`; poison → `POISONED`
  without token leak; poison report of in-flight/queued; worker crash; shutdown
  draining the queue via the cancel callback; `TaskState` values.
* **`agent`** — `mock/agent.py`: canceled request → `ERROR`/`SESSION_RECOVERY_REQUIRED`
  and registry completion; dead transport → nothing sent but still completed;
  worker crash → `WORKER_CRASH` evidence; default pool 4 workers / 8 in-flight,
  `AGENT_CAP = 8`; gate resource allocation (pattern-verified, value never recorded).
* **`hang`** — `MockHangReleased` semantics (blocked worker, no response, never a
  clean `BYE`) with spec citation.
* **`w0_decisions_applied`** — the owner decisions this catalog now reflects
  (D8 effective sequence ceiling, D9 authentication mapping, D12 frame type byte
  table, D13 EVENT/READY scope), each with the vectors that pin it.

## Findings pinned here (owner decisions, nothing changed silently)

* **F3 — authentication failures were library-level → resolved by W0/D9.** The
  frozen channel used to raise `cryptography.exceptions.InvalidTag` for a bad
  tag, a foreign message type or a wrong-direction frame. Core/Wire Revision R1
  maps it centrally in `core.rpc.handshake.open_authenticated` to
  `AuthenticationFailed` (a `ProtocolError`); no library exception escapes the
  RPC layer. The catalog pins the new classes, and
  `tests/test_wire_frames.py` asserts that `InvalidTag` never propagates.
* **F2 — sequence ceiling → enforced by W0/D8.** `EFFECTIVE_LAST_SEQ = 2**53 - 1`
  (the JCS safe-number limit, not the 8-byte header space) is enforced in
  `seal()`/`open()`; reaching it closes the session with `SequenceExhausted`, no
  wraparound. Re-pinned in the crypto catalog boundaries and in
  `tests/test_wire_frames.py`.
* **F4 — a worker crash leaves the task pending.** After `on_worker_crash` the
  task keeps its in-flight token and stays in `_tasks` until `finish(rid)` is
  called; there is no implicit finalization on crash. Recovery code must call
  `finish()` (or poison) or the pool stays permanently one token short. **Owner
  decision (W0/D10): keep this contract — no pool auto-finalize.**
* **F5 — queue cancellation is lazy.** `poison()`/`shutdown()` cancel queued
  tasks, but `on_canceled` (and the `SESSION_RECOVERY_REQUIRED` response for the
  host) fires only when a worker actually reaches that task. A single-worker pool
  therefore reports a queued request as canceled only after the running task
  finished — relevant for host-side timeout budgets. **Owner decision (W0/D11):
  accepted, host timeout budget must account for the serialization.**
* `submit()` after `poison()` consumes no token (returns `'POISONED'`, stays at
  full capacity) — the frozen regression test relied on this and the catalog
  pins it as data.
* **F6 — the frame type byte table was missing from the sources → resolved by
  W0/D12.** Wire mapping v1 is now in-repo property and single-sourced in
  `core/rpc/wire.py` (`0x01` REQUEST, `0x02` RESPONSE, `0x03` EVENT, `0x04` BYE,
  `0x05` READY); any other byte is a protocol error with fail-close. The
  catalog records the table, the reserved semantics and the per-frame type byte,
  header and `wire_hex`.

## Relationship to W1/W2 deliverables

The W1 spec (`docs/P4-W1-TESTVECTORS-SPEC.md`) defines the native forward/backward
harness; this catalog supplies the message-level inputs for it. Neither catalog
makes an SDK decision, calls into the console, or executes anything beyond the
frozen mock/core modules — it is derived data only.
