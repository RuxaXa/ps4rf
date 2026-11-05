# P4/W1 — crypto & handshake test-vector catalog: spec and native harness contract

Status: **pre-review artifact** (input for W0/W1) · written 2026-10-05 ·
decision-free work package: no SDK choice, no payload code, no kernel code,
nothing executed against a console.

Companion artifacts:

* Catalog: `tests/fixtures/crypto/vectors-v1.json` (sha256
  `dc5b99d6ce4f59b6c823fb042a5d55d139dee96fdb677600ee4ba388cbf62b63`)
* Generator: `tests/fixtures/crypto/gen_vectors.py` (offline, deterministic)
* Pinned fixture README: `tests/fixtures/crypto/README.md`
* Self-verification: `tests/test_crypto_vectors.py`

## 1. Why this exists

The frozen host core defines the wire contract exactly:

* `core/canonical.py` (sha256 `e35983f1…`) — **JCS/RFC 8785** canonicalization
  plus the safe-number policy (±(2^53−1), finite only, string keys only).
* `core/rpc/handshake.py` (sha256 `497a77a9…`) — HELLO/HELLO_ACK/AUTH/AUTH_ACK
  transcript, HKDF-SHA256 key schedule, HMAC proofs, ChaCha20-Poly1305 /
  AES-256-GCM frames, sequence discipline, framing limits.

Whatever SDK or toolchain the native agent uses (see
`docs/P4-W1-DRAFT-PAYLOAD-SDK-OPTIONS.md`), **this protocol core stays in-repo
and must reproduce these bytes exactly**. This catalog therefore pre-computes
the acceptance set *before* any native code exists, so W2 can be built
test-first and so the SDK decision does not delay the protocol work.

## 2. Vector classes

1. **RFC anchors** (`rfc_vectors`) — independent of this repo, verified against
   `cryptography`/`hashlib`/`hmac`/`rfc8785` at generation time: RFC 8439
   §2.8.2 (AEAD incl. nonce construction `fixed-common ‖ IV`), RFC 5869 A.1–A.3
   (PRK + OKM; case 3 zero-length salt/info), RFC 4231 §4.2–4.8 (SHA-256 rows;
   case 5 is truncated in the RFC and intentionally absent), RFC 8785 §3.2.2
   sample and 24 Appendix B number rows.
2. **Protocol-derived** (`protocol`) — transcript hash, three derived keys,
   proofs, both nonce prefixes, AAD bytes, four sealed frames, and the complete
   four-message handshake exchange produced by running the real
   `agent_handshake` against the real `host_handshake` over an in-memory
   endpoint pair (TEST-ONLY PSK/nonces).
3. **Boundaries** (`boundaries`) — 21 cases where the *outcome* is the vector:
   safe-number rejections, the AAD sequence ceiling, length checks, unknown
   suite, oversize seal **without** sequence consumption, replay detection,
   tag tamper, oversize open, exhausted sequence counter, handshake frame
   > 64 KiB. Each records either the produced bytes (hex) or the exception
   class name.

## 3. Native harness contract (what W2 builds against)

The catalog is consumed in two directions; both are offline.

### 3.1 Forward check (native verifies against frozen bytes)

CLI (name proposal, W2 may rename):

```text
ps4rf_cryptovec --vectors tests/fixtures/crypto/vectors-v1.json --out report.json
```

* One process, no sockets, no arguments beyond the two paths.
* Recompute every entry: RFC cases with the native crypto primitives, protocol
  cases with the native JCS encoder + handshake code, boundary cases by
  performing the action and classifying the outcome.
* Compare **byte-exactly** (hex-level). No partial credit: one mismatching byte
  is FAIL for that vector.
* For failures, report the first differing byte index and both hex prefixes.
* Sequence semantics must match the frozen ones: a rejected oversize seal must
  leave the counter untouched; a rejected open must not advance `recv`.

Report schema:

```json
{
  "schema": "ps4rf-cryptovec-report-v1",
  "vectors_sha256": "<sha256 of vectors-v1.json as read>",
  "tool": {"name": "ps4rf_cryptovec", "version": "..."},
  "results": [{"id": "<vector id>", "status": "PASS|FAIL", "detail": "..."}],
  "summary": {"passed": 0, "failed": 0}
}
```

Exit codes: `0` all PASS · `1` any FAIL · `2` input/parse error (bad file,
unreadable, schema mismatch). A report is written in all three cases (code 2
with an empty `results` array and the reason in `detail` of the summary entry).

### 3.2 Reverse check (Python verifies native bytes)

The native side must also be able to **produce**: given the same inputs (PSK,
nonces, objects, sequences), emit its own HELLO/AUTH frames and sealed frames as
hex. A host-side checker (W2) re-runs the frozen implementation on the same
inputs and compares. This catches the failure mode where both sides "understand"
the vectors but disagree on generation.

Interface (proposal): `ps4rf_cryptovec --emit exchange-frames.json` produces the
same shape as `protocol.exchange`; the host checker diffs it against the frozen
recomputation. The reverse direction is required because vector *consumption*
alone cannot prove the native encoder is byte-stable.

### 3.3 Mutation probes (must fail)

To prove the checker is not vacuous, W2 must inject, for a sample of vectors:

* one flipped byte in a sealed frame → expect `InvalidTag` (or FAIL on compare);
* one flipped byte in the AAD → expect tag verification failure;
* a wrong receive sequence → expect replay classification;
* a truncated handshake frame → expect protocol error at the length prefix.

A checker that reports PASS on mutated input is a FAIL of the harness itself.

## 4. Acceptance criteria (W2 exit, offline)

1. Forward check: 100 % PASS on a clean build, including all 21 boundary rows.
2. Reverse check: native-emitted exchange frames byte-identical to the frozen
   recomputation.
3. Mutation probes: all injected mutations are rejected with the documented
   classification.
4. Reproducibility: two clean native builds produce identical reports; the
   catalog hash in the report matches the pinned fixture.
5. Findings F1/F2 (below) are either fixed in the core (catalog regenerated in
   the same change) or explicitly carried as open decisions in the report.

## 5. Findings carried by the catalog

* **F1 — AAD direction string.** The frozen `build_aad` embeds
  `str(direction)`; with the `Direction` enum that is literally
  `"Direction.AGENT_TO_HOST"`, while the enum *value* is `"agent-to-host"`.
  Both variants are pinned in the catalog. The native side must follow the
  frozen bytes; correcting the core is an owner decision (any change regenerates
  the catalog and every frame).
* **F2 — Sequence ceiling.** AAD carries `sequence` as a JSON integer, so the
  encodable range ends at `2^53 − 1` although `LAST_SEQ` is `2^64 − 2`. Pinned
  on both sides; reconcile or document in the contract.

## 6. Non-goals

* No decision on SDK, toolchain, or where the crypto implementation comes from
  (in-repo vs. vendored) — that is W1/Q3.
* No production keys, no live session material; all constants are TEST-ONLY.
* No payload, no kernel code, no console interaction.
* No claims about loader mechanics (relocations, delivery form) — those are the
  image gates in the options draft §5/§7.

## 7. Provenance & regeneration

* Generator: `tests/fixtures/crypto/gen_vectors.py`; regeneration command and
  determinism rules in `tests/fixtures/crypto/README.md`.
* RFC provenance (URLs + sha256 of the fetched plain-text files) is recorded in
  the fixture README and inside the catalog (`rfc_vectors._provenance`).
* The catalog embeds the sha256 of the two frozen modules it was derived from;
  `tests/test_crypto_vectors.py` fails when they drift without regeneration.
* Evidence pack for this artifact (including the fetched RFC texts): see the
  P4/W1-prep evidence directory in `~/07-evidence/`.

## 8. Companion artifact — parity catalog (W2 prep)

`tests/fixtures/parity/vectors-v1.json` (generator `gen_parity.py`, checks in
`tests/test_parity_vectors.py`) carries the message- and behaviour-level vectors
for W2:

* five byte-level frames (two inbound `REQUEST`s, outbound `RESPONSE` OK /
  `RESPONSE` ERROR, `BYE`) with canonical plaintext, nonce, ciphertext and the
  spec citation for each message *shape* (encoding/sealing is frozen code);
* observed frozen semantics for `RequestIdRegistry`, `BoundedPool`,
  `mock/agent.py` and `DirectionChannel`, recorded as data;
* the F16 direction rule (`host→agent`: `REQUEST`; `agent→host`:
  `RESPONSE`/`EVENT`/`BYE`), the post-handshake frame header layout
  (`4B len ‖ 1B type ‖ 8B seq ‖ ciphertext`) and the open shape questions (READY
  frame, `EVENT` body, missing frame type byte table);
* findings F3–F5 (library-level `InvalidTag`, crash leaves the task pending until
  `finish()`, lazy queue cancellation) and gap F6 (the `FRAME_TYPE_NAMES` byte
  table is referenced but absent from the sources) — see the parity README.

Both catalogs share one TEST-ONLY session (asserted during generation). The
native harness therefore has two inputs: this crypto catalog for primitives and
the parity catalog for messages/state transitions.
