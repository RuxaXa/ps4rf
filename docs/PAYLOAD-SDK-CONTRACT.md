# P4 — Payload SDK & native artifact contract (W1 deliverable)

Status: **decided**. This contract supersedes the option space of
`docs/P4-W1-DRAFT-PAYLOAD-SDK-OPTIONS.md` (kept for rationale). Every clause below
is either an owner decision from the W0 record (`docs/P4-W0-DECISIONS.md`) or a
consequence of the frozen core / wire specification that the native side must
match. W2 builds against this document; deviations require a documented
parity/contract finding plus the minimal fix, not a redesign.

## 1. In-repo protocol core, SDK-independent (D1)

* The W2 protocol core — framing, AEAD, JCS canonicalization, dispatcher, request
  registry, pool semantics — stays **fully in-repo and SDK-independent**. No
  SDK type, header or helper appears in the protocol path.
* **D first**: the first native prototype is built against this in-repo core with
  no external SDK. Only when a real native primitive needs SDK functions
  (process startup, syscalls, sockets) do we compare **A — libPS4** and **B —
  ps4-payload-sdk** practically. Long-term target: **E — composition**, with
  every external build input hash-pinned (§4).

## 2. Artifacts (D2)

| Artifact | Role | Requirement |
|---|---|---|
| ELF | reproducible **build** artifact | ELF header must confirm **`ET_DYN`** (build check, not just convention); sha256 recorded |
| flat BIN | optional **delivery** payload | sha256 recorded; must be derived from the same build as the ELF |

* Both artifacts are hashed and both hashes are pinned in the toolchain manifest
  (§4) and in the P5 handoff (§9).
* The `ET_DYN` check is a hard build gate: a build whose ELF header reports
  `ET_EXEC`/`ET_REL` fails, it is not "adjusted" afterwards.

## 3. Crypto stack (D3)

* **C1: minimal in-repo stack**, no own cryptographic design — only the
  standardized primitives the wire specification needs
  (ChaCha20-Poly1305, AES-256-GCM, HKDF-SHA-256, HMAC-SHA-256, SHA-256, and JCS /
  RFC 8785 canonicalization).
* Verification is by **RFC test vectors and the PS4RF golden vectors**:
  `tests/fixtures/crypto/vectors-v1.json` (RFC 8439/5869/4231/8785 anchors +
  boundaries) and `tests/fixtures/parity/vectors-v1.json` (message level). A
  native crypto implementation that does not reproduce those bytes is wrong, not
  a variant.
* An external crypto library may only be used if it is hash-pinned per §4 **and**
  reproduces the same catalogs byte-for-byte.

## 4. External build inputs (D4, D16)

* An external SDK copy is allowed **only hash-pinned**. The repository remains
  source of truth for the toolchain manifest: version, path/source ID, sha256,
  build flags, compiler version, linker version (plus, per D16: compiler,
  linker, SDK, source commit, and a build timestamp that is **metadata, not hash
  authority**).
* An **unpinned external SDK must not produce a reproducible build** — the
  manifest validator (`tools/toolchain/toolchain_manifest.py`) refuses such a
  manifest, and the W2 build gate calls it.
* Schema, example and validation rules: `docs/P4-W1-TOOLCHAIN.md`.

## 5. Transport (D5)

* **connect out**: the PS4 agent connects to the operator host. A listening
  daemon on the console side is deferred to P5.
* Direction is a transport fact, not a role: **the agent sends `HELLO`, the host
  sends `HELLO_ACK`**, independent of who opened TCP. Frame direction rules then
  follow §3 of the wire specification.

## 6. Scope (D6, D17/§70.8)

* P4 is **userland only**. Kernel, GPUVM, KeyMgr, CCP, SAMU, PUP, EAP, SBRAM, EMC
  and secure-service primitives need an explicit approval for that privilege
  level/phase; every new native primitive needs an approved Capability Missing
  Record first (§70 text in
  `docs/spec-history/70-capability-gated-native-primitive-additions.md`).
* Kernel code / payloads: only with explicit new approval.

## 7. Wire-layer contract points the native side must match (R1)

| Point | Value / rule | Source |
|---|---|---|
| frame type bytes | `0x01` REQUEST, `0x02` RESPONSE, `0x03` EVENT (reserved), `0x04` BYE, `0x05` READY (reserved); any other byte = protocol error, fail-close | D12, `docs/P4-WIRE-SPEC-v1.md` |
| sequence ceiling | `EFFECTIVE_LAST_SEQ = 2**53 - 1`; beyond → `SequenceExhausted`, session closed, no wraparound | D8 |
| authentication failure | library `InvalidTag` maps to `AuthenticationFailed` (one shared helper); no library exception escapes the RPC layer | D9 |
| AAD direction string | keep `str(direction)` (`Direction.HOST_TO_AGENT`) — documented compatibility wart | D7 |
| direction rule | host→agent: REQUEST; agent→host: RESPONSE/EVENT/BYE | spec F16 |
| worker crash / cancellation | keep the existing contracts: no pool auto-finalize (`finish()` exactly once), queued cancellation stays lazy | D10, D11 |
| request ids | passthrough `lead_id` when valid, otherwise the controlled remap hook; mapping documented in evidence; no new global id algorithm | D19 |

## 8. Parity sharpness (D14)

* **Byte-identical** between Python reference and native implementation: crypto,
  AAD, framing, message encoding, canonicalization, sequence, message type.
* **Semantic equivalence** suffices for scheduling/thread interleaving — and every
  permitted scheduling deviation must be **listed explicitly** in the harness
  report; anything not listed counts as a failure.
* Acceptance basis: `tests/fixtures/crypto/vectors-v1.json` (forward + reverse)
  and `tests/fixtures/parity/vectors-v1.json` (messages, wire bytes, pool/agent
  semantics), per `docs/P4-W1-TESTVECTORS-SPEC.md`.

## 9. P5 handoff (D16)

P4 delivers exactly: (1) artifact format and sha256, (2) installation/delivery
path, (3) rollback procedure, (4) evidence requirements, (5) firmware profile
binding — plus the hash-pinned toolchain manifest carrying compiler, linker, SDK,
build flags, source commit and the timestamp as metadata.

## 10. Still owner-gated

* SDK choice A/B/E — decided only when a real native primitive needs SDK
  functions (D1); the comparison then follows §4 pinning.
* Normative §44 request-id text (D19) — until then §7 applies.
* `READY` wire semantics (D13) — reserved until shape, encryption status,
  capability content and state transition are specified.
