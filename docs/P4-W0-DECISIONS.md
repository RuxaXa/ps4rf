# P4 — W0 Decision Record (owner-approved)

Status: **CLOSED / BINDING** — the PS4RF Project Owner / Research Lead answered
the W0 review packet (`docs/P4-W0-REVIEW-PACKET.md`) on 2026-10-05 with the
standing instruction *"Alle Empfehlungen übernehmen, mit den folgenden
verbindlichen Konkretisierungen"*, extended by the closing statement *"D1 bis D19
hiermit freigegeben"*. W1/W2 may proceed on this basis.

This file is the traceable record of those decisions. Where a decision produced
a repo change, the change is named; where a decision only constrains future work,
the constraint is binding for every later phase.

Standing constraints from the same decision (repeated verbatim in sense):

* P4 is **userland only**.
* No new kernel primitive without §70 approval
  (`docs/spec-history/70-capability-gated-native-primitive-additions.md`).
* No core architecture change outside a concrete integration finding: first
  document the parity/contract finding, then make only the minimal necessary fix.

## D1 — SDK / artifact source

* **D first**: the W2 protocol core stays fully in-repo and SDK-independent.
* As soon as the first real native primitive needs SDK functions: check
  **A (libPS4)** and **B (ps4 payload SDK)** practically against each other.
* Long-term target is **E (composition)**, with external build inputs always
  hash-pinned.

## D2 — ET_DYN ELF

* Variants **(1) and (3)**: the ELF is the reproducible build artifact; a flat
  BIN may be the delivery payload. **Both artifacts are hashed.**
* Additional build check: **ELF header must confirm `ET_DYN`**.

## D3 — Crypto stack

* **C1**: minimal crypto stack in-repo. Must be verified by RFC test vectors and
  the PS4RF golden vectors.
* No own cryptographic design; only necessary standardized primitives.

## D4 — Build inputs outside the repo

* An external SDK copy is allowed but **exclusively hash-pinned**.
* The repo stays source of truth for the toolchain manifest: **version, path /
  source ID, SHA256, build flags, compiler version, linker version**.
* An unpinned external SDK must not produce a reproducible build.

## D5 — Transport direction

* **connect out**: PS4 agent → operator host. A listening daemon moves to P5.
* Semantic roles stay independent of TCP direction: **AGENT sends HELLO, HOST
  sends HELLO_ACK**.

## D6 — P4 scope

* **userland only**; kernel primitives are not part of P4. Kernel extensions only
  later via the §70 capability-missing rule and with explicit approval.

## D7 — F1 AAD direction string

* Keep the **frozen bytes**: current core generation stays on `str(direction)`,
  i.e. `Direction.HOST_TO_AGENT` in the canonical AAD — recorded as a
  **documented compatibility wart**.
* **No change to `.value` inside the frozen core.** Such a change only in an
  explicitly versioned core/wire revision with new golden vectors.

## D8 — F2 sequence ceiling

* Document **and enforce** the ceiling. While `sequence` is a JSON integer in the
  canonical JCS structure: **`EFFECTIVE_LAST_SEQ = 2^53 - 1`**. The 64-bit header
  space does not change that.
* No AAD format change during the freeze.
* On reaching the effective ceiling: `SequenceExhausted`, close the session,
  **no wraparound**.
* → implemented in Core/Wire Revision R1 (`core/rpc/handshake.py`; pinned in both
  catalogs).

## D9 — F3 InvalidTag

* Map **centrally in the core**: one shared core helper catches the library
  exception `InvalidTag` and translates it into a PS4RF protocol exception.
  Mock and native use exactly the same helper.
* **No library-specific exception may leak out of the RPC layer.**
* → implemented in R1 (`core.rpc.handshake.open_authenticated` →
  `AuthenticationFailed`).

## D10 — F4 worker crash

* Take over the existing contract. **No pool auto-finalize.**
* Recovery / agent lifecycle must call `finish()` explicitly and exactly once.
* The parity test must prove token balance and request lifecycle.

## D11 — F5 lazy queue cancellation

* Take over: queued cancellation stays **lazy**; the host timeout budget must
  account for this serialization. No eager cancellation architecture in P4.

## D12 — F6 frame type byte table

* Declare the mapping **in-repo property**; since no older normative table exists,
  no historical byte identity is invented.
* Binding wire mapping v1: `0x01` REQUEST, `0x02` RESPONSE, `0x03` EVENT,
  `0x04` BYE, `0x05` READY.
* W2: REQUEST/RESPONSE/BYE active; EVENT reserved and never sent; READY reserved
  for a later fully defined shape and **out of the W2 byte-parity scope**.
* Any other value: **PROTOCOL_ERROR, session fail-close.**
* `_send_frame()` / `recv_frame()` must use **only** this shared table; the table
  is part of the versioned PS4RF wire specification.
* → implemented: `core/rpc/wire.py` (table + framing), `docs/P4-WIRE-SPEC-v1.md`,
  catalog `wire_frame.type_table` + per-frame `header_hex`/`wire_hex`.

## D13 — READY and EVENT

* Out of the active W2 parity scope.
* EVENT: reserved message type, no body in W2, the agent does not send it in v0.1.
* READY: the host may tolerate it for existing mock compatibility; native W2 need
  not send it. Active wire semantics only once shape, encryption status,
  capability content and state transition are fully specified — **no
  implementation may invent READY information until then**.

## D14 — Parity sharpness

* **Second variant**: bytes must be identical for crypto, AAD, framing, message
  encoding, canonicalization, sequence, message type.
* Scheduling and thread interleaving need only **semantic equivalence**, and all
  permitted scheduling deviations must be **listed explicitly**.
* → binding acceptance criterion for the W2 harness (documented in the W1
  test-vector spec and the parity catalog).

## D15 — Approval authority

* Signer = **PS4RF Project Owner / Research Lead**.
* Every new native primitive requires a concrete **Capability Missing Record**
  approved by the owner/research lead. **Hermes must not grant this approval
  itself.**

## D16 — P5 interface

* Deliverable **five items + manifest**: artifact format and SHA256,
  installation/delivery path, rollback procedure, evidence requirements,
  firmware profile binding, hash-pinned toolchain manifest.
* The same manifest additionally carries compiler, linker, SDK, build flags,
  source commit; **build timestamp is metadata, not hash authority**.

## D17 — §70 text

* **Text supplied by the owner** and stored verbatim as
  `docs/spec-history/70-capability-gated-native-primitive-additions.md`
  (normative for native primitive additions; §70.8 keeps P4 userland only; §70.9
  keeps PROVEN bound to the VerificationEvidence path; §70.10 requires the
  changelog entry to reference the approved Capability Missing Record, tests and
  evidence).
* → **W4 unblocked** (the former blocker "§70 text missing" is resolved).

## D18 — Freeze manifest

* Keep the point-in-time `SHA256SUMS`. Introduce a **drift log that the gates
  read**. No silent changes to the freeze manifest; re-freeze only with the next
  planned core/wire revision.
* Drift log entry fields: **file, old hash, new hash, reason, phase, review
  reference, core impact yes/no**.
* Non-core changes may drift documented; core changes after freeze require the
  revision process.
* → implemented: `FREEZE-DRIFT.md` + `tests/test_freeze_drift.py` (validates
  fields, hashes, and that **every** manifest mismatch is logged, and that both
  the point-in-time manifest and the freeze tag stay untouched).

## D19 — §44 request id allocator

* Keep **passthrough `lead_id` + remap hook**. No invented IDs.
* Until the normative §44 text exists: take over `lead_id` when valid, otherwise
  a controlled remap hook; document the mapping in the evidence.
* **No new global request-id algorithm in P4.**
* Current state (verified): `tools/orbisprobe/adapter.py` passes `lead_id`
  through and never invents identifiers; a remap hook is not implemented yet — it
  becomes required only when an invalid `lead_id` actually appears, and then its
  mapping must be documented in the evidence.

## Core/Wire Revision R1 (consequence of D8, D9, D12)

Scope, kept minimal: `core/rpc/handshake.py` (effective sequence ceiling +
central authentication mapping), new `core/rpc/wire.py` (shared frame table +
framing helpers), regenerated crypto/parity catalogs, new tests
(`tests/test_wire_frames.py`, +14 parity-checks). Freeze tag
`PS4RF-CORE-1.0-MOCK-READY` stays where it is; the drift log records the core
file change with `core impact: yes` and references this decision record.

## Unblocked / still open

* **Unblocked by W0:** W1 deliverables (`docs/PAYLOAD-SDK-CONTRACT.md`,
  `docs/P4-W1-TOOLCHAIN.md`), W2 native skeleton on both ends, W4 (native
  primitives under §70), byte-identical framing (D12), auth-error contract (D9),
  sequence ceiling (D8), freeze-drift discipline (D18).
* **Still owner-gated / later:** listening daemon (P5), any kernel/privileged
  primitive (§70.8 + D6), SDK decision A/B/E (D1 — only once a real native
  primitive needs SDK functions), §44 normative text (D19 — current behaviour is
  the interim contract).
