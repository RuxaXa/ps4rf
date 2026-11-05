# P4 — W0 review packet: every open decision in one pass

**STATUS: ANSWERED / CLOSED (2026-10-05).** The owner approved all 19 items —
*"Alle Empfehlungen übernehmen, mit den folgenden verbindlichen
Konkretisierungen"*, closing with *"D1 bis D19 hiermit freigegeben"*. The binding
record of the answers (including the delivered §70 text and the frame type byte
table) is `docs/P4-W0-DECISIONS.md`; the answered sheet is kept in §5 below for
traceability. Consequences implemented so far: Core/Wire Revision R1 (D8, D9,
D12), `docs/P4-WIRE-SPEC-v1.md`, §70 text under `docs/spec-history/`,
`FREEZE-DRIFT.md` + gate test (D18), W1 deliverables (D1–D4, D16).

Prepared for the W0 review gate. **Decision support only:** nothing here decides
anything, no code was written, and nothing touched a console.

Status at preparation time (verified, not claimed): suite `193 passed / 1 skipped`,
pre-flight `20/0` (main repo + gate clone), gate clone at the current commit with
`all_green: true` and a clean worktree, freeze tag `PS4RF-CORE-1.0-MOCK-READY`
untouched at `1536e35`.

| Artifact | Location | sha256 / commit |
|---|---|---|
| P4 plan (plan only) | `P4-NATIVE-PS4RFD-PLAN.md` | commit `b66cd42` |
| W1 options draft (no decision) | `docs/P4-W1-DRAFT-PAYLOAD-SDK-OPTIONS.md` | commit `f778298` |
| Crypto/handshake vector catalog + harness spec | `tests/fixtures/crypto/`, `docs/P4-W1-TESTVECTORS-SPEC.md` | catalog `d6f67fdb…` (v1.1, F16-aligned) |
| Parity vector catalog (W2 prep) | `tests/fixtures/parity/` | `3114dfb7…` (catalog), `eded4b27…` (generator) |
| This packet | `docs/P4-W0-REVIEW-PACKET.md` | see evidence pack |

Citations `Pasted_text(n).txt l.x` refer to `docs/spec-history/`.

---

## 1. Decisions that gate native work (W1/W2)

**D1 — Artifact source / toolchain** (plan Q1 + draft Q2).
Options: A libPS4 (prior campaign, strongest live evidence) · B Scene-Collective
`ps4-payload-sdk` (no in-repo evidence) · C OpenOrbis (app-level only) · D minimal
in-repo freestanding skeleton · E composition.
Consequence: A/B/C define the build regime *and* its provenance/licence record;
D keeps the protocol core fully in-repo and hash-pinned, but provides no console
service helpers (no network init, no loader glue) — those would still be needed
before any live primitive.
*Hermes recommendation (non-binding):* build the W2 protocol core as **D** (it needs
no SDK: crypto, JCS, framing, dispatcher are all in-repo-able), and decide A vs. B
only when the first live primitive needs SDK helpers — expecting **E** as end state.
Blocks: W2 packaging, toolchain manifest.

**D2 — Reading of "ET_DYN ELF"** (draft Q1, §5; plan R3).
Options: (1) ELF = build artifact, flat BIN = delivery (both hashed; matches every
live-proven payload) · (2) ELF = delivery via the HTTP route · (3) ET_DYN as ELF
*type* requirement on the build artifact only.
Consequence: (1) reuses the proven `objcopy -O binary` path and its zero-relocation
gate; (2) adds a second delivery/evidence path that has never been exercised here;
(3) leaves delivery undefined — the weakest binding.
*Hermes recommendation:* reading **(1)**, with (3) as an additional build-artifact
check; the BinLoader applies no dynamic relocations on either route.
Blocks: W2 packaging step, P5 delivery runbook.

**D3 — Crypto stack** (draft Q3).
Options: C1 in-repo minimal (own/vendored single-file, hash-pinnable, RFC-vector
testable) · C2 vendored third-party single-file (faster to correct, adds licence +
provenance) · C3 console-native crypto (unproven here; not a P4 candidate).
*Hermes recommendation:* **C1**, verified against the normative vectors already in
`tests/fixtures/crypto/vectors-v1.json`; C2 acceptable if hash-pinned like any build
input.
Blocks: W1 contract (`docs/PAYLOAD-SDK-CONTRACT.md`), crypto implementation plan.

**D4 — Build inputs outside the repo** (draft Q4).
Option A: staged outside the repo, hash-pinned in a manifest, never committed ·
Option B: repo must remain the only input source.
*Hermes recommendation:* A (with the manifest in-repo) — SDK/CRT copies stay
uncommitted but reproducible.
Blocks: toolchain manifest format.

**D5 — Transport direction** (draft Q5).
Option A: connect-out from the console to the operator host (as in every
live-proven payload), listen direction deferred to P5 · Option B: listening daemon.
*Hermes recommendation:* A as the working assumption.
Blocks: W2 session bootstrap, P5 runbook.

**D6 — Scope: userland-only or kernel primitives in P4?** (plan Q3, draft Q6).
Option A: P4 accepts a **userland-only** agent; kernel primitives deferred to P5 or
a separate approval · Option B: bound kernel primitive set inside P4.
Consequence: B requires the missing §70 rule text and a kernel-capable candidate,
and contradicts the plan's own non-goal ("no kernel code in P4").
*Hermes recommendation:* A.
Blocks: W3 registry/capability work, the plan's DoD wording.

## 2. Contract verdicts (findings from the catalogs)

**D7 — F1: AAD direction string.** Frozen `build_aad` embeds `str(direction)`, so
AAD bytes carry `"Direction.HOST_TO_AGENT"`/`"Direction.AGENT_TO_HOST"` (Python 3.13
`(str, Enum)`), not the enum *value*. Options: (a) native reproduces the frozen
bytes and we record the wart · (b) change the core to `.value` (regenerates both
catalogs and every sealed frame; needs a deliberate freeze revision).
*Hermes recommendation:* (a) now; (b) only inside a planned core revision.
Blocks: nothing today; native byte-identity.

**D8 — F2: sequence ceiling.** AAD carries `sequence` as a JSON int, so the
safe-number policy caps encodable sequences at `2^53−1`, while `LAST_SEQ` is
`2^64−2`. Options: (a) document + enforce the cap in code · (b) change the AAD
encoding (bytes change; freeze revision) · (c) lower `LAST_SEQ` to match.
*Hermes recommendation:* (a).
Blocks: native counter design, wrapper-boundary clarity.

**D9 — F3: `InvalidTag` surfacing.** A type byte that contradicts the sealed
message type, a bad tag, or a cross-direction frame makes `DirectionChannel.open`
raise the library exception `InvalidTag` (only sequence errors map to
`ReplayDetected`/`SequenceExhausted`). Options: (a) map `InvalidTag` centrally in
the frozen core (one helper both mock and native use) · (b) map it in the native
session loop only · (c) leave as is.
Consequence of (c): fail-close is not guaranteed; a tampered frame can surface as an
unhandled exception.
*Hermes recommendation:* (a), decided at W2 start.
Blocks: W2 session loop, fail-close matrix.

**D10 — F4: worker crash leaves the task pending.** After `on_worker_crash` the
task keeps its in-flight token until `finish(rid)`; there is no implicit
finalization. Options: (a) adopt as contract: recovery must call `finish()`
explicitly, and a crash leaves the pool permanently one token short otherwise ·
(b) change the pool to auto-finalize on crash (behaviour change, freeze revision).
*Hermes recommendation:* (a) + a pinned parity test on token accounting.
Blocks: W2/W3 recovery rules.

**D11 — F5: lazy queue cancellation.** `on_canceled` (and therefore the
`SESSION_RECOVERY_REQUIRED` reply) fires only when a worker actually reaches the
queued task; with one worker that is after the running task finishes. Options:
(a) adopt; host timeout budgets account for serialization · (b) change the pool to
cancel eagerly (behaviour change).
*Hermes recommendation:* (a).
Blocks: host-side timeout policy.

**D12 — F6: the frame type byte table is missing.** `recv_frame` reads
`4B len ‖ 1 type byte ‖ 8B seq ‖ ciphertext` and indexes `FRAME_TYPE_NAMES`, but
neither the table nor `_send_frame` is defined anywhere in the spec excerpts.
Options: (a) owner supplies `FRAME_TYPE_NAMES` (byte → message type) —
byte-identical framing becomes possible · (b) declare the type byte an in-repo
owned mapping (then the spec text needs an amendment and parity means "consistent
with our own mapping").
Consequence of neither: the framing layer cannot be byte-identical, so W2's
"byte-identical RPC trace" cannot include the header.
Blocks: W2 framing parity.

**D13 — Missing message shapes: READY frame and `EVENT` body.** READY is sent by
the spec mocks but is not in the frozen code and not part of the F16 inbound sets;
it is also unclear whether it is plaintext or sealed. `EVENT` is a valid
agent→host type with no defined body. Options: (a) owner supplies both shapes ·
(b) declare READY out of W2 parity scope (host tolerates it, native may omit it
until later) and `EVENT` reserved/never sent in v0.1.
*Hermes recommendation:* (b) for W2, (a) whenever available.
Blocks: W2 completeness of the message layer.

## 3. Acceptance and process questions

**D14 — Parity strictness** (plan Q5). Options: byte-identical RPC trace for the
whole session · byte-identical for crypto/framing/message bytes, semantic
equivalence (with documented, enumerated differences) for scheduling/interleaving.
*Hermes recommendation:* the second — single-worker interleaving order is not
reproducible by construction.
Blocks: W2/W6 exit criteria wording.

**D15 — Approval authority** (plan Q4): who signs a "capability-missing"
justification that admits a new native primitive? Pure governance; the plan and
`SAFETY-AND-EXECUTION-RULES.md` require a named signer per primitive.
Blocks: W3/W4 gates.

**D16 — P5 interface** (plan Q6): which deliverables does P4 owe P5 (artifact
format and hashes, installation path, rollback story, evidence requirements,
profile binding)? *Hermes recommendation:* the five named in the plan plus the
hash-pinned toolchain manifest from D4.
Blocks: handover completeness.

**D17 — §70 text** (plan Q2): the v0.1 excerpt references §70 (capability-gated new
primitives) but it is absent from `docs/spec-history/`. W4 stays blocked without it.
Blocks: W4.

**D18 — Freeze manifest** (plan Q7): root `SHA256SUMS` is a point-in-time freeze
record; five phase-touched non-core files now drift (`TOOLS.md`, `pyproject.toml`,
three `tools/metasploit/*`), all `core/*` entries still match, and neither
pre-flight nor G1–G8 checks it. Options: (a) keep as a record and add an explicit
drift log that the gates read · (b) re-issue at named review points (a "re-freeze"
commit).
*Hermes recommendation:* (a) now, (b) at the next planned freeze revision.
Blocks: nothing today.

**D19 — §44 request-id allocator (carried from P1):** spec §44 (K/U-NNN allocation)
is missing. Options: (a) owner supplies §44 · (b) keep the current passthrough
`lead_id` + remap hook and never invent an ID format.
*Hermes recommendation:* (b) until (a) exists; the adapter already refuses to
invent IDs.
Blocks: nothing today.

## 4. Already settled — no need to re-decide

* P4 is plan-only; no payload/kernel code in P4, nothing executed against a console
  (plan §5, DoD §10).
* Adapters are offline-first pure translators; `tools/metasploit/` is the single
  documented network client (loopback/TLS, token per call, never logged).
* N4 redaction: `<redacted>`, no secret digests, `options_sha256` secret-independent.
* Single attempt per call, no implicit retry.
* Gate procedure: clone at HEAD, inherited freeze tag deleted in the clone, logs
  outside the clone, runner sets the tag only when all gates are green.
* Mock stays normative for W2 parity; the catalogs are derived data, decision-free.
* msf-namespace records are capped at `OBSERVED`; `PROVEN` requires a separate
  `verify.*` record from a PS4RF-native provider.

## 5. Answer sheet (as answered by the owner, 2026-10-05)

Binding record: `docs/P4-W0-DECISIONS.md`. Short form of the answers:

```text
D1  SDK/candidate:        [x] D in-repo first; A vs. B compared at the first real SDK need; long-term E composition (hash-pinned)
D2  ET_DYN reading:       [x] (1) build artifact + optional flat BIN  [x] (3) type check on the ELF header; both artifacts hashed
D3  Crypto:               [x] C1 in-repo minimal stack, verified by RFC + PS4RF golden vectors
D4  SDK copy outside repo:[x] allowed + hash-pinned; repo owns the toolchain manifest
D5  Transport:            [x] connect-out (agent -> host); listening daemon deferred to P5; AGENT sends HELLO, HOST sends HELLO_ACK
D6  Scope:                [x] userland-only for P4; kernel primitives only later via §70 + explicit approval
D7  F1 AAD direction:     [x] keep frozen bytes (str(direction)), documented compatibility wart; no .value change in the frozen core
D8  F2 sequence cap:      [x] document + enforce EFFECTIVE_LAST_SEQ = 2^53-1; SequenceExhausted, session closed, no wraparound
D9  F3 InvalidTag:        [x] map centrally in the core (one shared helper); no library exception leaves the RPC layer
D10 F4 crash pending:     [x] adopt the contract; no pool auto-finalize; finish() exactly once; parity test proves token balance
D11 F5 lazy cancel:       [x] adopt; host timeout budget must account for the serialization
D12 F6 frame type table:  [x] in-repo owned mapping v1: 0x01 REQUEST, 0x02 RESPONSE, 0x03 EVENT, 0x04 BYE, 0x05 READY; others = PROTOCOL_ERROR fail-close
D13 READY/EVENT shapes:   [x] out of the W2 parity scope for now; EVENT reserved (no body), READY reserved (mock tolerance only)
D14 Parity strictness:    [x] second variant: bytes identical for crypto/AAD/framing/encoding/canonicalization/sequence/message type; scheduling = semantic equivalence, deviations listed
D15 Primitive approval:   signer = PS4RF Project Owner / Research Lead; Hermes must not self-approve
D16 P5 interface:         [x] plan's five + hash-pinned toolchain manifest (compiler, linker, SDK, flags, source commit, timestamp as metadata)
D17 §70:                  [x] text supplied by the owner (stored verbatim, normative)
D18 Freeze manifest:      [x] keep point-in-time SHA256SUMS + drift log (file, old/new hash, reason, phase, review reference, core impact), read by the gates
D19 §44 allocator:        [x] keep passthrough lead_id + remap hook; no new global id algorithm in P4
```

## 6. What answering unblocked (now resolved)

| Answer | Unblocked |
|---|---|
| D1, D2, D3, D4 | W1 contract docs (`docs/PAYLOAD-SDK-CONTRACT.md`, `docs/P4-W1-TOOLCHAIN.md`) — **written** |
| D5, D12, D13, D14 | W2 skeleton + parity harness scope — **unblocked** (framing now byte-defined) |
| D7–D11 | native byte-level claims — **resolved** (R1 implemented what D8/D9 required; D7/D10/D11 bind as-is) |
| D15, D17 | W3/W4 (registry, capability gate, §70 rule) — **unblocked** (§70 text stored) |
| D16 | P5 handover — **specified** |
| D18, D19 | housekeeping — **implemented** (drift log + gate test; §44 interim contract recorded) |

W0 has passed; native work proceeds strictly under `docs/P4-W0-DECISIONS.md`, the
wire specification and §70. P4 remains userland only.
