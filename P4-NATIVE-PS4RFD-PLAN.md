# P4 — Native ps4rfd: Plan (PLAN ONLY — no implementation)

> Note (owner, 2026-10-05): the wave numbering below is the original plan; the owner's W8
> brief redefines W8 as "Live Userland Bring-up + Target Attestation" (first controlled live
> step, userland only). The binding scope is `docs/P4-W8-LIVE-BRINGUP.md`.


Status: **plan artifact, nothing built** · written 2026-10-05 · repo commit
`7c6e190` (P3 complete) · requires review before any work package starts.

This document plans the native agent (`ps4rfd` on the PS4) as required by
`HERMES-TODO.md`:

> ## P4 — Native ps4rfd
> Plan only after the host core and adapters are stable. Keep it
> primitive-oriented and profile-driven.

Per the delivery-2 handoff, code does not start here:

> Danach erst (P4): echter ps4rfd planen. Kernel Code / Payloads: nur mit
> expliziter neuer Freigabe. (`docs/spec-history/Pasted_text(20261005-115353).txt`
> line 167, sha256 `903547569942c6172a297b2d4ceaa50488ac24543513b9185d68805468098532`)

## 1. Entry criteria — met

| Criterion | Evidence |
|---|---|
| Host core frozen | tag `PS4RF-CORE-1.0-MOCK-READY` @`1536e35`, untouched by P1–P3 (each phase re-set it in a throwaway clone only) |
| Adapters stable | P1 OrbisProbe, P2 Metasploit, P3 Ghidra/Rizin/angr/AFL++ — each offline, mock-tested, evidence-packed (4/4) |
| Gates green | preflight 20/0 and G1–G8 `all_green: true` in every phase clone; full suite 171 passed / 1 skipped at `7c6e190` |
| Normative sources identified | `core/rpc/pool.py`, `core/rpc/hang.py`, `core/resources/manager.py`, glue in `mock/agent.py` (handoff §"Normative Quellen") |

**Freeze-manifest note (found during planning):** the root `SHA256SUMS` manifest
(95 entries, frozen state) still matches **all `core/*` entries**, but 5
phase-touched non-core files have drifted: `TOOLS.md`, `pyproject.toml` and the
three `tools/metasploit/*` files (P2 replaced their stubs). Neither preflight
nor the G1–G8 gate suite checks this manifest, so the drift is currently
invisible to the gates. Decision requested in §8/Q7: leave the manifest as a
point-in-time freeze record, or re-issue it at a defined review point. No silent
update was made.

## 2. Target architecture (fixed by the frozen spec)

```text
Research Host (authoritative)
  ps4rfctl · Experiment Engine · Evidence Store · OrbisProbe/Tool adapters
        |
        +==== authenticated, AEAD, versioned RPC ====> ps4rfd (today: MockAgent)
                                                      +-- userland primitives
                                                      +-- kernel primitives
                                                      +-- GPUVM / KeyMgr / CCP / SAMU
```

Binding rules from the spec:

* ps4rfd exposes **only primitives** (`memory`, `gpuvm`, `keymgr`, `ccp`,
  `kernel.snapshot`, `sync`, `verify.*`) — **no experiment logic, no firmware
  RVAs in code; RVAs only in profiles** (`Pasted_text(20261005-115353).txt` line 52).
* Handshake: agent sends `HELLO` → receives `HELLO_ACK` → sends `AUTH` →
  receives `AUTH_ACK`; semantic roles are independent of the TCP
  connect/accept direction (`Pasted_text(8).txt` line 184, `ARCHITECTURE.md`).
* The primitive set already exists as the host's operation registry:
  `core/rpc/registry.py::default_registry()` (sha256 `788ef091…`) registers
  `memory.alloc/free`, `gpuvm.map/unmap/lookup`, `keymgr.claim/release/snapshot`,
  `ccp.submit`, `kernel.snapshot/read/dump.full`, `session.ping/status`,
  `telemetry.read`, `sync.barrier.*`, `sync.gate.*`, `experiment.load`,
  `mock.*` (mock-only), `verify.*`.
* Capability/provider model already exists host-side:
  `core/models/capability.py` (sha256 `2d999bc7…`) — `CapabilityRecord`
  (availability/assurance/context/provider/scope), `ProviderRule`
  (provider_type, max_assurance, availability_write), `CapabilityIntake`.
* Current profiles are **placeholders**: `profiles/fw1352/README.md`
  (sha256 `ff55d153…`) and `profiles/fw900/README.md`
  (sha256 `acd3707d…`) state "populate from verified evidence only".

Deliverable shape per `HERMES-TODO.md`/handoff: **PS4-Payload-SDK, ET_DYN ELF,
provider interfaces, and new native primitives only when a capability is
missing (v0.1 §70)**.

## 3. Binding principles

1. **Primitive-oriented.** Registered primitives only; no generic
   `call(address, args)`, no arbitrary kernel-write RPC; only registered
   primitives may be executed by the agent (`SAFETY-AND-EXECUTION-RULES.md`).
2. **Profile-driven.** Firmware addresses resolve through profiles; EAP
   evidence-only population rule; no RVA literals anywhere in code.
3. **Offline-first.** Native development is driven by *parity with MockAgent*;
   no live PS4 work in P4.
4. **Fail-closed.** Unknown state becomes `UNCERTAIN` → console dirty →
   recovery; no automatic retry after hang/panic/crash; cleanup fails closed.
5. **Evidence-bound.** No invented evidence, no PASS without a real run; every
   step ships a hash-verified evidence pack (discipline of P1–P3).
6. **Capability-gated additions.** A new native primitive is added only when a
   required capability is missing (§70), through an explicit review (W4).
7. **Single-attempt RPC discipline** inherited from adapters and hang semantics.

## 4. Work packages

Each package: goal → deliverables → exit criteria (offline-verifiable) →
evidence. No package may start before its predecessor's exit criteria pass
review.

**W0 — Plan review** *(this document)*
* Goal: agree scope, principles, gates and open questions.
* Exit: review **PASS** by the owner; no code exists. Evidence: this file +
  review note.

**W1 — Payload-SDK contract & toolchain decision** *(offline research)*
* Goal: decide the native artifact contract (PS4-Payload-SDK vs. minimal custom
  skeleton), ET_DYN ELF constraints, reproducible build inputs, artifact hashing.
* Deliverable: `docs/PAYLOAD-SDK-CONTRACT.md` + `docs/P4-W1-TOOLCHAIN.md`
  (options, trade-offs, decision + rationale).
* Exit: contract reviewed; no payload or kernel code produced.

**W2 — Agent skeleton & handshake parity** *(native userland only, offline)*
* Goal: ps4rfd skeleton implementing the frozen handshake/AEAD/state machine
  (`core/rpc/handshake.py`, `core/rpc/pool.py`, `core/rpc/hang.py`) and nothing
  else; parity harness vs. `mock/agent.py`.
* Deliverables: skeleton source, host-side parity vectors (bytes in/out),
  parity test results.
* Exit: parity tests green offline against the mock reference; byte-level
  handshake traces match pinned vectors.

**W3 — Primitive surface freeze v1 + provider interfaces**
* Goal: map each registry operation to a native provider interface with strict
  request/response schemas; one provider per family (`memory`, `gpuvm`,
  `keymgr`, `ccp`, `kernel.*`, `sync`, `verify.*`); declare `ProviderRule`
  values (type, max assurance, availability_write) for the native provider.
* Deliverables: interface spec `docs/P4-PRIMITIVE-INTERFACES.md`, host-side
  stubs + tests, provider registry wiring plan (no frozen-core behaviour change
  without a recorded integration finding).
* Exit: schemas validated by tests; every registry operation either mapped or
  explicitly deferred with reason.

**W4 — Capability-gating process (§70)**
* Goal: formalize "new native primitive only when a capability is missing":
  request form (capability name, missing-capability evidence, proposed
  primitive, profile binding, risk note), review step, decision record,
  freeze-patch discipline.
* Deliverable: `docs/P4-CAPABILITY-GATE.md` + template + a worked dry-run
  example (no real primitive added).
* Exit: process reviewed; **blocked until the v0.1 §70 text is available**
  (see §7/R1) — the dry-run may precede it, the process may not be declared
  final.

**W5 — Profile binding path (fw1352/fw900)**
* Goal: profile schema for signatures/RVAs/structures + validation chain, and
  the host-side rules that bind primitives to profile entries at call time.
* Deliverables: profile schema + validators + tests; placeholder profiles kept
  evidence-only (no invented values).
* Exit: schema tests green; a profile entry that is not evidence-backed is
  refused by construction.

**W6 — Differential parity harness (mock vs. native)**
* Goal: run identical host-side experiment scripts against MockAgent and the
  native agent and compare resulting evidence records field by field.
* Deliverables: harness + comparison report format + mock-vs-mock baseline.
* Exit: baseline parity green offline; mismatch classification documented
  (semantic difference vs. bug vs. profile drift).

**W7 — Host provider wiring for the native agent**
* Goal: register the native agent as a provider (`provider_type` native,
  authority rules: what assurance a native provider may claim without
  store-bound verification — proposal: cap at `OBSERVED` until P5 proves
  otherwise), capability intake, availability transitions.
* Deliverables: wiring patch + tests + authority-rule doc.
* Exit: tests green; frozen-core change, if any, recorded as an integration
  finding with a minimal patch and a fresh freeze check.

**W8 — Offline acceptance & handover to P5**
* Goal: acceptance checklist for the native agent (offline), plus the mapping
  onto the v0.1 §60–66 hardware acceptance phases for P5 (on-site only).
* Deliverables: `docs/P4-ACCEPTANCE.md`, P5 handover note.
* Exit: reviewed checklist; **no hardware action in P4**.

## 5. Explicit non-goals (P4)

* No kernel code, no payload deployment, no live PS4 interaction (new explicit
  approval required — spec line 167; hardware/reboot/HEN only on site).
* No RVA/signature invention; no profile values without evidence.
* No architecture change in the frozen host core; no new host-side "call any
  address" surface, no auto-remediation, no exploitability claims.
* The mock stays normative: native semantics count as equal only where the
  parity harness proves it, primitive by primitive.

## 6. Gates, approvals, repo discipline

* Review gates at W0 (plan), W1 (SDK), W3 (interfaces), W5 (profiles),
  W7 (providers), W8 (acceptance). Milestone/commit only on review **PASS**.
* New explicit owner approval required before: kernel code, payload delivery,
  any live PS4 run, any change to freeze-gated core behaviour.
* Repo discipline per package (as in P1–P3): small commits, preflight 20/0,
  full test suite green, gate suite G1–G8 run in a throwaway clone with the
  inherited tag deleted, `all_green: true` + clean worktree, evidence pack with
  `sha256sum -c` verification, freeze tag in the main repo untouched.

## 7. Risks & missing sources

* **R1 — v0.1 §70 text is missing.** `grep -rn "§70" docs/spec-history/`
  finds only the *reference* (line 204), not the rule text. The capability-gate
  process (W4) cannot be finalized without it.
* **R2 — Payload-SDK shape unknown offline**: availability, license, build
  reproducibility, ELF constraints. Drives W1; blocks W2/W3 if unresolved.
* **R3 — ET_DYN loader realities** (relocations, allocation, entry) are not
  documented in the repo → W1 must record assumptions explicitly.
* **R4 — Frozen-core pressure**: provider wiring (W7) may want core changes;
  each is an integration finding → minimal patch + review, never a redesign.
* **R5 — Scope creep into P5** (live work) — bounded by §5 non-goals and by the
  fact that all P4 exits are offline-verifiable.
* **R6 — Evidence-only profiles mean some primitives may be undeliverable
  offline** until verified values exist; those stay `PLANNED` rather than
  guessed.

## 8. Open questions for review

1. **SDK**: use the public PS4 payload SDK, or a minimal in-repo ET_DYN
   skeleton whose only job is the primitive dispatcher?
2. **§70**: can the v0.1 excerpt (or its rule text) be provided?
3. **Kernel primitives in P4?** The registry lists `kernel.snapshot/read/
   dump.full`. Is P4's acceptance target a **userland-only** agent (kernel
   primitives deferred to P5/explicit approval), or is a bounded kernel
   primitive set part of P4?
4. **Approval authority**: who signs a capability-missing justification that
   admits a new native primitive?
5. **Parity strictness**: is byte-identical RPC trace the acceptance bar for
   W2/W6, or is semantic equivalence with documented differences acceptable?
6. **P5 interface**: which deliverables does P5 need from P4 (artifact format,
   installation path, rollback story) so the handover is complete?
7. **Freeze manifest**: re-issue root `SHA256SUMS` at a defined review point,
   or keep it as a point-in-time record (with drift documented as above)?

## 9. Traceability (sources, sha256)

| Source | sha256 | Used for |
|---|---|---|
| `HERMES-TODO.md` | `34cde8ae724eb9ace50329b698757357f8f129e0505e9a3625fe584f64b8db05` | P4 scope line ("plan only … primitive-oriented and profile-driven"), P5 lines |
| `docs/spec-history/Pasted_text(20261005-115353).txt` | `9035475699…098532` | primitives-only rule (l. 52), flow (l. 113), "P4 after adapters + approval" (l. 167), P4 DoD incl. SDK/ET_DYN/§70 (l. 202–204) |
| `docs/spec-history/Pasted_text(8).txt` | `4d462037c832fbdb51db9c65e3e4def738899be69b65ed1b6665a63432a296c2` | handshake roles (l. 184) |
| `docs/spec-history/Pasted_text(5).txt` | `b062b113721687fd43515565a6df1871cbb19fe2da1c44daa62fc540c798410a` | mock ps4rfd integrated architecture (l. 892) |
| `docs/spec-history/Pasted_text(4).txt` | `88b423ea051f9d553d8fd48c382cdc33e904d6a66b8496c700b37b325d6b86ed` | mock agent as reference implementation (§8) |
| `SAFETY-AND-EXECUTION-RULES.md` | `4599cb0fa69feaa2c8cf01aedd440844dd9af6b6ab617c625d2e94eb06158f3a` | no generic kernel RPC, registered primitives only, fail-closed cleanup, evidence rules |
| `ARCHITECTURE.md` | `a91782121d6b0ef2dbd7779d664305e15eb75639369f084d6ef51ea72201c2d4` | host/target split |
| `CURRENT-STATE.json` | `ded1e07a17cc1aad0ccf71c93b84461cea7cdc2fc27bb9eb223807f2267d8e05` | version/status context |
| `core/rpc/registry.py` | `788ef091bcf9e3f2664a7956941ebaaa575560345cf002592e8d7faacad5cc7c` | the v1 primitive list |
| `core/models/capability.py` | `2d999bc7d515fe0d2969b7ca7d20a076849efeea34a14d21fe9c047340b1708c` | capability/provider rules for W3/W4/W7 |
| `mock/agent.py` | `d2f34efc3aedac8437519d49a50436416507cfbba94295604aac49b1117fa360` | normative mock semantics (W2/W6 reference) |
| `profiles/fw1352/README.md`, `profiles/fw900/README.md` | `ff55d153…`, `acd3707d…` | profile placeholders / evidence-only rule |

Truncated hashes above are abbreviated only where the full value is redundant
in-context; the cited spec and safety sources are given in full.

## 10. Definition of done for P4 (at plan level)

P4 is done when: a reviewed SDK/toolchain contract exists; a native skeleton
passes handshake parity offline; the primitive surface is frozen with provider
interfaces and a live capability-gate process; the profile binding path refuses
non-evidence values; the differential harness shows mock/native parity on the
agreed bar; the native provider is wired with explicit authority rules; and the
offline acceptance checklist is reviewed — **with no kernel code, no payload
deployment and no live PS4 interaction having occurred in P4**.
