# P4/W1 draft — payload SDK & native artifact contract: options and trade-offs

Status: **pre-review draft** — input for the W0 review and the W1 work package.
Written 2026-10-05 against `P4-NATIVE-PS4RFD-PLAN.md` (§4, W1). **No decision is taken here.**
No payload code, no kernel code, no console interaction, nothing executed.

On W0 review **PASS** this draft is promoted into the two W1 deliverables named in the
plan: `docs/PAYLOAD-SDK-CONTRACT.md` (artifact contract) and `docs/P4-W1-TOOLCHAIN.md`
(options, trade-offs, decision + rationale).

## 1. Normative frame (already fixed — not part of the option space)

| Rule | Source (sha256 of file) |
|---|---|
| "Planung NACH Adaptern; **PS4-Payload-SDK; ET_DYN ELF**; Provider-Interfaces; nur neue native Primitive bei fehlender Capability (v0.1 §70)" | `docs/spec-history/Pasted_text(20261005-115353).txt` l. 204 (`903547569942c6172a297b2d4ceaa50488ac24543513b9185d68805468098532`) |
| "Neue Research-Idee = neues Experiment, nicht neuer Payload." | same file, l. 17 |
| "Kernel Code / Payloads: nur mit expliziter neuer Freigabe." | same file, l. 167 |
| Current status: "BLOCKED: Echter ps4rfd (P4), Kernel-Code, Payloads" | same file, l. 449 |
| ps4rfd exposes only registered primitives; no generic `call(address, args)`, no RVA literals in code (profiles only) | `SAFETY-AND-EXECUTION-RULES.md` (`4599cb0f…`), plan §3 |
| "BinLoader port 9090 must never be probed before payload delivery" | `SAFETY-AND-EXECUTION-RULES.md` l. 13 |
| Agent-side semantics: single attempt per RPC, no implicit chaining, hang ⇒ console dirty, no auto-retry | plan §3; `core/rpc/hang.py` (`7e108687…`) |

The *requirement* (a native, primitive-only agent, delivered as an ET_DYN ELF, built with
a "PS4-Payload-SDK") is fixed. **Which** SDK, and **what exactly** "ET_DYN ELF" means as a
delivered artifact, are the open W1 questions.

## 2. Requirement inventory for the native artifact

These are the things any candidate must satisfy. They are derived from the frozen host
core, not from preference.

**R1 — RPC transport & handshake (byte-exact).** The agent must implement the agent half of
`core/rpc/handshake.py` (`497a77a9…`): agent sends HELLO → host HELLO_ACK → agent AUTH →
host AUTH_ACK; then AEAD frames in both directions. The TCP connect/accept direction is
**semantically free** (roles in the spec are independent of it) — but the direction is a
deployment decision with operational consequences (§3, axis "transport direction").

**R2 — Crypto stack (byte-exact).** Required primitives, all SHA-256 based except the AEAD:

* SHA-256 (transcript hash, HKDF, HMAC).
* HMAC-SHA256 (AUTH proof, both roles).
* HKDF-SHA256 extract+expand, salt = agent_nonce ‖ host_nonce (16+16 B), info strings
  `ps4rf/handshake/v1`, `ps4rf/aead/agent-to-host/v1`, `ps4rf/aead/host-to-agent/v1`,
  `ps4rf/proof/<role>/v1`, `ps4rf/nonce-prefix/<direction>/v1`.
* AEAD **ChaCha20-Poly1305** (default suite `AEAD_CHACHA20_POLY1305`), 16-byte tag,
  nonce = 4-byte HKDF prefix ‖ 8-byte big-endian sequence; `AES_256_GCM` is a defined
  alternative suite in the same module.
* No asymmetric crypto anywhere in the handshake: the shared secret is a 32-byte
  pre-shared key. The native crypto surface is therefore **symmetric-only** and small.

**R3 — Canonical serialization (byte-exact).** All handshake envelopes and every AAD are
produced by `core/canonical.py` (`e35983f1…`) = **JCS / RFC 8785** (`rfc8785>=0.1.4`,
pinned in `pyproject.toml` and present in the frozen venv). The native side must reproduce
JCS byte-for-byte (sorted keys per RFC 8785, minimal escaping, ES6 number formatting) for
the message shapes the protocol actually uses.
Two observed consequences to pin in the contract:

* `validate_safe_numbers` rejects integers outside ±(2^53−1) and non-finite floats. Because
  `build_aad` embeds `sequence` as a JSON integer, the **encodable** sequence ceiling is
  2^53−1, even though `LAST_SEQ` in the same module is 2^64−2. Both numbers should be
  reconciled in the contract (or the difference documented) rather than silently carried.
* Address-like values travel as canonical u64 strings (`0x` + 16 lowercase hex), never as
  raw JSON numbers — the agent must apply the same representation rule on every path.

**R4 — Framing & limits.** Handshake frames: 4-byte big-endian length + JSON, ≤ 65536 B.
AEAD frames: ≤ 1 MiB plaintext+tag by default, strict send/receive sequence counters,
exact-match receive sequence (replay ⇒ refuse), `SequenceExhausted` past the ceiling.

**R5 — Primitive dispatcher only.** Requests map 1:1 onto the frozen registry
(`core/rpc/registry.py` `788ef091…`). The agent contains no experiment logic, no addresses,
no profiles; profile-resolved values arrive per request (plan §3.1/3.2).

**R6 — Fail-closed session behaviour.** Transport loss/timeout ⇒ no retry, session state
`UNCERTAIN`/recovery-required, in-flight requests resolved as the host core defines
(`core/rpc/pool.py` `7c148d3c…`, `mock/agent.py` `d2f34efc…` is the normative mock).

**R7 — Evidence & observability.** Startup stage and raw init/connect returns reported
in-band (prior-campaign practice, §10 source 4). Useful for W2 parity and for P5; not
required by the frozen core itself.

**R8 — Build reproducibility.** Hash-pinned, double-buildable artifact; toolchain inputs
(compiler, flags, SDK archive members, CRT, linker script) recorded as part of the
artifact identity (P4 discipline, plan §6).

## 3. Option space — artifact source & toolchain

### Option A — libPS4 ("PS4-Payload-SDK" from the prior PS4 campaign)

The SDK behind every payload that has already run on the user's PS4 in this research series
(userland, and userland+kpayload dual-mode). Build regime is documented and proven:
compile `-Os -std=c11 -fno-builtin -mcmodel=small -march=btver2 -m64 -fpie -fPIC -Wall
-mno-red-zone` with the SDK include dir first; link `-T <sdk>/linker.x -nostartfiles
-nostdlib` with `libPS4.a`; entry symbol `_main`; flat delivery artifact via
`objcopy -O binary`. Networking via `sceNet*` after `initKernel(); initLibc();
initNetwork();`.

* For: strongest empirical base (live-proven on this exact target path); known pitfalls are
  already catalogued (BSS function-pointer/resolver traps, 0-relocation gate, single-TU
  discipline, ASCII-only sources, `.data` section forcing); kernel-side path (kexec/kpayload)
  exists if a later phase ever needs it under separate approval.
* Against / open: SDK provenance and provenance record for *this* freeze (where the copy
  lives, exact archive hash); license; the SDK is large and pulls extra archive members on
  some call paths (must be gated by link-map review); not obviously an "ET_DYN ELF"
  toolchain by intent — it produces flat loadable images for BinLoader, with ELF as an
  intermediate.
* Prior-campaign build paths on the LAN worker are recorded in `ORBISPROBE-INVENTORY.md`
  (l. 256); the SDK itself is **not** present in this repo or on this host — availability
  must be verified (worker reachable, archive hashed) before it can be a candidate.

### Option B — Scene-Collective `ps4-payload-sdk`

A public payload SDK already touched in a prior project of this series (its firmware helper
`get_firmware()` returns decimal-style integers such as `505`/`702`/`900`; FW 9.00 must be
compared as decimal `900`, not `0x900`).

* For: public, payload-oriented, C; firmware-helper surface included; prior project
  experience exists.
* Against / open: license and maintenance status to verify offline; overlap with Option A
  is large (both derive from the same lineage of PS4 userland SDKs) — evaluating both fully
  may be duplicate work; no live evidence on this target **in this repo**.

### Option C — OpenOrbis PS4 toolchain

Open-source toolchain + CRT used in this series for full Orbis **applications** (the
no-fork research-shell/Dropbear work) and, in at least one bridge payload, for
reproducible payload builds.

* For: open source, reproducible, active; standard ELF/SELF outputs; good for
  "ET_DYN ELF by intent".
* Against / open: it targets packaged applications; a ps4rfd delivered via BinLoader is a
  *payload*, not a package — the delivery path (flat BIN vs ELF-over-HTTP) and its loader
  behaviour must be re-verified for this toolchain's output; larger artifact surface
  (crt/dynamic-loading expectations) needs an explicit "no relocations" audit; heavier
  toolchain to pin.

### Option D — Minimal in-repo freestanding skeleton (no external SDK)

Own CRT, own syscall wrappers (plain `syscall` instructions), own crypto (see §6), flat or
ELF link with a pinned linker script.

* For: smallest possible trust surface and dependency tree; fully hash-pinnable inside the
  repo; no license questions; every byte auditable; forces the JCS/crypto work that is
  required anyway.
* Against / open: the loader realities (segment permissions, BSS, entry convention) have to
  be re-established from scratch from prior-campaign findings; no `sceNet*` module
  resolution — raw `socket/connect` syscalls must be used and verified on target; highest
  build risk; duplicates work the SDKs already did.

### Option E — Composition (SDK for startup/network + in-repo for crypto/JCS/dispatcher)

Any of A–C for startup, module resolution and sockets; the protocol-critical parts
(JCS encoder, crypto, framing, dispatcher) in-repo as small auditable C units.

* For: matches the actual risk distribution — the protocol core must be **byte-exact**
  independent of the SDK, while startup/networking is exactly what live-proven SDKs do
  well. Keeps the crypto/JCS surface under this repo's own gates.
* Against / open: two dependency classes to hash-pin; requires the "single-TU / extra
  archive member" discipline to be re-checked per SDK.

## 4. Cross-cutting evaluation axes

Every candidate is scored on these in the eventual W1 decision record:

* **Delivery-form fit** — flat BIN vs ELF-over-HTTP; loader applies **no** ELF dynamic
  relocations on either route (`readelf -rW` must show zero entries) — see §5.
* **Reproducibility** — double build byte-identical (ELF and delivered form), warning-free,
  toolchain inputs hash-pinned; `.map` compared normalized.
* **Fault tolerance of the image** — no host libc, no uninitialised SDK function pointers
  (`.bss` + resolver discipline), all post-load globals in `.data`/explicit sections.
* **Crypto/JCS ownership** — can the protocol core be kept as in-repo, hash-pinned C
  regardless of SDK? (see §6)
* **Evidence bindability** — can every build input (archive members, headers, CRT, linker
  script) be hashed into the artifact record?
* **Maintenance & license** — public/private, license terms, mirrorability offline.
* **Later kernel path (not in P4 scope)** — if plan Q3 ever admits kernel primitives, does
  the candidate keep the kexec/kpayload path available under separate approval?

## 5. The "ET_DYN ELF" question (plan R3)

Facts to carry (prior-campaign, repeatedly measured):

* The BinLoader accepts both a raw flat image (TCP route) and an ELF (HTTP route) — but it
  applies **no dynamic relocations** on either route; segments load, `.rela.dyn` is ignored
  and the request still returns success. A statically initialised function-pointer structure
  produces `R_X86_64_RELATIVE` relocs and dies silently on first indirect call.
* Consequence for the contract: "ET_DYN ELF" can be satisfied in at least three readings,
  and the contract must name **one**:

  1. **ELF as build artifact, flat BIN as delivery artifact** (`objcopy -O binary` step,
     both hashed; matches every live-proven payload so far).
  2. **ELF as delivery artifact** via the HTTP route (needs its own delivery/evidence path
     and the same zero-relocation gate).
  3. **ET_DYN as ELF *type* requirement** on the build artifact only (file type + zero
     relocations), independent of delivery.

This reading must be chosen by the owner (open question Q1) — it directly shapes W2's
packaging step and P5's delivery runbook.

## 6. Crypto stack — implementation options (critical path)

The handshake requires SHA-256, HMAC-SHA256, HKDF-SHA256 and ChaCha20-Poly1305 in a
freestanding console binary. Options:

* **C1 — In-repo minimal implementation** (own SHA-256/HMAC/HKDF + ChaCha20-Poly1305, or
  an in-repo vendored single-file implementation): small, hash-pinnable, testable offline
  per RFC vectors, no license entanglement for own code.
* **C2 — Vendored third-party tiny crypto library** (e.g. a single-file public-domain
  ChaCha20-Poly1305/SHA-2 implementation): faster to get right, but adds a license and
  provenance record and must be hash-pinned like any other build input.
* **C3 — Console-native crypto services** (if the platform exposes usable symmetric crypto
  to a payload): unproven for these primitives on FW13.52/9.00; would need live verification
  (P5). Not a P4-decision candidate; keep as noted possibility only.

Regardless of choice: the JCS encoder is in-repo either way; and the crypto core must be
verified against **normative test vectors** offline (RFC 8439 ChaCha20-Poly1305, RFC 5869
HKDF, RFC 4231 HMAC, RFC 8785 JCS test suite) plus a cross-language round-trip
(C encoder → existing Python decoder and vice versa), before any parity claim.

## 7. Offline verification plan (no hardware, no code yet)

**Status 2026-10-05:** item 1 below now has a concrete, decision-free artifact:
the catalog `tests/fixtures/crypto/vectors-v1.json` plus the contract
`docs/P4-W1-TESTVECTORS-SPEC.md` (RFC anchors + protocol-derived vectors + 21
boundary cases, self-verifying; findings F1/F2 recorded there). items 3–4 remain
open until the SDK/image decisions land.

What can be proven without a console, and therefore belongs to W1/W2 exit criteria:

1. **Crypto/JCS conformance**: RFC vectors + host-side round-trips against the frozen
   Python implementation.
2. **Transcript parity**: reproduce the exact HELLO/AUTH byte sequences of the mock
   handshake from pinned vectors (W2).
3. **Image gates**: zero relocations, no undefined host-libc symbols, no forbidden
   instruction/import classes, section/BSS discipline, deterministic rebuild.
4. **No-RVA gate**: static scan proves no firmware addresses/RVAs in agent code (profiles
   only).
5. **Artifact hashing**: SDK/CRT/headers/linker script recorded as hash manifest, artifact
   hash reproducible from a clean tree.

## 8. Draft trade-off matrix (orientation only — no ranking decision)

| Axis | A libPS4 | B ps4-payload-sdk | C OpenOrbis | D minimal in-repo |
|---|---|---|---|---|
| Live evidence on this target | strongest (prior campaign) | none in-repo | app-level only | none |
| ET_DYN/ELF by intent | flat-first | payload-first | yes | self-defined |
| Dependency surface to hash-pin | archive + headers | archive + headers | toolchain + crt | none |
| Crypto/JCS ownership | in-repo anyway (protocol core) | in-repo anyway | in-repo anyway | in-repo anyway |
| License openness | to verify | public | open | n/a |
| Build risk | low (proven regime) | medium | medium-high (payload form) | high |
| Auditability inside repo | medium | medium | medium | highest |
| Availability now | on worker (verify) | public (verify) | public (verify) | local |

## 9. Open questions to the owner (W1-specific)

* **Q1** Which reading of "ET_DYN ELF" is binding (§5)?
* **Q2** Which candidate is evaluated first for the contract (A/B/C/D/E)?
* **Q3** Crypto: in-repo minimal implementation (C1) preferred over vendoring a
  third-party blob (C2)?
* **Q4** May the W1/W2 build inputs include an SDK copy staged **outside** the repo
  (hash-pinned, not vendored), or must the repo remain the only input source?
* **Q5** Transport direction for the agent (connect-out to the operator host, as in every
  live-proven payload, vs. listening daemon) — confirm connect-out as the working
  assumption, with the listen direction deferred to P5?
* **Q6** (cross-ref plan Q3) Is P4's acceptance target userland-only, or in scope for
  kernel primitives — this changes which candidate's kernel path must stay available.

## 10. Sources

Repo-normative (sha256 in §1/§2 where cited): `P4-NATIVE-PS4RFD-PLAN.md`,
`docs/spec-history/Pasted_text(20261005-115353).txt` (`9035475699…`),
`core/rpc/handshake.py` (`497a77a9…`), `core/canonical.py` (`e35983f1…`),
`core/rpc/pool.py` (`7c148d3c…`), `core/rpc/hang.py` (`7e108687…`),
`core/rpc/registry.py` (`788ef091…`), `mock/agent.py` (`d2f34efc…`),
`SAFETY-AND-EXECUTION-RULES.md` (`4599cb0f…`), `pyproject.toml`, `ORBISPROBE-INVENTORY.md`.

Prior-campaign evidence (Hermes skill references, **not** repo-normative; to be re-verified
against real artifacts during W1/W2): libPS4 build regime and BinLoader behaviour
(no-relocation gate, flat BIN via `objcopy`, init chain, `.bss`/resolver traps, connect-out
payload direction); Scene-Collective `ps4-payload-sdk` firmware helper (decimal `900`);
OpenOrbis use for the research-shell builds.

No firmware addresses, no RVAs, no payload bytes appear in this document by design.
