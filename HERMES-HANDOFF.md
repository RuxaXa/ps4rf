# HERMES HANDOFF — PS4RF Core Freeze Candidate

## W11.2 handoff (fixed privileged boot identity read)

* the payload reads exactly one fixed region: `kbase + 0x224C6C8`, 16 bytes, and nothing else. The
  callback stops before any read if the LSTAR shape is wrong or the cross check against the SDK's
  own base does not match; the event then reports zero bytes and `UNMEASURED` values, never a guess.
* on the host, `tools/hostctl/bootpriv.py` decides: contract violations mean "no verdict at all",
  failed reads mean "valid fail-closed outcome, no boot id", and only a complete, validated read
  yields the canonical `ps4rf.boot-binding.v1` object, its digest and the public `BOOT-…` id. The
  W10 capture instant is comparison evidence only.
* the manifest gate (`gate_bootread`, profile `w11.2`) demands the kernel ABI explicitly: the args
  struct must carry `void *syscall_handler;` first and `info` second, because the console wraps the
  syscall-11 argument and hands the payload a pointer to the wrapper. The offline harness found
  this defect first (all eight cases failed with the misread signature); after the fix the build is
  `PASS` with `problems: []`, reproducible twice, and the harness is 8/8.
* the v2 live run landed: the fixed privileged read produced a complete 16 byte `timeval`
  (`1791179388.549567`) from the one frozen region, the host formed the canonical boot object,
  digest `f0329415c5d8517d…` and the public id `BOOT-f0329415c5d8517d`, W5 accepted the binding for
  the real profile hash, and the W4/W7 gate moved to `PROFILE_MATCH`. `BOOT_ID_UNVERIFIED` is
  resolved by evidence; the run's verdict is `FAIL` only on the port-3232 health probe (log stream
  silent on an idle console).
* review outcome: **W11.2 approved with devisation W11.2-D1** (`PASSIVE_LOG_STREAM_NO_BANNER`,
  `ACCEPTED_PROBE_DESIGN_ISSUE`). The health check is now `health:port-3232-connect` (bounded TCP
  connect) with `log_activity_observed` reported outside the verdict; FTP/ICMP unchanged, 9090 still
  excluded. Semantics accepted: `IN_BOOT_STABILITY_EMPIRICALLY_PROVEN`;
  `CROSS_REBOOT_CHANGE_EMPIRICALLY_PROVEN` explicitly not claimed. No further W11.2 live execution.
* **W12 starts offline** (first bounded `kernel.read` provider promotion): registry of proven
  FW13.52 read regions, `region`/`offset`/`length` requests (never a raw VA) capped at 4096 bytes with
  checked arithmetic and region containment, the full capability gate path, a separate verification
  flow, NATIVE ceiling OBSERVED, plus offline safety gates, negative/positive matrices and the
  `W12 OFFLINE READY` gate. Nothing live until separately approved.
* **W12 offline is delivered** (`W12 OFFLINE READY`, commit `73e2c68`): one bounded read from an
  approved region by name (never by address), the full capability path with W4/W5/W7 parity, a
  separate verification flow whose bootstrap needs no already-PROVEN read, and a drift-checked
  generated region table. Everything verified in the integration pass: 706 passed / 1 skipped,
  harness 17/17, build reproducible, two mutants stopped. Nothing live.
* nothing privileged beyond this one read is available: `kernel.read`/`kernel.dump`/GPUVM/KeyMgr/
  CCP/SAMU stay closed, and the remaining reason for the first bounded `kernel.read` promotion is
  still `OPERATION_DEFERRED` / `LOCATOR_MISSING`.

---

**W11.1A (2026-10-06): the W11.1 live gap was a host side evidence bug — the live runner dropped the
captured `boot.binding` event, the reader had recorded it.** The `except` branch of both live modes
recorded a failed check and returned without copying the session's captured event, while the offline
branch copied it: the paths had diverged. Fixed with one shared `capture_events()` /
`live_agent_stop_outcome()` and one central frame router in `HostSession`; proven by an offline
replay of the live frame order (real agent, loopback, live stand-in `BOOT_READ_FAILED`): the pre-fix
branch loses the event (`LEGACY_REPLICA_EVENT_LOST`, `events_seen: 1`), the current branch keeps it
(`PASS`, `verified: true`, `no_boot_id: true`). Regressions in `tests/test_event_capture.py`; the
W11.1 payload is unchanged (`2b3d0037…`, no rebuild, no upload, port 9090 untouched). The *live*
classification of the failed `KERN_BOOTTIME` read is still unknown — the replay's classes come from
the host stand-in, not from the console. `BOOT_ID_UNVERIFIED` and `kernel.read`
(`OPERATION_DEFERRED`) are unchanged.

**W11.1 (2026-10-06): the W11 live run failed closed (`BOOT_READ_FAILED`) and is accepted as a valid
negative finding; W11.1 exists to classify *why*, still userland-only.** The userland collector now
runs both access paths with an instrumented size query and a bounded read (max 64 bytes) and reports
a machine-readable classification of each path; the host re-derives every class from the measured
numbers, re-computes the raw digest and refuses any binding that is not a complete 16 byte
`struct timeval` (partial/conflicting/drifting -> no boot id, never a guessed value). `kernel.read`
stays `OPERATION_DEFERRED` (`LOCATOR_MISSING`). Live run pending the single BinLoader rearm.

**W11 offline complete (2026-10-06): live userland boot binding prepared — `BOOT_ID_UNVERIFIED` is
resolved by the offline proof and awaits the single live run.** Read-only userland collector
(`KERN_BOOTTIME` twice, bounded pause) in the target agent behind `PS4RF_TARGET_BOOTID=1`, with no
`kexec`/`rdmsr`/kernel address anywhere in that payload (artefact gate: `rdmsr 0`, `kexec refs 0`,
no privileged entry). One canonical algorithm `ps4rf.boot-binding.v1`; the W10 draft string is
withdrawn and the capture id recomputed (`BOOT-19d2c790b0769502`). Offline end-to-end against the
real host build: stable source binds `4a6f575c…`, drifting source stops with
`BOOT_SOURCE_NOT_STABLE`, absent source stops with `BOOT_READ_FAILED`. Gate: W5 goes
`BOOT_BINDING_MISMATCH` → `PROFILE_MATCH`; `kernel.read` stays `OPERATION_DEFERRED` and the
`LOCATOR_MISSING` triple (`kernel.read`, fields `addr`/`size`, `locator_ref: null`) is reported as
the remaining blocker. Cross-reboot remains `SUPPORTED_BY_WRITE_PATH_ANALYSIS`. Live payload built
and hashed, **port 9090 untouched** — waiting for "BinLoader rearmed" before exactly one upload.
Note (drift, stated by hand): the shared platform/agent sources changed for W11, so the W9 profile
is no longer rebuildable bit-identically (rebuilt BIN `eefbb3cb…` vs frozen live BIN `f70fd896…`);
the frozen packs stay untouched as evidence and a W9 re-run would need re-review.

**W10 complete (offline, 2026-10-05): real FW13.52 profile promoted, boot identity resolved.**
The promoted profile `profiles/fw1352/profile-13.52.json` (profile_sha256 `4a6f575c…`) is built
only from the accepted W9 live evidence plus the pinned FW13.52 research: 7 STRICT_FINGERPRINT
windows (one relocated: image value + slide) with `aperture_global` permanently STRUCTURAL_ONLY,
no runtime address persisted, fixture untouched, identity from kernel evidence (never
`kern.sdk_version`). Independent validator PASS (mutation-proven). Boot identity: primary source
`sysctl:kern.boottime` (userland path, cross-checked by the same `struct timeval` as a fixed
read-only kernel variable), KASLR slide secondary only; contract and reboot semantics tested
offline, **no live measurement** - `BOOT_ID_UNVERIFIED` stays the one hard blocker. Gate report:
W5 `PROFILE_MATCH` becomes reachable for the real profile (demonstrated with a labelled simulated
binding), gated operations refuse `LOCATOR_MISSING`, W4/W7 stay `DEFERRED`/`OPERATION_DEFERRED`
with no provider entry, `kernel.read` untouched. No upload, port 9090 untouched.

**W9 complete: offline + the executed live run (2026-10-05).** Live result PASS with exactly
one upload: callback executed once (`kexec_rc 0`, 8 read-only byte reads), LSTAR
`0xffffffff998f41c0`, kbase candidate `0xffffffff998f4000` equal to the userland cross check,
strict fingerprints **7/7** with no mismatch, one structural observation (aperture
`0xffffe7b0e4800000`) that proves the STRUCTURAL_ONLY policy right, session ended with a
captured BYE (`CLIENT_CLOSE`, cleanup COMPLETE, resources []) and green health. Decision
recorded without promotion: PROFILE_MATCH_CANDIDATE only, `BOOT_ID_UNVERIFIED` /
`PROFILE_UNBOUND` unchanged. Live pack `20261005T202857Z_ps4rf_p4w9-live` (`VERIFY_OK`), offline
pack after the window-policy correction `20261005T202341Z_ps4rf_p4w9-offline-r2`.

**Original W9 offline notes (still accurate):** One fixed read-only kernel
attestation callback, triggered by the agent itself (no host address/flag/trigger), reported in
one sealed EVENT frame and verified host-side against the pinned FW13.52 evidence. Payload BIN
`f70fd8965a6e554571cae7255a416780b06c173734c836507e3c6581f3466bc5` (build id `20e188612db876ece995207d3778cb2d`, after the window-policy correction),
gates PASS, reproducible twice, zero relocations. Offline: five fail-closed callback scenarios
(clean 104 byte reads / corrupted window stops / corrupted identity reads 16 bytes / bad LSTAR
reads nothing / missing marker reads nothing) plus a fail-closed host E2E (EVENT FAILED + BYE
ATTESTATION_FAILED). No core change, no new capability; `PROFILE_UNBOUND` and
`BOOT_ID_UNVERIFIED` stay until measured evidence supports more. Evidence pack
`20261005T201139Z_ps4rf_p4w9-offline`. Next action after an explicit rearm: exactly one
BinLoader upload of this payload (port 9090 is never probed) and the nine-step W9 live sequence
in `docs/P4-W9-ATTESTATION.md`.


**W8 REVIEW: APPROVED WITH DOCUMENTED DEVIATION (2026-10-05)** — deviation ``W8-D1``
("LIVE_BYE_NOT_CAPTURED_DUE_TO_RELAY_FULL_CLOSE") carries disposition **ACCEPTED**: exactly one
upload, real PS4 userland agent, authenticated handshake + READY, 14/14 requests, gate lifecycle
clean, held_resources empty, cleanup COMPLETE, kernel.read OPERATION_DEFERRED with
provider_entry=false, relay log documents the session end, PS4 healthy, missing live BYE
explained by the relay full close and the fix proven offline. Live pack unchanged
(``20261005T195043Z_ps4rf_p4w8-live``), relay fix pack separate
(``20261005T195347Z_ps4rf_p4w8-relay-fix``). No second live upload for the BYE. **W9 underway:**
read-only privileged attestation bring-up, offline first, stop at ``W9 LIVE READY``.


**P4 W8 OFFLINE COMPLETE (2026-10-05)** — first controlled live step prepared, **no console
contact yet**. Target payload build (`native/target/build_ps4.sh`, reproducible twice, 0
relocations, no privileged symbol/code, loader port absent, one endpoint) plus the host
controller (`tools/hostctl/`, `ps4rfctl`) whose live mode refuses to upload without an
explicit `--rearm-confirmed`. The native dispatch path mirrors W7: exactly one provider entry
site, the 15 W8-scope stub operations wired, everything else `OPERATION_DEFERRED` with
`provider_entry=false` stated in the wire detail. Wire parity re-verified with target codegen
flags. Evidence, runbook and the `W8 LIVE READY` report are in the wave evidence pack; the
live sequence itself (one payload upload, 14 requests, health checks, STOP) waits for the
owner's BinLoader rearm confirmation.


## Status

**FREEZE GATE EXECUTED** — the tag `PS4RF-CORE-1.0-MOCK-READY` was created by the
freeze gate runner and sits at `1536e35`; the tag is never moved.
**TOOL LAYER EXTENDED (2026-10-05)** — recon and privilege-escalation knowledge
adapters added; current status matrix in `TOOLS.md`.
**P4 W0 CLOSED (2026-10-05)** — the owner approved all 19 decisions
(`docs/P4-W0-DECISIONS.md`); the two missing sources are delivered: §70 text
(`docs/spec-history/70-capability-gated-native-primitive-additions.md`) and the
frame type byte table (wire mapping v1, `docs/P4-WIRE-SPEC-v1.md`).
**CORE/WIRE REVISION R1** — minimal, decided consequences of D8/D9/D12:
effective sequence ceiling enforced, central `InvalidTag` mapping, shared frame
table in `core/rpc/wire.py`; core file drift is documented in `FREEZE-DRIFT.md`
and read by the gate (`tests/test_freeze_drift.py`). No silent manifest update,
no re-freeze without the next planned revision.
**P4 W2 ACCEPTED BY THE OWNER (2026-10-05)** — native userland skeleton
`native/` (in-repo C99 protocol core: SHA-256/HMAC/HKDF, ChaCha20-Poly1305,
RFC 8785 JCS, handshake, directional AEAD channels, wire framing v1; agent
`ps4rfd` with connect-out, `session.ping`/`session.bye` request loop, clean
disconnect, fail-closed fatal path) plus the offline parity harness. The harness
replays both golden catalogs and the generated boundary/negative catalog
`tests/fixtures/parity/w2-negative-v1.json` byte-for-byte: **154 PASS / 0 FAIL /
4 documented structural exemptions**. Build artifacts `native/build/ps4rfd.elf`
(`ET_DYN`) + `ps4rfd.bin`, reproducible byte-identically, toolchain manifest
validated (no SDK used, W0/D1 "D first"). No kernel code, no core change. Next
steps stay gated: W3/W4 or live PS4 only after the W2 finding is reviewed.
**W3 COMPLETE (2026-10-05, pending owner review)** — primitive interface freeze v1:
`docs/P4-PRIMITIVE-INTERFACES.md` + `tools/primitive_iface/{schema,validate,stub}.py`;
all 35 registry operations mapped, 16 implemented in the host-side stub, gated ones
refused with `OPERATION_DEFERRED`, findings F7-F10 recorded without touching the core.
Next planned packages: W5 (profile binding data — not started), W6 (mock-vs-native
differential harness — not started), W7 (provider wiring, resolves F7 — not started);
offline except the on-site profiles.
**W4 COMPLETE (2026-10-05, pending owner review)** — capability gate process (§70):
`tools/primitive_iface/gate.py` + `docs/P4-CAPABILITY-GATE.md` +
`tests/test_capability_gate.py`; 14 deferred-privilege requirements + 1 host-chain,
10 reasons with owners, decisions never executable, wire stays `OPERATION_DEFERRED`,
mock evidence excluded for privileged capabilities (F11, recorded). W4 decides only —
it implements nothing.
**W6 COMPLETE (2026-10-05, pending owner review)** — differential harness (offline):
`tools/differential/{normalize,schema,inventory,compare,candidates,cli}.py`,
`docs/P4-DIFFERENTIAL-HARNESS.md`, fixtures under `tests/fixtures/differential/`,
`tests/test_differential_harness.py`. Hash-bound inputs, deterministic normalized
output (`output_sha256` over the core, `--timestamp` pins the rest), fail-closed on hash
mismatch / schema mismatch / unknown normalization version / architecture conflict /
malformed locator / incomplete provenance, `ARTIFACT_MISSING` for absent firmware images
instead of synthesized content. Candidates stay OBSERVATION with impact.w4 NONE; a diff
never removes a W4 reason, never allows a provider, never raises assurance and never
removes `NOT_WIRED`.
**W5 COMPLETE (2026-10-05, pending owner review)** — profile binding (offline):
`tools/profiles/{schema,binding,loader,w4_adapter}.py`, `schemas/profile.schema.json`,
`docs/P4-PROFILE-BINDING.md`, fixtures under `tests/fixtures/profiles/`,
`tests/test_profile_binding.py`. Persistent target facts + canonical hash, boot
binding that expires with the boot, runtime binding as `locator + runtime base`,
read-only bounded probe contract, explicit profile policy for all 14 gated operations,
value domains for all 16 profile fields (unresolved ones fail closed). W5 supplies
only the profile part of the W4 decision: it never makes an operation executable,
never removes `NOT_WIRED`, never legitimises a mock provider, and no real firmware
address is invented - on-site values stay `UNRESOLVED` (fixtures marked as such).
**W7 COMPLETE (2026-10-05, pending owner review)** — provider wiring (offline): the W3
interface, the W4 gate, the W5 binding and the W6 findings are joined into one dispatch
path (`tools/dispatch/{matrix,providers,resources,evidence,dispatch,cli}.py`,
`docs/P4-PROVIDER-WIRING.md`, `tests/test_provider_wiring.py`, 53 tests). One route per
registered operation (35/35, parity-checked against registry/W3/W4/W5, no implicit
fallback), one productive provider entry site, evidence for every attempt incl. the chain
step that refused it, central recovery check before entry, per-request resource view over
the central `ResourceManager`, `max_inflight` enforced. F7 is fixed by the minimal,
documented core patch (`ProviderType.NATIVE` + one conservative authority rule,
`max_assurance = OBSERVED`), gated as revision `R2 (F7)` in `FREEZE-DRIFT.md`; F8/F9/F10
stay unchanged. All 14 privileged operations and the host-chain operation are registered
but `DEFERRED`: `provider_entry = false`, wire answer `OPERATION_DEFERRED`, even with a
satisfied gate. No live PS4 access, no payload, no kernel code, no provider implementation.
Next step only on explicit release: the first controlled target integration.

The tag may only ever be created by the freeze gate runner, never by hand.

## First assignment

1. Install this repository in the real Hermes development environment.
2. Run `python tools/preflight.py`.
3. Run `python -m pytest -q`.
4. Run `python tools/freeze/run_gate_suite.py`.
5. If anything fails, fix only the concrete failing behavior. Do not redesign the core and do not add unrelated features.
6. Archive `FREEZE-REPORT.json` after a successful run.
7. Only after the tag exists, start the OrbisProbe phase.

## OrbisProbe phase

Do not invent an OrbisProbe inventory. Use the real repository or archive.

1. `python tools/inventory/extract_orbisprobe_inventory.py <repo>`
2. Build `ORBISPROBE-INVENTORY.md` from actual source findings.
3. Build `ORBISPROBE-PS4RF-MAPPING.md` with `REUSE`, `ADAPT`, `REPLACE`, `KEEP_EXTERNAL` decisions.
4. PS4RF remains source of truth for profiles, capabilities, experiments, runs, evidence and resources.
5. OrbisProbe remains responsible for discovery, reasoning, ranking, hypotheses, assessment, experiment proposals and classification.
6. OrbisProbe must not independently perform payload delivery or hardware execution once integrated.

## After OrbisProbe

Canonical integration order (updated 2026-10-05):

1. GTFOBins knowledge adapter — **done** (`tools/knowledge/gtfobins/`; candidates
   only, no recipes stored, nothing executed).
2. PEASS-ng / linPEAS adapter — **done** (`tools/recon/peass/`; target-OS aware,
   PS4/OrbisOS not scanned generically).
3. unix-privesc recon layer — **done** (`tools/recon/unix_privesc/`; Linux vs.
   FreeBSD/OrbisOS classified separately, PS4 checks stay native).
4. Metasploit adapter against mock msfrpcd — done.
5. Ghidra, Rizin, angr, AFL++ adapters — done.
6. Only then plan native `ps4rfd` and real PS4 integration — the P4 plan exists
   (`P4-NATIVE-PS4RFD-PLAN.md`); **W0 is closed** — all 19 decisions are approved
   and recorded in `docs/P4-W0-DECISIONS.md`, the missing sources (§70 text,
   frame type byte table) are delivered, and the decided core consequences are
   implemented as Core/Wire Revision R1.

Still PLANNED, no source yet: pspy, Linux Smart Enumeration, unix-privesc-check,
Nuclei, ffuf/feroxbuster, nmap/masscan, SecLists (see `TOOLS.md`).

## References included in this package

- `references/samurf-0.1.0.zip`
- `references/ps4_fw1352_ccp_harness.zip`
- `references/ps4-fw900-cross-processor-handoff-20260907.zip`
- `docs/spec-history/` contains the iterative PS4RF design/freeze material used to assemble this handoff.

## Hard rules

- No capability becomes `PROVEN` without store-bound `VerificationEvidence`.
- No mutating operation in `RECOVERY_REQUIRED`.
- No silent retry after hang, panic, crash or unexpected target state.
- No generic arbitrary kernel call or arbitrary kernel write RPC.
- Firmware addresses belong in profiles, not experiment definitions.
- Uncertain cleanup makes the console dirty and requires recovery.
- No claimed PASS without a real run.
- Recon and knowledge-adapter output is never an exploit finding by itself, and no
  privilege-escalation technique is executed because of a linPEAS or GTFOBins
  match: recon → observation → candidate → verification → primitive → exploit
  candidate. PS4/OrbisOS is FreeBSD-based, so linPEAS is not a generic PS4
  scanner; PS4-specific checks stay native to PS4RF.
