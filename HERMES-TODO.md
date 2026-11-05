# HERMES TODO

## W13-C2 — WIRE-CATALOG R2: kernel.read bounded-region args (offline complete, no live upload)

- [x] `kernel.read` argument contract: `region_index` / `offset` / `length`, all required integers;
      retired names (`addr`, `address`, `va`, `kernel_va`, `ptr`, `source`, `size`) dead on the wire;
      unknown fields fail closed
- [x] operation, capability, route and all wire framing unchanged; documented as WIRE-CATALOG R2
      (`docs/P4-W13C2-WIRE-CATALOG-R2.md`), W13-C1 request-shape note marked superseded
- [x] trigger parse reads `body.arguments` only and refuses unparsable requests explicitly
      (`ARGUMENT_INVALID`) before every bound rule and before any kexec; no sentinels, no defaults;
      the refusal does not burn the one-shot
- [x] catalog regenerated (`PS4RF_ARG_ROW_COUNT 49`), schema ⇄ table parity asserted; callers on the
      triplet; host smoke fixture asserts both the triplet (deferred) and the retired pair (refused)
- [x] tests: `tests/test_w13c2_wire_arguments.py` (16) + `tests/harness/optable_args_check.c`;
      mutants 7/7 red (C2) and 7/7 build-gate (C1 re-run)
- [x] live: one upload + exactly one research read (`amd_iommu`, index 1, offset 0, length 16) —
      PASS, `checks_failed: []`, release consumed at the single provider entry, BYE clean, health
      green; artifacts produced (research evidence, dataset blob `0e5db66b…`, snapshot
      `SNAP-831b4707168282cc`, W6 input + result with OBSERVATION-only candidates, `impact.w4` NONE)
- [x] W14B (resident `ps4rfd`, review follow-up) — offline complete and reported as
      `W14 OFFLINE READY`: identity in HELLO (§14), session teardown + isolation (§2), recovery
      semantics and persistence (§4/§5/§11), dial-out backoff (§6), authenticated admin shutdown as
      wire catalogue revision R4 / core revision R3 (§15), two evidence levels (§18), 60-session
      stress (§17), per-session capability re-derivation (host side), two-session end-to-end (§11),
      console artefact reproducible + gate PASS, W12/W13 regression 327 passed, suite green.
      Evidence pack: `/home/hermes/07-evidence/20261006T_w14b-offline/`. W14 **live** stays separate:
      a live step needs its own review, approval and rearm (and the review must accept the
      `session.shutdown` live-scope delta).

## W11.2 — fixed privileged boot identity read (offline in progress, no live upload)

- [x] target module `native/target/ps4rf_bootread.{h,c}`: one fixed source (`kbase + 0x224C6C8`,
      16 bytes, compile-time constants), one callback, one `kexec`, guard set before it, kbase only
      via `rdmsr(LSTAR)` + shape gate + `LSTAR - 0x1C0` + cross check against `get_kernel_base()`
      **before** the first byte; `magic_out` = started, `guard` = completed
- [x] agent hook (`ps4rf_agent.c`, `PS4RF_TARGET_BOOTREAD`): one run on the first `session.status`,
      sealed `boot.binding.privileged` event, fail-closed BYE (`BOOT_READ_FAILED` /
      `BOOT_TIME_IMPLAUSIBLE`), never a second attempt; build flags in `build_host.sh` /
      `build_ps4.sh` (`PS4RF_TARGET_BOOTREAD=1`, profile `w11.2`, label `ps4rfd-live-w112`)
- [x] host verification `tools/hostctl/bootpriv.py`: independent re-derivation of the base relation,
      the source RVA, the read length, the raw-byte hash, the timeval decode and the refusal rules;
      contract violations leave the event untrusted, failed reads stay valid fail-closed outcomes
      with no boot id; the canonical object, digest and `BOOT-…` id are formed host side only
- [x] session contract (`boot.binding.privileged`), CLI flag `--w112-privileged-boot-read`,
      shared capture path for offline/self-test/live
- [x] offline proofs: verifier self test green, loopback end-to-end run PASS (fail closed, no boot
      id), W11.2 gate report PASS (`BOOT_BINDING_MISMATCH` -> `PROFILE_MATCH`, `kernel.read` stays
      `OPERATION_DEFERRED` / `LOCATOR_MISSING`), new pytest module green
- [x] offline harness `tests/harness/bootread_offline.c` + `tests/test_bootread_offline.py`:
      production callback with replaced leaf reads, synthetic kernel, cases A–H one child each ->
      **8/8, exit 0** (A `RUN_OK`/16 bytes/`MATCH`; B–D exact `TIMEVAL_*`; E `BOOT_TIME_IMPLAUSIBLE`;
      F `CB_LSTAR_SHAPE` with the read counter unchanged; G `CB_KBASE_MISMATCH` with zero bytes;
      H `RUN_ALREADY` with zero deltas)
- [x] the harness found a **real defect**: the console's syscall-11 wrapper puts the caller's block
      in its *second* field, so `struct ps4rf_bootread_args` must carry `void *syscall_handler;`
      first (as W9 does). Without it the callback would have read the kernel's syscall handler as
      its block and written `cb_status` into kernel memory. Fixed; the manifest gate independently
      demands the same ABI (`args_fields: [syscall_handler, info]`)
- [x] `gate_bootread()` in `build_manifest.py` (profile `w11.2`) + `--repro-elf`: one payload-owned
      `kexec`, one callback, one fixed read region (`0x224c6c8` twice, both in the callback), read
      length 16, one payload `rdmsr` / zero `wrmsr`, only module-owned calls, guard stored before
      `kexec`, bounded result block (96 bytes, `magic_out +0x50`, `guard +0x58`), reproducibility
      recorded -> build `verdict: PASS`, `problems: []`; scratch mutant with the guard removed ->
      `FAIL` with exact findings; full suite **551 passed / 1 skipped**
- [x] **live run** (one upload after the rearm): the privileged read worked on the console —
      `callback_executed true`, `kexec_rc 0`, `lstar 0xffffffff998f41c0` (page offset `0x1C0`),
      `kbase_candidate == kbase_sdk == 0xffffffff998f4000` (`MATCH`), 16 bytes at `+0x224c6c8`,
      `tv_sec 1791179388 / tv_usec 549567` (complete `timeval`), wall clock `1791277354`, cleanup
      `COMPLETE`, health green, loader port untouched
- [x] **host refused the event, no boot id** — correct fail-closed behaviour: the event claimed 16
      bytes but carried 30 hex characters (15 bytes). Root cause: the *event builder's* hex encoder
      used `o + 3u < cap` (the read path, kernel section and host verification were all correct; the
      frozen W11.1 module uses `o + 2u < cap`, W9 uses libc's encoder — neither affected)
- [x] fix v2 (offline only, no second upload): bound corrected + regression test
      `test_hex_encoder_leaves_room_for_the_last_byte`; offline proof 8/8, gate PASS, suite
      **552 passed / 1 skipped**, BIN `ec48b2fc…`, ELF `abf51379…`, build id `33aa4bb2…`
- [x] **live run with v2** (one upload after rearm): complete 16 byte read reported as 32 hex
      characters; host re-derived `tv_sec 1791179388 / tv_usec 549567` == payload claim; canonical
      `ps4rf.boot-binding.v1` object, `full_digest f0329415c5d8517d3e20bca831343adac3b03a83be7eaa6ce4fad245964867bc`,
      public id **`BOOT-f0329415c5d8517d`**, bound to the real profile
      `4a6f575c8b1aa7906d7a86d08fe5cc4e5dc1a2939a2de19fac40c7fa82771766`; **W5 accepted**
      (`binding binds exactly this profile hash` = OK); W4/W7 gate after the binding: PASS
      (`BOOT_BINDING_MISMATCH` → `PROFILE_MATCH`, `no_capability_promotion true`)
- [x] `BOOT_ID_UNVERIFIED` **resolved by evidence** — with one open review point: the run's own
      verdict is `FAIL` solely because the port-3232 health probe timed out (that port is the console
      log stream and is silent when idle; FTP/ICMP/upload/session/BYE were all green —
      see the pack's `health-diagnosis.txt`). No retry, no second upload.
- [x] review outcome: **W11.2 APPROVED WITH HEALTH-PROBE DEVIATION** — `W11.2-D1:
      PASSIVE_LOG_STREAM_NO_BANNER` / `ACCEPTED_PROBE_DESIGN_ISSUE`; health check renamed to
      `port-3232-connect` (bounded TCP connect) with informational `log_activity_observed` outside
      the verdict; semantics `IN_BOOT_STABILITY_EMPIRICALLY_PROVEN` accepted,
      `CROSS_REBOOT_CHANGE_EMPIRICALLY_PROVEN` not claimed; no further W11.2 live execution
- [ ] **W12** (offline first): first bounded `kernel.read` provider promotion — registry/allowlist
      from proven FW13.52 read regions, `region`/`offset`/`length` request (never a raw VA), max
      4096 bytes with checked arithmetic and region containment, full capability gate path
      (REQUEST → Registry → Capability Resolution → effective_grant → W4 → W5 → Boot Binding → W7 →
      native provider), separate verification flow, NATIVE ≤ OBSERVED, negative/positive offline
      matrices, `W12 OFFLINE READY` gate. Nothing live until separately approved.
- [x] **W12 offline complete — `W12 OFFLINE READY`** (commit `73e2c68`, pack
      `20261006T100052Z_ps4rf_p4w12-offline`, 10/10 VERIFY_OK, self `ca91f300a6ae2848`):
      registry (8 STRICT incl. `boottime`, `aperture_global` STRUCTURAL_ONLY and never a trusted
      read, 2 UNRESOLVED refused), request model (exact keys, fail-closed, no address input),
      capability path, separate verification with the bootstrap contract (DEFERRED → ELIGIBLE, no
      auto live execution), bounded native provider + generated drift-checked region table,
      `MAX_READ_LEN 4096` parity three ways, 17/17 harness cases, full suite 706 passed / 1 skipped,
      BIN `de9e787d…` / ELF `4d4a6365…` / build id `07d6fd12…` reproducible twice, two wave-owner
      mutants stop the build. No live step, 9090 untouched, nothing promoted.
- [x] **W12 pre-live closure** (pack `20261006T*_ps4rf_p4w12-prelive`): bootstrap region =
      `xfast_entry` (0x1C0, 8 B) chosen by the documented filter; profile + boot evidence
      re-verified against the pinned dump and the frozen live pack; run separation enforced
      before provider entry (`KREAD_VERIFICATION_NOT_SEPARATE`, regression test); gate states
      DEFERRED -> DEFERRED(live approval) -> GRANTED(one entry) simulated; all safety
      assertions stop before provider entry; payload BIN byte-identical; suite
      707 passed / 1 skipped. Live needs two rearm confirmations (verify run, read run).
- [x] **W12 live prerequisites (offline, before any upload)**: (a) `session.py` knows+validates the
      payload event `kernel.read.bounded` / `ps4rf.kernel.read.bounded.v1` (`session.py`,
      `tests/test_kernel_read_bounded_event.py`); (b) host driver `tools/hostctl/kreadlive.py` for
      the approved two-run flow (bootstrap verify -> VerificationEvidence -> W4/W5/W7 -> one
      generic bounded read in a new run id), phase flags on `ps4rfctl live|listen`
      (`--w12-verify-run` / `--w12-read-run`, fail-closed preflight, one invocation = ONE phase),
      `tests/test_kreadlive.py` (37) and the offline end-to-end simulation
      (`kreadlive.py --simulate`, byte-stable across re-runs). Bootstrap region stays `image_elf`
      (the frozen payload's live trigger reads the first STRICT row); payload stays byte-identical
      `de9e787d…`.
- [x] **W12-RVA0-BINDING resolved — `W12 VERIFY LIVE READY` (phase A only)** (pack
      `20261006T*_ps4rf_p4w12-rva0-verify-live-ready`, supersedes `..._p4w12-prelive`; owner ruling
      2026-10-06: **not** Option C, payload unchanged, `image_elf @ RVA 0x0` stays the
      `BOOTSTRAP_VERIFY_REGION`): rva `0x0` is a valid *locator* (`FIELD_DOMAINS['rva']`,
      `validate_locator_value`: `0 <= rva < 2**64`), while a *runtime* address stays `> 0` and
      canonical (`FIELD_DOMAINS['runtime_va']`, applied at resolution against the current boot base:
      `regions.checked_kernel_address` / `resolve_runtime`, checked adds, overflow / zero /
      non-canonical / out-of-window fail closed). The W5 binding binds the locator, never a runtime
      address. `image_elf` phase B now walks the whole chain: `GRANTED`, exactly **1** provider
      entry, pinned bytes back (simulation 18/18, `accepted_contract_met` true). Profile untouched
      (`4a6f575c…`), no payload rebuild (BIN `de9e787d…` / ELF `4d4a6365…` / build id `07d6fd12…`
      re-verified); suite 781 passed / 1 skipped / 0 failed, 13 regressions in
      `tests/test_rva0_domain_binding.py`.
- [x] **W12 phase A live attempt #1 (2026-10-06)** — one upload, read verified, evidence REFUSED by
      one host check: deviation `W12-A-D1`
      (`COMPILED_REGION_COUNT_COMPARED_TO_POLICY_REGISTRY_TOTAL`, disposition `HOST_VERIFIER_BUG`,
      payload result `READ_SUCCESSFUL_NOT_PROMOTED`, verification result `REFUSED_FAIL_CLOSED`).
      Pack `20261006T120929Z_ps4rf_p4w12-phaseA-deviation` (unchanged, owner-accepted).
- [x] **W12-A-D1 fixed offline → `W12 VERIFY LIVE READY R2`** (pack
      `20261006T*_ps4rf_p4w12-verify-live-ready-r2`): `regions.compiled_regions()` is the normative
      target table (registry order minus the `UNRESOLVED` policy entries) and the single source for
      the compiled count, the target order, the index mapping and payload parity; `regions()` stays
      the full policy registry. The check compares against the compiled count (9 == 9), indices map
      inside the compiled table, the simulation uses the same path, the table fails closed
      (`KREAD_TABLE_INVALID`). 18 pinned regressions + a mutation guard
      (`ALL_MUTANTS_KILLED`); suite 799 passed / 1 skipped / 0 failed. No payload rebuild (BIN
      `de9e787d…` / ELF `4d4a6365…` / build id `07d6fd12…` unchanged); the generated header was
      regenerated (provenance comment only).
- [x] **W12 phase A live attempt #2 — VERIFIED (2026-10-06)**: one upload, `image_elf` rva 0 length
      16, expected == observed, 22/22 owner criteria PASS, exactly one `VerificationEvidence`
      persisted (`VRUN-ae918ffe023e9e9c`, `evidence_sha256 313b2455…`, re-hash MATCH on load), zero
      generic provider entries, cleanup COMPLETE, BYE `CLIENT_CLOSE`, health green. Pack
      `20261006T122857Z_ps4rf_p4w12-phaseA-verified`; owner review **APPROVED** (phase A accepted).
- [x] **W12-A2 — NATIVE assurance consistency closed offline** (pack
      `20261006T123838Z_ps4rf_p4w12-read-live-ready`): the phase-B PROVEN state is
      *verification-derived assurance* — `NATIVE` alone stays `OBSERVED`/`DEFERRED`, `PROVEN` only via
      the separate, store-bound `VerificationEvidence`; the exception is documented (§6 of the W12
      doc, the F7 finding, the module docstring) and pinned by 18 regressions. No bypass found, no
      production code changed in A2.
- [x] **W12-A3 — verification-derived assurance gate (offline)**:
      `derive_capability_record()` is the store-bound authenticity gate (addressed by
      `evidence_sha256`, all facts re-established from the stored record), the phase-B path revalidates
      the derivation immediately before the provider entry (`KREADLIVE_CAPABILITY_NOT_DERIVED`), the
      store gains `load_verification_by_sha256()`, the derivation receipt is bound to the content
      hash of the derived record (a copied receipt id on another record is refused too) and
      `test_w12a3_derivation_authenticity.py` (19) pins the hand-built-PROVEN rejection, the
      stolen-receipt case, the marker bindings and the store-manipulation cases. Status `W12 READ LIVE READY R2`
      — phase B still needs its own review decision, its own live approval (incl. the pinned read
      window) and its own rearm confirmation.
- [x] **W12 phase B live (`--w12-read-run`) — VERIFIED, W12 COMPLETE (2026-10-06)**: the owner pinned
      the window as the bootstrap window (`image_elf` / offset 0 / length 16) in the §70 approval and
      gave the exact rearm token; one upload ran with exactly one provider entry and one callback,
      `RUN-0aa2093b16472b39` in session `SES-c9f6d93f70d61278d04ae493b4622108`, expected == observed
      (`7f454c46…` / `7ef1ae26…`), 28/28 criteria, cleanup COMPLETE, BYE `CLIENT_CLOSE`, health green,
      store 1 verification + 1 read run. Pack `20261006T130108Z_ps4rf_p4w12-phaseB-verified`; owner
      review **APPROVED** → milestone tag `PS4RF-KERNEL_READ_L1-VERIFIED`. No further W12 upload.
- [x] **W13 — Read-Only Kernel Research Baseline (offline, 2026-10-06)**: the verified primitive is
      turned into a repeatable, bounded, auditable research instrument without loosening a W12 rule.
      Region classification (`IDENTITY_ONLY`/`APPROVED_READ`/`STRUCTURAL_ONLY`/`UNRESOLVED`) with
      seven machine-checked promotion criteria and documented review decisions (5 approved reads,
      `aperture_global` stays `STRUCTURAL_ONLY`, 2 stay `UNRESOLVED`, identity windows excluded);
      research read plan derived from `APPROVED_READ` only; content-addressed dataset with a
      deterministic snapshot index; bounded pointer-follow policy (`UNRESOLVED_TARGET` → STOP);
      W6 integration contract (relative-locator artifacts, `OBSERVATION` candidates, W4 impact
      `NONE`). `tools/research/*`, `tests/test_w13_research_baseline.py` (54 tests),
      docs `P4-W13-READ-ONLY-RESEARCH-BASELINE.md`. Status `W13 OFFLINE READY`.
- [x] **W13 offline review APPROVED (2026-10-06)** — classification matrix 11/11 ratified, no
      additional promotion, pack `20261006T131555Z_ps4rf_p4w13-offline-ready` accepted. Pre-live
      consistency check for `amd_iommu` resolved from the pinned artifacts: section `text`,
      permissions `r-x` (profile locator + the pinned image's own PT_LOAD flags), rva `0x7ce9e9`,
      length 16, expected bytes `414d4420494f4d4d5500696f6d6d7520`, expected sha256
      `0e5db66bb6e045a242282881beb9525d80f00efdccd3586da7d2692e74d4cc5f`, provenance pinned image
      `cf157ffd...` + W9 live attestation; the "rodata" wording is withdrawn and now impossible
      (rule + tests). Status **`W13 RESEARCH READ 1 LIVE READY`**.
- [x] **W13 release gate + released-window read path (offline, 2026-10-06, owner decision A)**: the
      approved read was blocked by a host gap — the W12 read path could only run the pinned bootstrap
      window (`image_elf/0/16`; the CLI had no region/window parameter and `bootstrap_expectation()`
      hard-pinned it). Fixed host-only, payload untouched: new record `--w13-release`
      (`tools/research/release.py`, schema `ps4rf.w13.research-read-release.v1`,
      region/offset/length/expected bytes+sha256/module/section/permissions/classification/profile/
      boot/state) whose window is built with `window_for()` only after every cross-check —
      `W13_RELEASE_INVALID`, `_NOT_APPROVED`, `_REGION_NOT_APPROVED_READ`, `_REGION_NOT_IN_PLAN`,
      `_BYTES_NOT_PINNED`, `_LENGTH_MISMATCH`, `_WINDOW_MISMATCH`, `_PROFILE_MISMATCH`,
      `_BOOT_MISMATCH`, `_SECTION_MISMATCH`; validation runs in the preflight (a refused release
      stops the invocation before a bridge, a listener or an upload exists) and again immediately
      before the read. Two invariants keep W12 frozen: the stored VerificationEvidence is still
      judged against the **pinned bootstrap window** (A3 §1.12/1.13) while the read is about the
      released window, and a non-bootstrap window without a release id can never be read
      (`KREADLIVE_WINDOW_NOT_RELEASED`, zero provider entries). The read-run record now names the
      release that selected the window. 25 tests (`tests/test_w13_release_window.py`), suite
      **918 passed / 1 skipped**; rehearsal against a copy of the live store (real phase-A evidence,
      real release record): outcome `READ`, exactly 1 provider entry, event verified, bytes and
      sha256 exactly the released window, `resolved_runtime_va 0xffffffff9a0c29e9`, BYE clean, live
      store untouched. Status **`W13 READ 1 RELEASED WINDOW PATH READY`**.
- [x] **W13 trust-object separation + one-shot semantics (offline, 2026-10-06, owner ruling)**:
      section 70 approval (`tools/research/approval.py`, existing contract, answers only "may the
      provider run", never carries a window) and W13 research release (`approval_sha256` binding;
      answers only "which window, exactly once") are separate records that can never stand in for
      each other — `W12_APPROVAL_SCHEMA_INVALID` / `W13_RELEASE_INVALID`, `W13_RELEASE_REQUIRED`,
      `W13_RELEASE_APPROVAL_MISSING`, `W13_RELEASE_APPROVAL_NOT_SEPARATE`,
      `W13_RELEASE_APPROVAL_BINDING_MISSING`, `W13_RELEASE_APPROVAL_MISMATCH`,
      `W13_RELEASE_FORBIDDEN_FIELD` (no assurance/PROVEN/capability/W4 approval in a release),
      `W13_RELEASE_REGION_IS_BOOTSTRAP`. One-shot: unique `release_id`, marker
      `releases/<release_id>.json` (`consumed: true`, `consumed_at: provider_entry`, release +
      approval hash pinned, rehashed on load) written immediately before the provider entry; a
      refusal before that consumes nothing; a retry is `W13_RELEASE_ALREADY_CONSUMED` with zero
      provider entries; `W13_RELEASE_CONSUMPTION_FAILED` refuses an unwritable store and keeps the
      release spent in-process; `W13_RELEASE_UNBOUND` refuses a released window without a release
      document hash. `tests/test_w13_release_separation.py` (24 tests: the owner's eleven mandated
      regressions + the one-shot policy), suite **943 passed / 1 skipped**, rehearsal against a copy
      of the live store with the transcribed records `READ` / one provider entry / marker at the
      entry / second attempt refused with zero entries / live store untouched. Status
      **`W13 RESEARCH READ 1 LIVE READY R2`**.
- [ ] **W13 research read 1 live**: NOT uploaded. Released by the owner (`W13 RESEARCH READ 1 LIVE
      APPROVAL`, exactly one read `amd_iommu`, offset 0, length 16 — the promoted region length,
      expected bytes `414d4420494f4d4d5500696f6d6d7520`, expected sha256 `0e5db66b...`, boot
      `BOOT-f0329415c5d8517d`), transcribed into the release record; the section 70 approval is the
      separate record `§70-W13-READ-1-20261006T1345Z` (sha256 `4d54046c…`). The one remaining gate is
      a fresh `BinLoader rearmed`, then exactly ONE upload, then its own new session with store rehash MATCH,
      current profile/boot binding, newly derived session capability, W4 approval, W5 APPROVED_READ
      (recovery false, resolved runtime VA internal and canonical, no raw address in the request).
      One bounded read per released run, no pointer follow, no multi-read, no auto expansion; W6 may
      only produce `OBSERVATION` with W4 impact `NONE`.

---

## W11.1A — host EVENT capture debug (offline done, no live upload, payload unchanged)

- [x] root cause found: the **live** evidence-assembly branch dropped the already captured
      `boot.binding` event (the single reader had recorded it in the session); the offline branch
      copied it -> the two paths had diverged, the console was never at fault
- [x] offline replay of the live frame order (real agent on loopback, live stand-in
      `BOOT_READ_FAILED`): before = event lost (`LEGACY_REPLICA_EVENT_LOST`, `events_seen: 1`),
      after = event captured (`PASS`, `verified: true`, `no_boot_id: true`)
- [x] fix, host side only: one central router in `HostSession` (single reader, RESPONSE -> dispatcher,
      EVENT -> sink, BYE -> lifecycle) + one shared `capture_events()` / `live_agent_stop_outcome()`
      used by `drive()`, the offline self test and both live modes; opt-in frame trace
      (`PS4RF_FRAME_TRACE=1`) with types/AEAD sequences/lengths/destinations, no key material
- [x] fail closed, never silent: refused EVENT -> `ProtocolError` + accounting, unknown type kept as
      opaque authenticated event, schema failure -> `EVENT_SCHEMA_REJECTED` with reason, duplicates
      defined, BYE does not cut the event queue
- [x] regressions `tests/test_event_capture.py` (the 10 mandated tests + a divergence guard);
      full suite green
- [x] W11.1 payload untouched (no rebuild): BIN `2b3d00370444f9ba75e77d83048343f4cc1ee5868dad148e34bcdb9678283418`
- [ ] review: is a further W11.1 live run justified? (frozen payload, its single rearm is consumed;
      no live upload happened in W11.1A)

## W11.1 — userland KERN_BOOTTIME diagnostics (offline done, live pending rearm)

- [x] both userland paths instrumented: size query first (`oldval = NULL`), then a bounded read of
      at most 64 bytes — `sysctlbyname("kern.boottime", ...)` and the MIB `sysctl({1, 21}, 2, ...)`
- [x] machine-readable classification from measured values only (name/mib not found, permission,
      invalid argument, size query failed, read failed, short result, malformed result, success)
- [x] contract: a complete 16 byte `struct timeval` or nothing — `BOOT_SOURCE_PARTIAL`,
      `BOOT_SOURCE_CONFLICT`, `BOOT_SOURCE_NOT_STABLE` never produce a boot id
- [x] ABI pinned and asserted (`sizeof(struct timeval) == 16`); manifest gates: syscall
      instructions 0 (whole image), max read buffer 64, rdmsr/wrmsr/kexec/kernel literals 0
- [x] offline proof: 10 scripted access-path scenarios + `boot.py --self-test`; suite 529/1
- [ ] live run after the BinLoader rearm: one upload, then the diagnosis of the failed read
- [ ] decision after the diagnosis: W11.2 bounded privileged read (own review) vs. accept

## W11 — live userland boot binding (offline done, W11 live FAILED fail-closed: BOOT_READ_FAILED)

- [x] canonical algorithm `ps4rf.boot-binding.v1` + recomputed capture boot id (documented change)
- [x] read-only userland collector + agent one-shot hook + fail-closed BYE reasons
- [x] host verifier, session capture, `selftest --w11-boot-binding`, W4/W5/W7 gate before/after
- [x] offline end-to-end (stable / drifting / absent source) + source and artefact gates
- [x] evidence pack `20261006T020705Z_ps4rf_p4w11-offline`, suite 526 passed / 1 skipped
- [ ] **live run after "BinLoader rearmed"** (one upload; then handshake → status → boot read →
      binding → W5 → W4/W7 → status → BYE → health)
- [ ] after the live result: decide the first real `kernel.read` promotion from the remaining
      W4/W5/W7 reasons (its locator is still pending: `LOCATOR_MISSING`, fail closed)

## P0 — Freeze gate

- Install dependencies.
- Preflight PASS.
- Full pytest PASS.
- G1–G8 PASS through `tools/freeze/run_gate_suite.py`.
- Confirm `PS4RF-CORE-1.0-MOCK-READY` was created by the runner only.
- Archive `FREEZE-REPORT.json`.

## P1 — OrbisProbe

- Obtain the real OrbisProbe source.
- Generate the static inventory draft.
- Complete the source inventory manually.
- Create PS4RF mapping and conflict list.
- Implement adapter against the mock core.
- Add parity tests.

## P2 — Metasploit

- Implement msfrpcd adapter/provider layer.
- Keep PS4RF as source of truth.
- Do not promote module success beyond `OBSERVED` without PS4RF verification.

## P3 — Tool adapters (complete)

- Ghidra headless analysis.
- Rizin xrefs / CFG / boundaries.
- angr CFG / dataflow / constraints.
- AFL++ corpus / crash / reproducer workflow.

## P3b — Recon & privesc knowledge adapters (complete, added 2026-10-05)

- PEASS-ng / linPEAS adapter (`tools/recon/peass/`): target-OS detection
  (Linux / FreeBSD-OrbisOS / unknown); compatibility marked for supported
  targets only; PS4/OrbisOS is explicitly **not** scanned generically.
- GTFOBins knowledge adapter (`tools/knowledge/gtfobins/`): index + matcher,
  candidates only (`source = external_knowledge`); no recipes stored, nothing
  executed.
- unix-privesc compat layer (`tools/recon/unix_privesc/`): platform-independent
  enumeration schema/classifier, Linux vs. FreeBSD/OrbisOS classified separately.
- PLANNED (no source yet): pspy, Linux Smart Enumeration, unix-privesc-check,
  Nuclei, ffuf/feroxbuster, nmap/masscan, SecLists.
- Binding rule: recon → observation → candidate → verification → primitive →
  exploit candidate. Recon output is never an exploit finding by itself and no
  privilege-escalation technique is executed because of a match.

## P4 — Native ps4rfd (userland only)

Plan: `P4-NATIVE-PS4RFD-PLAN.md`. Keep it primitive-oriented and profile-driven.

- **W0 — decisions: complete (2026-10-05).** All 19 owner decisions approved and
  recorded in `docs/P4-W0-DECISIONS.md`; the previously missing sources are
  delivered: §70 text
  (`docs/spec-history/70-capability-gated-native-primitive-additions.md`) and the
  frame type byte table (wire mapping v1, `docs/P4-WIRE-SPEC-v1.md`).
- **Core/Wire Revision R1 — complete.** Minimal decided consequences: effective
  sequence ceiling `EFFECTIVE_LAST_SEQ` enforced (D8), central `InvalidTag` →
  `AuthenticationFailed` mapping (D9), shared frame table + framing in
  `core/rpc/wire.py` (D12); catalogs regenerated, drift documented in
  `FREEZE-DRIFT.md`.
- **W1 — deliverables: complete.** `docs/PAYLOAD-SDK-CONTRACT.md`,
  `docs/P4-W1-TOOLCHAIN.md`, `docs/P4-W1-TESTVECTORS-SPEC.md` (with the crypto and
  parity catalogs as the SDK-independent acceptance basis).
- **W2 — complete and ACCEPTED by the owner (2026-10-05).** Native userland
  skeleton (`native/src/`, C99, in-repo core) + offline parity harness: both
  golden catalogs plus the generated negative catalog are replayed natively with
  byte-level comparison (154 PASS / 0 FAIL / 4 structural exemptions). Artifacts:
  `native/build/ps4rfd.elf` (`ET_DYN`) + `native/build/ps4rfd.bin`, reproducible
  byte-identically, toolchain manifest validated. No SDK used (D1 "D first"), no
  kernel code, no core change. Evidence:
  `~/07-evidence/20261005T154624Z_ps4rf_p4w2` (`VERIFY_OK`, self-hash `3329ba12…`).
- **W3 — primitive interface freeze v1: complete (pending owner review).** All 35
  registry operations are mapped in `tools/primitive_iface/schema.py` to exactly one
  provider interface each (strict request/result schemas, capability binding,
  `mutating`/`recovery_safe` read from the frozen core and cross-checked by
  `--self-test`); `docs/P4-PRIMITIVE-INTERFACES.md` carries the prose contract and the
  machine-checked inventory. Status split: 16 `stub` (implemented in the host-side
  stub, 48 behavioural checks + 105 validator checks), 14 `deferred-privilege`,
  1 `deferred-host-chain`, 4 `mock-only`; gated operations are refused fail-closed
  with the new, distinct code `OPERATION_DEFERRED`. Findings recorded, not patched:
  F7 (`ProviderType.NATIVE` missing for the W7 registration), F8 (read-class kernel
  ops marked mutating in the frozen registry), F9 (mock tolerates `memory.alloc`
  without `size`), F10 (sync flags: spec draft vs frozen core). No core change, no
  privileged implementation, no hardware action.
- **W6 — differential harness: complete (pending owner review).** Offline comparison of
  profiles, offline artifacts (zip bundles, ELF sections, raw blobs, inventories),
  operation contracts and optional external analysis results, producing findings
  (10 classes, 4 confidences, no verdict vocabulary) and OBSERVATION-only candidates.
  Delivered: `tools/differential/{normalize,schema,inventory,compare,candidates,cli}.py`,
  `docs/P4-DIFFERENTIAL-HARNESS.md`, `tests/fixtures/differential/` (+ generator),
  `tests/test_differential_harness.py` (29 tests: all 16 named scenarios, fail-closed
  inputs, determinism, non-escalation, D18 regression). Nothing is enabled by a diff;
  a candidate still needs review → verification → W5 profile update → new binding.
- **W5 — profile binding: complete (pending owner review).** Target identity, locator
  facts (`module`, relative locator, `section`, `permissions`, optional
  `expected_bytes`, provenance, confidence), canonical profile hash via the frozen
  core canonicalizer, value domains for every profile field (typed where the repo has
  verified types, explicitly `unresolved` where it does not - fail-closed), boot
  binding that expires with the boot while facts persist, runtime binding as
  `locator + runtime base` (never stored), read-only bounded probe contract, strict
  schema (no absolute address expressible), loader as the single entrance, W4 adapter
  that feeds only the profile reason, fixtures with `UNRESOLVED`/fixture markers (no
  invented FW13.52 addresses) and 29 tests covering every named scenario. Delivered:
  `tools/profiles/{schema,binding,loader,w4_adapter}.py`,
  `schemas/profile.schema.json`, `docs/P4-PROFILE-BINDING.md`,
  `tests/fixtures/profiles/`, `tests/test_profile_binding.py`.
- **W4 — capability gate process (§70): complete (pending owner review).** The
  process by which a `deferred-privilege` primitive may ever leave
  `OPERATION_DEFERRED`: `tools/primitive_iface/gate.py` (pure decision function, 14
  privileged + 1 host-chain requirement entries, 10 reason codes each with a named
  owner), `docs/P4-CAPABILITY-GATE.md` (state model, fail-closed decision logic,
  verification/evidence requirements, recovery+cleanup policy per class, transition
  path, W5/W7 handoff contract) and `tests/test_capability_gate.py` (19 tests: the ten
  required negative scenarios, doc/module/frozen-core parity, "claims carry no
  authority", "everything satisfied but not wired → still deferred", "no path from
  mock evidence to privileged release"). Minimum assurance per namespace is read from
  the frozen core, never restated. A decision never executes anything: `executable`
  is hard-`False` and the wire answer stays `OPERATION_DEFERRED`. Mock evidence is
  excluded for privileged capabilities (policy, finding F11 — recorded, not patched).
- **W7 — provider wiring: complete (pending owner review).** The one dispatch path
  (`tools/dispatch/`): router matrix (35/35 exactly one route, parity-checked against the
  frozen registry and the W3/W4/W5 matrices, no implicit fallback), provider interface
  (validated context in, structured result out), per-request resource view over the
  central `ResourceManager`, invocation evidence for every attempt (incl. the refusing
  chain step), the single provider entry site, central recovery check before entry and
  `max_inflight`. Sixteen stub operations wired and semantically unchanged; 4 mock-only
  and 15 gated operations registered but not enterable. F7 fixed by the minimal core
  patch (`ProviderType.NATIVE` + one conservative authority rule, revision `R2 (F7)` in
  `FREEZE-DRIFT.md`); F8/F9/F10 unchanged by design. `docs/P4-PROVIDER-WIRING.md`,
  `tests/test_provider_wiring.py` (53 tests). No live PS4, no payload, no primitive.
- **W4 — unblocked by D17.** Native primitives only per §70: a concrete
  Capability Missing Record approved by the Project Owner / Research Lead; the
  implementing agent must not self-approve. P4 stays **userland only** — kernel,
  GPUVM, KeyMgr, CCP, SAMU, PUP, EAP, SBRAM, EMC and secure-service primitives
  need an explicit approval for that privilege level/phase.
- Kernel code / payloads: only with explicit new approval (P4 release caveat).
- Freeze discipline: `SHA256SUMS` stays point-in-time; every divergence is logged
  in `FREEZE-DRIFT.md`, which the gate reads. Re-freeze only with the next
  planned core/wire revision.

## P5 — Live PS4

- Complete FW13.52 primary profile.
- Complete FW9.00 reference profile.
- Port verified mock semantics to the real target agent incrementally.

## P4 — W8 (live userland bring-up, first controlled live step)

- [x] Target build of the agent (reproducible, gated) — `native/target/build_ps4.sh`.
- [x] Host controller + approved smoke sequence + evidence record — `tools/hostctl/`.
- [x] Wire parity re-run with the target codegen flags (W2 catalogues, 0 mismatches).
- [x] Offline end-to-end: host build of the agent against the controller (14 requests, PASS).
- [ ] Live: one payload upload after the owner's BinLoader rearm confirmation
      (`ps4rfctl live --rearm-confirmed`), then the approved sequence, health checks, STOP.
- [ ] Post-live: W8 evidence pack + review; no W9 work before that review.

## P4 — W10 (real FW13.52 profile promotion + boot binding resolution) — DONE (offline, 2026-10-05)

- [x] Real profile promoted from W9 evidence + pinned research; independent validator PASS;
      `profile_sha256` `4a6f575c…`; W5 fixture untouched; no runtime address persisted.
- [x] Boot identity candidates and contract; reboot semantics covered offline; no live measurement.
- [x] W4/W5/W7 gate report before/after: privileged providers stay deferred, `kernel.read` stays
      `OPERATION_DEFERRED`, no provider entry.
- [ ] Owner review of the W10 evidence pack. W11 (boot identity live attestation -> runtime
      binding -> separate `verify.kernel.read` -> bounded read-only `kernel.read` provider) is
      **not** implemented and needs a new explicit release.

## P4 — W9 (read-only privileged attestation bring-up) — DONE (offline + live executed 2026-10-05)

- [x] Offline: fixed attestation callback (no host supplied kernel addresses, no writes, no
      variable function pointers, no retry, bounded copyout), static gates + reproducible build.
- [ ] Expected fingerprints with provenance from the existing FW13.52 evidence (expected vs
      observed vs match kept separate).
- [ ] Everything else stays closed: no generic kernel.read/write/call, no dump, no GPUVM/KeyMgr/
      CCP/SAMU/SBRAM/EAP/EMC/PUP, no fuzzing, no races, no persistence.
- [x] Stopped at "W9 LIVE READY" with the payload SHA256; live run executed after the owner's
      "BinLoader rearmed" (one upload, PASS, packs `20261005T202341Z_ps4rf_p4w9-offline-r2` and
      `20261005T202857Z_ps4rf_p4w9-live`). Profile decision: PROFILE_MATCH_CANDIDATE only.
- [ ] Owner review of the W9 live evidence pack; any profile/boot-binding promotion follows that
      review (no promotion in W9), and any further privileged work needs a new explicit release.


## W13-C1 — bounded region request plumbing (read trigger only, new payload, offline) — DONE offline

- [x] root cause of the refused first live W13 read pinned to the payload's fixed probe
      (`ps4rf_kread_probe_request()` = first `STRICT_FINGERPRINT` row = `image_elf / 0 / 16`); the
      probe is deleted, the region is data-driven (owner decision "Entscheidung: C")
- [x] request model: exactly `(region_index, offset, length)` — never an address, never an RVA; the
      parser is strict and total (sentinels), the provider owns the vocabulary
      (`KREAD_REGION_INDEX_INVALID`, `REQUEST_REFUSED`) and every rule runs before the single
      `kexec`; the frozen router keeps answering `kernel.read` as deferred privilege
- [x] host path: `wire_request_for()` before the provider entry, release pins `window.region_index`
      (`W13_RELEASE_INDEX_MISMATCH`), echoed index re-checked (`KREADLIVE_REGION_INDEX_MISMATCH`,
      `KREADLIVE_REGION_NOT_COMPILED`, `KREADLIVE_TRIGGER_NOT_DEFERRED`), optional payload binding
      (`W13_RELEASE_PAYLOAD_MISMATCH`)
- [x] gate + mutants: gate proves the three-key request, no address key, sentinels, three uses per
      parsed value, bounds/identity/length/containment/checked-add/table-lookup; all seven required
      mutants fail the build
- [x] regressions: harness `N`, `N2`, `O`, `P`, `Q` on the production path plus the host suites
      (wrong row replayed = the first live failure; wrong index for the right region; hand-picked
      index; release for another payload; unmappable window refused with the release untouched)
- [x] offline rehearsal `all_green` with the new trust objects; full suite green
- [x] new payload (built twice, identical): BIN `f7052568…`, ELF `5341e1b9…`, build id
      `2e6a2d68b3c828855fe4dd4519bdbf7a`; the W12/W13 BIN `de9e787d…` stays historical evidence
- [x] new trust objects: §70 approval `§70-W13C1-READ-1-20261006T1510Z`, W13 release
      `W13-C1-READ-1-NEW-PAYLOAD`; the consumed `W13-READ-1-LIVE-APPROVAL` is never reused
- [ ] **Live run: NOT authorised here.** Requires a fresh, exact `BinLoader rearmed` (the previous
      token is spent) and one upload only, then the same STOP rule as before.
- [ ] W14 (resident `ps4rfd`, multi-read, pointer follow) stays separate: no persistent agent, no
      agent update, no new provider was built in this wave.
- W14 stage A (landed, committed): the transitional per-operation trigger is gone -- the session
  loop holds no `kernel.read` state and no call site, the target catalog routes `kernel.read`
  through exactly one wired privileged provider (WIRE-CATALOG R3, target-side override; host route
  unchanged), the read record rides the RESPONSE, and the one shot is per session.
- W14 (resident daemon, landed): `native/target/ps4rf_daemon.{h,c}` implements the life cycle
  (BOOTSTRAP -> RESIDENT_IDLE -> SESSION_ACTIVE -> SESSION_CLEANUP -> RESIDENT_IDLE) over the
  existing dial-out transport, with the single acceptance gate (`ps4rf_daemon_accept`, ACCEPT only
  in RESIDENT_IDLE), the boot-input cache re-checked before every session, the per-session resource
  demand (`held = []` + cleanup COMPLETE), the boot-wide `RECOVERY_REQUIRED` flag, the §13
  `SESSION_BUSY` notice (unauthenticated, no session id, strictly parsed by the host) and the four
  exit conditions of §3 (admin shutdown declared but without a producer yet). Offline: `--resident`
  in `ps4rfd_host.c`, `tools/hostctl/resident.py` as per-session controller, and the source-level
  build gate `gate_agent_source()` in `build_manifest.py` (comment-stripped, ELF-free) enforcing
  "the agent names no kernel.read" plus the daemon's structural properties. Tests:
  `tests/harness/daemon_state_check.c` + `tests/test_w14_daemon.py` (26), phase doc
  `docs/P4-W14-RESIDENT-DAEMON.md`. The console KREAD artefact gate is restated to WIRE-CATALOG R3
  (absent trigger block, per-session re-arm, R3 target row with an unchanged host route table) and
  is exercised by the suite from now on: console build verdict PASS, 0 relocations, build id
  `b9226334e4e2fadb1b00fae82c2583c0`.
- [ ] W14 (rest, named): §4 session-isolation audit (nonces, directional keys, request-ID registry,
      capability derivation, approval/release evaluation per session), §6 evidence re-bind per
      session + "`CapabilityRecord` never reused", §7 multi-read rehearsals with separate releases,
      §14 agent identity binding in HELLO, §15 authenticated admin shutdown, the 10 offline
      scenarios (§16), the 100-session leak/stress run (§17), per-session + daemon evidence (§18),
      phase doc + evidence pack, then the `W14 OFFLINE READY` report and STOP (no upload).
