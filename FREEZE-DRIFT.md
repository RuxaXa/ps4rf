# Freeze drift log (D18)

The point-in-time manifest `SHA256SUMS` (written at the core freeze
`PS4RF-CORE-1.0-MOCK-READY`, commit `1536e35`) is **kept as-is**: it is never
silently updated. Every file whose content diverges from it is listed here, with
the reason, the phase and the review reference. `tests/test_freeze_drift.py`
(the gate) reads this file and fails when

* a documented entry's hashes do not match reality,
* any manifest mismatch is **not** documented here, or
* the manifest file itself was modified (no silent re-issue).

Policy (W0/D18): non-core changes may drift with a documented entry. **Core**
changes after the freeze require the revision process: every core entry names the
revision it belongs to, and the `revisions` map names that revision's review
document. Four revisions exist: **R1** (consequences of W0 decisions D8/D9/D12,
reviewed in `docs/P4-W0-DECISIONS.md`), **R2** (the W7/F7 integration patch,
reviewed in `docs/P4-PROVIDER-WIRING.md`), **R3** (wire catalogue revision
R4, the W14 §15 authenticated admin shutdown, reviewed in
`docs/P4-W14-RESIDENT-DAEMON.md`) and **R4** (the W17E generic primitive
surface — `kernel.snapshot.recipe` and `ioctl.invoke`, the capability catalog
name list, reviewed in `docs/P4-W17-PRIMITIVE-MIGRATION.md`). Re-freeze only with
the next planned core/wire revision. New files created after the freeze are not
drift and are not listed.

```json
{
  "entries": [
    {
      "core_impact": "no",
      "file": "CHANGELOG.md",
      "new_sha256": "68d53c1bf83853f36f5da4e7690acdebedea0cf520683df01d656417c87b831d",
      "old_sha256": "60a3442eea8cfcc362bfd2ae9e3dd5f062f9ea3a1ff0e5f17d6d7818a67e2f64",
      "phase": "W0 / R1 -> W9 -> W11 -> W11.1 -> W12 -> W12-RVA0 -> W12-A-D1 -> W12-A2 -> W12-A3 -> W13 -> W13 release gate -> W13 separation -> W13-C1 -> W13-C2 -> W14 -> W14B -> W17",
      "reason": "W13 (2026-10-06): post-freeze entry for the read-only research baseline - new tools/research package (classification, read plan, dataset, pointer follow, W6 contract), docs/P4-W13-READ-ONLY-RESEARCH-BASELINE.md, 54 new tests + 5 module self-tests, status W13 OFFLINE READY (no live step); W12 closed with milestone tag PS4RF-KERNEL_READ_L1-VERIFIED. W12-A3 (2026-10-06): post-freeze entry for the verification-derived assurance gate - derive_capability_record() is addressed by the evidence hash and re-establishes every fact from the stored record before it stamps PROVEN, the store gains load_verification_by_sha256(), the phase-B path revalidates the derivation immediately before the provider entry (KREADLIVE_CAPABILITY_NOT_DERIVED), F7 and the chain are untouched, 18 + 18 regressions green, status W12 READ LIVE READY R2 (phase B needs its own approval, window pin and rearm). W12-A2 (2026-10-06): the assurance consistency answer and the phase-A acceptance recorded. | W12-A-D1 (2026-10-06): post-freeze entry for the compiled-target-table vs policy-registry fix (deviation COMPILED_REGION_COUNT_COMPARED_TO_POLICY_REGISTRY_TOTAL, disposition HOST_VERIFIER_BUG, payload result READ_SUCCESSFUL_NOT_PROMOTED, verification result REFUSED_FAIL_CLOSED), the new compiled_regions() source, the mutation guard, the regenerated provenance comment and the 18 regressions. | W12-RVA0-BINDING (2026-10-06): post-freeze entry for the relative-locator vs runtime-address domain fix (W5 binds the locator; the runtime address is resolved checked at bind time), the closed live seam, the unchanged payload/profile, the regenerated region table header (provenance comment only) and the 13 regressions. | W12 (2026-10-06): post-freeze entry for the offline W12 host driver (two-phase live flow: explicit session/boot/profile boundaries, run separation with a rehashed VerificationEvidence, provider-entry counting, ps4rfctl phase flags, tests/test_kreadlive.py, byte-stable offline end-to-end simulation) and the open live seam (the frozen W5 addr domain refuses the pinned rva-0 window; reported verbatim, not bypassed). | W11.1 (2026-10-06): post-freeze entry for the instrumented userland diagnostics, the classification table, the partial/conflict rules and the new artefact gates. | post-freeze section: P3b tool layer, W0 decision record, Core/Wire Revision R1 (D8/D9/D12), W1 deliverables | W9 (2026-10-05, commit 2f8324b): status/phase/CHANGELOG updated for the W8-D1 deviation record and the W9 attestation wave (offline half); no core file touched by W9 | W9 window-policy correction (commit with BIN f70fd896...): docs + status files re-stamped | W11 (2026-10-06): post-freeze entry for the canonical ps4rf.boot-binding.v1, the read-only boot collector, the offline end-to-end proof, the PROFILE_MATCH gate result and the hand-stated W9 rebuild drift. | W11.1A (2026-10-06): host side EVENT capture fix (one shared capture helper + one central frame router; the live evidence branch no longer drops a captured event) - reason for the refreshed pin of this status file; payload unchanged, no live upload.; W13 release gate for the first research read (owner decision A: dedicated --w13-release record; bootstrap evidence binding unchanged; non-released non-bootstrap windows refused) | W13-C1 (2026-10-06): post-freeze entry for the bounded region request plumbing - the payload no longer picks the read region (the fixed probe is deleted); the trigger is the kernel.read request carrying exactly (region_index, offset, length) with sentinel refusals, the released window pins the compiled row (W13_RELEASE_INDEX_MISMATCH, KREADLIVE_REGION_INDEX_MISMATCH, KREADLIVE_REGION_NOT_COMPILED, KREADLIVE_TRIGGER_NOT_DEFERRED) and a release may bind its payload (W13_RELEASE_PAYLOAD_MISMATCH); the build gate proves the request shape and all seven required mutants fail the build; new payload BIN f7052568..., ELF 5341e1b9..., build id 3b1eccb4983b0870bed2d39928711fa9 (old BIN de9e787d... stays historical evidence); new trust objects W13-C1-READ-1-NEW-PAYLOAD + section 70 approval W13C1-READ-1-20261006T1510Z; the previous release stays consumed; suite 949 passed / 1 skipped. No live step in this wave (no upload, no rearm, port 9090 untouched). | W13-C2 (2026-10-06): WIRE-CATALOG R2 - the kernel.read argument contract was replaced after the live finding that the frozen catalog required addr+size (a raw kernel address from host input, forbidden by the security contract) while a bounded triplet request was an unknown argument set. kernel.read now takes region_index/offset/length, all required integers; addr/address/va/kernel_va/ptr/source/size are never valid arguments again; unknown fields fail closed in the generated validator; operation, capability and route are unchanged, no second operation, no framing change. The trigger reads body.arguments and refuses an unparsable request explicitly as ARGUMENT_INVALID before every bound rule and before any kexec (no sentinels, no defaults; a refusal does not consume the one-shot). New payload BIN 5195568e..., ELF 51da9fa7..., build id 87127919a124f4fa7ae29a857b06e562 (the C1 payload 2a767a88... stays historical evidence); new trust objects W13-C2-READ-1-WIRE-CATALOG-R2 + section 70 approval W13C2-READ-1-20261006T1522Z; the C1 pair is SUPERSEDED / CONSUMED. Required tests: tests/test_w13c2_wire_arguments.py (16) + tests/harness/optable_args_check.c; mutants 7/7 red (C2) and 7/7 build-gate (C1 re-run); suite 965 passed / 1 skipped. No live step in this wave (no upload, no rearm, port 9090 untouched). | W13-C2 LIVE (2026-10-06): the single approved read of amd_iommu / index 1 / 0 / 16 PASSED with checks_failed [] (callback executed, kexec_rc 0, bytes and sha256 exactly the expected ones, resolved RVA 0x7ce9e9, no kernel writes, no host supplied address, release consumed at the provider entry, cleanup COMPLETE, health green); research evidence + dataset blob + snapshot SNAP-831b4707168282cc + W6 input/result (OBSERVATION only, impact.w4 NONE) produced; no second read, no next region, no retry. | W14 (2026-10-06): post-freeze entry for the resident-daemon step - native/target/ps4rf_daemon.{c,h} (life cycle BOOTSTRAP/RESIDENT_IDLE/SESSION_ACTIVE/SESSION_CLEANUP, the single acceptance gate, the per-session boot-input re-check, the per-session resource demand, the boot-wide RECOVERY_REQUIRED flag, the SESSION_BUSY notice and the four exit reasons with ADMIN_SHUTDOWN declared without a producer yet), the checkpoint seam in ps4rf_agent.{c,h}, the --resident mode in ps4rfd_host.c (its --selftest line is valid JSON now), the per-session offline controller tools/hostctl/resident.py, the source gate gate_agent_source() in build_manifest.py, tests/harness/daemon_state_check.c + tests/test_w14_daemon.py (26 tests) and docs/P4-W14-RESIDENT-DAEMON.md. No live step in this wave (no upload, no rearm, loader port untouched); W14 stays NOT DONE (sections 4/6/7/14/15/16/17/18/19 open). | W14B (2026-10-06): review follow-up on the resident daemon, still offline - (a) \u00a714/\u00a74 identity: HELLO carries the W14 identity block (build_id, platform, profile_id, boot_id+instant+status, session_state) with the nonce fresh per session, session.py exposes IDENTITY_FIELDS/agent_identity and resident.py::freshness_report() makes the freshness demands explicit (same identity, own nonce/session id/transcript/key material, recovery only raised, never lowered); (b) \u00a72 isolation: ps4rf_res_teardown() is the single session teardown (releases the set before the BYE reports the cleanup state, refuses a set it cannot attribute to a session), the agent wipes session key material/nonce/session id through agent_finish() on every exit path, and what survives is boot/lifetime scoped only; (c) \u00a74/\u00a75/\u00a711 recovery: ps4rf_daemon_session_recovery_required() is the one mapping from a finished session to a boot state (protocol obligation broken, undelivered answer to a mutating operation, work in flight, leftovers, refused teardown) - a plain EOF/RST is not in it, so a lost transport now ends a session and leaves the boot flag clear, and a leftover object is reaped instead of ending the agent; the router records last_op_mutating at the single dispatch point and the runtime seeds the boot-wide flag into every session (session_state/mutating_allowed visible in session.status, mutating refused before provider entry); (d) \u00a76 dial-out backoff: bounded exponential pause (floor 50 ms, cap 30 s, --backoff-max-ms) with dial misses recorded and no effect on boot/recovery/capability state. Report gains cleanup_reaped/cleanup_refusals/cleanup_state/held_after_cleanup/undelivered_*/dial_misses_total/dial_backoff_us/recovery_source/recovery_transitions; harness daemon_state_check.c extended with the teardown and mapping cases; tests/test_w14_daemon.py 26 -> 33 tests (identity freshness, two-boot recovery persistence, five transport-loss cases, backoff bounds); suite 1000 passed / 1 skipped. No live step, no upload, loader port untouched; W14 stays NOT DONE (sections 6/7/10/11/15/16/17/19 open). | W17 (2026-10-07): post-freeze section for the generic primitive surface (core revision R4: kernel.snapshot.recipe + ioctl.invoke, the experiment layer, the W17F migration that replaced every historical count with set equality against the authoritative surface, the profile operation_policy revision and the D18 entries under R4). Reason for this refreshed pin; no live step.",
      "review_reference": "docs/P4-W0-DECISIONS.md | W9: docs/P4-W9-ATTESTATION.md"
    },
    {
      "core_impact": "no",
      "file": "HERMES-HANDOFF.md",
      "new_sha256": "af8ec70058003157a89e5ef0cceb965a37bf7f9f9ad6aed16b7ada83c2cda6c3",
      "old_sha256": "bc8c2a58e1c4c4c4148ef644f5124a739802795ef4383605c563473ee0ba6463",
      "phase": "P3b / W0 -> W11 -> W11.1",
      "reason": "W11.1 (2026-10-06): status paragraph for the accepted fail-closed W11 live outcome and the diagnostics wave. | status block: core freeze executed, tool layer extended (recon/knowledge adapters), canonical tool order, binding recon pipeline rule | W9 (2026-10-05, commit 2f8324b): status/phase/CHANGELOG updated for the W8-D1 deviation record and the W9 attestation wave (offline half); no core file touched by W9 | W9 window-policy correction (commit with BIN f70fd896...): docs + status files re-stamped | W11 (offline, 2026-10-06, commits 63071a3 + 59c352e): status block for the live userland boot binding - read-only KERN_BOOTTIME collector (PS4RF_TARGET_BOOTID=1), canonical ps4rf.boot-binding.v1 with the W10 draft withdrawn and the capture boot id recomputed (BOOT-bd1e2729373fc597 -> BOOT-19d2c790b0769502), offline end-to-end stable/drift/absent, W5 BOOT_BINDING_MISMATCH -> PROFILE_MATCH, kernel.read stays OPERATION_DEFERRED with the LOCATOR_MISSING triple, plus the hand-stated W9 rebuild drift (shared platform/agent sources changed; frozen packs untouched). Core files untouched by W10/W11. | W11.1A (2026-10-06): host side EVENT capture fix (one shared capture helper + one central frame router; the live evidence branch no longer drops a captured event) - reason for the refreshed pin of this status file; payload unchanged, no live upload.",
      "review_reference": "docs/P4-W0-DECISIONS.md; recon commit b354598 | W9: docs/P4-W9-ATTESTATION.md | W10/W11: docs/P4-W10-PROFILE-PROMOTION.md, docs/P4-W11-BOOT-BINDING.md, evidence pack 20261006T020705Z_ps4rf_p4w11-offline"
    },
    {
      "core_impact": "no",
      "file": "HERMES-TODO.md",
      "new_sha256": "2c519babc8145b60ff50264b65100b47467e2ec30bfb57973421efe70a5cd985",
      "old_sha256": "34cde8ae724eb9ace50329b698757357f8f129e0505e9a3625fe584f64b8db05",
      "phase": "P3b -> W9 -> W11 -> W11.1 -> W12 -> W12-RVA0 -> W12-A-D1 -> W12-A2 -> W12-A3 -> W13 -> W13 release gate -> W13 separation -> W13-C1 -> W13-C2 -> W14 -> W14B",
      "reason": "W13 (2026-10-06): post-freeze entry for the read-only research baseline - new tools/research package (classification, read plan, dataset, pointer follow, W6 contract), docs/P4-W13-READ-ONLY-RESEARCH-BASELINE.md, 54 new tests + 5 module self-tests, status W13 OFFLINE READY (no live step); W12 closed with milestone tag PS4RF-KERNEL_READ_L1-VERIFIED. W12-A3 (2026-10-06): post-freeze entry for the verification-derived assurance gate - derive_capability_record() is addressed by the evidence hash and re-establishes every fact from the stored record before it stamps PROVEN, the store gains load_verification_by_sha256(), the phase-B path revalidates the derivation immediately before the provider entry (KREADLIVE_CAPABILITY_NOT_DERIVED), F7 and the chain are untouched, 18 + 18 regressions green, status W12 READ LIVE READY R2 (phase B needs its own approval, window pin and rearm). W12-A2 (2026-10-06): the NATIVE assurance consistency check is closed offline (verification-derived assurance: NATIVE alone OBSERVED/DEFERRED, PROVEN only via the separate store-bound VerificationEvidence; documented and pinned by 18 regressions; no bypass found, no production code changed). | W12 phase A live attempt #2 VERIFIED and owner-approved (22/22 criteria, one persisted record, zero generic provider entries) and the A-D1 fix round recorded. | W12-A-D1 (2026-10-06): the first phase A live attempt is recorded (one upload, read byte/hash-exact, evidence refused by one host check, nothing persisted/promoted) and closed by the host-side fix - regions.compiled_regions() is the normative target table (count, order, index mapping, payload parity), the verifier and the simulation use it, the table fails closed, 18 pinned regressions + mutation guard, suite 799/1/0, status W12 VERIFY LIVE READY R2 (phase A repeat needs a new rearm). | W12-RVA0-BINDING (2026-10-06): the blocked pinned rva-0 window item is closed as a domain-modelling fix (rva 0 is a valid relative locator; the runtime address keeps its non-zero/canonical domain and is validated at resolution with the current boot base) - status W12 VERIFY LIVE READY (phase A only), two-phase release rule restated, payload and profile unchanged. | W12 (2026-10-06): offline W12 live prerequisites closed and the open live seam recorded - (a) session.py knows+validates the payload event kernel.read.bounded / ps4rf.kernel.read.bounded.v1; (b) host driver tools/hostctl/kreadlive.py for the approved two-run flow (bootstrap verify -> VerificationEvidence -> W4/W5/W7 -> one generic bounded read in a new run id) with ps4rfctl phase flags, tests/test_kreadlive.py and a byte-stable offline end-to-end simulation; plus the blocked RUN B window (the frozen W5 addr domain admits only > 0 and refuses the pinned rva-0 image_elf window with PROFILE_UNBOUND, zero provider entries) as a named TODO with owner files and the decision needed. | W11.1 (2026-10-06): TODO section for the diagnostics wave and the post-diagnosis decision. | new phase P3b (recon & privesc knowledge adapters), canonical tool order after the freeze, recon pipeline rule | W9 (2026-10-05, commit 2f8324b): status/phase/CHANGELOG updated for the W8-D1 deviation record and the W9 attestation wave (offline half); no core file touched by W9 | W11 (2026-10-06): TODO section for the live userland boot binding (offline done, live pending rearm) and the remaining kernel.read decision. | W11.1A (2026-10-06): host side EVENT capture fix (one shared capture helper + one central frame router; the live evidence branch no longer drops a captured event) - reason for the refreshed pin of this status file; payload unchanged, no live upload.; W13 release gate for the first research read (owner decision A: dedicated --w13-release record; bootstrap evidence binding unchanged; non-released non-bootstrap windows refused); W13 trust-object separation (section 70 approval vs research release) and one-shot release consumption | W13-C1 (2026-10-06): post-freeze entry for the bounded region request plumbing - the payload no longer picks the read region (the fixed probe is deleted); the trigger is the kernel.read request carrying exactly (region_index, offset, length) with sentinel refusals, the released window pins the compiled row (W13_RELEASE_INDEX_MISMATCH, KREADLIVE_REGION_INDEX_MISMATCH, KREADLIVE_REGION_NOT_COMPILED, KREADLIVE_TRIGGER_NOT_DEFERRED) and a release may bind its payload (W13_RELEASE_PAYLOAD_MISMATCH); the build gate proves the request shape and all seven required mutants fail the build; new payload BIN f7052568..., ELF 5341e1b9..., build id 3b1eccb4983b0870bed2d39928711fa9 (old BIN de9e787d... stays historical evidence); new trust objects W13-C1-READ-1-NEW-PAYLOAD + section 70 approval W13C1-READ-1-20261006T1510Z; the previous release stays consumed; suite 949 passed / 1 skipped. No live step in this wave (no upload, no rearm, port 9090 untouched). | W13-C2 (2026-10-06): WIRE-CATALOG R2 - the kernel.read argument contract was replaced after the live finding that the frozen catalog required addr+size (a raw kernel address from host input, forbidden by the security contract) while a bounded triplet request was an unknown argument set. kernel.read now takes region_index/offset/length, all required integers; addr/address/va/kernel_va/ptr/source/size are never valid arguments again; unknown fields fail closed in the generated validator; operation, capability and route are unchanged, no second operation, no framing change. The trigger reads body.arguments and refuses an unparsable request explicitly as ARGUMENT_INVALID before every bound rule and before any kexec (no sentinels, no defaults; a refusal does not consume the one-shot). New payload BIN 5195568e..., ELF 51da9fa7..., build id 87127919a124f4fa7ae29a857b06e562 (the C1 payload 2a767a88... stays historical evidence); new trust objects W13-C2-READ-1-WIRE-CATALOG-R2 + section 70 approval W13C2-READ-1-20261006T1522Z; the C1 pair is SUPERSEDED / CONSUMED. Required tests: tests/test_w13c2_wire_arguments.py (16) + tests/harness/optable_args_check.c; mutants 7/7 red (C2) and 7/7 build-gate (C1 re-run); suite 965 passed / 1 skipped. No live step in this wave (no upload, no rearm, port 9090 untouched). | W13-C2 LIVE (2026-10-06): the single approved read of amd_iommu / index 1 / 0 / 16 PASSED with checks_failed [] (callback executed, kexec_rc 0, bytes and sha256 exactly the expected ones, resolved RVA 0x7ce9e9, no kernel writes, no host supplied address, release consumed at the provider entry, cleanup COMPLETE, health green); research evidence + dataset blob + snapshot SNAP-831b4707168282cc + W6 input/result (OBSERVATION only, impact.w4 NONE) produced; no second read, no next region, no retry. | W14 (2026-10-06): post-freeze entry for the resident-daemon step - native/target/ps4rf_daemon.{c,h} (life cycle BOOTSTRAP/RESIDENT_IDLE/SESSION_ACTIVE/SESSION_CLEANUP, the single acceptance gate, the per-session boot-input re-check, the per-session resource demand, the boot-wide RECOVERY_REQUIRED flag, the SESSION_BUSY notice and the four exit reasons with ADMIN_SHUTDOWN declared without a producer yet), the checkpoint seam in ps4rf_agent.{c,h}, the --resident mode in ps4rfd_host.c (its --selftest line is valid JSON now), the per-session offline controller tools/hostctl/resident.py, the source gate gate_agent_source() in build_manifest.py, tests/harness/daemon_state_check.c + tests/test_w14_daemon.py (26 tests) and docs/P4-W14-RESIDENT-DAEMON.md. No live step in this wave (no upload, no rearm, loader port untouched); W14 stays NOT DONE (sections 4/6/7/14/15/16/17/18/19 open). | W14B (2026-10-06): review follow-up on the resident daemon, still offline - (a) \u00a714/\u00a74 identity: HELLO carries the W14 identity block (build_id, platform, profile_id, boot_id+instant+status, session_state) with the nonce fresh per session, session.py exposes IDENTITY_FIELDS/agent_identity and resident.py::freshness_report() makes the freshness demands explicit (same identity, own nonce/session id/transcript/key material, recovery only raised, never lowered); (b) \u00a72 isolation: ps4rf_res_teardown() is the single session teardown (releases the set before the BYE reports the cleanup state, refuses a set it cannot attribute to a session), the agent wipes session key material/nonce/session id through agent_finish() on every exit path, and what survives is boot/lifetime scoped only; (c) \u00a74/\u00a75/\u00a711 recovery: ps4rf_daemon_session_recovery_required() is the one mapping from a finished session to a boot state (protocol obligation broken, undelivered answer to a mutating operation, work in flight, leftovers, refused teardown) - a plain EOF/RST is not in it, so a lost transport now ends a session and leaves the boot flag clear, and a leftover object is reaped instead of ending the agent; the router records last_op_mutating at the single dispatch point and the runtime seeds the boot-wide flag into every session (session_state/mutating_allowed visible in session.status, mutating refused before provider entry); (d) \u00a76 dial-out backoff: bounded exponential pause (floor 50 ms, cap 30 s, --backoff-max-ms) with dial misses recorded and no effect on boot/recovery/capability state. Report gains cleanup_reaped/cleanup_refusals/cleanup_state/held_after_cleanup/undelivered_*/dial_misses_total/dial_backoff_us/recovery_source/recovery_transitions; harness daemon_state_check.c extended with the teardown and mapping cases; tests/test_w14_daemon.py 26 -> 33 tests (identity freshness, two-boot recovery persistence, five transport-loss cases, backoff bounds); suite 1000 passed / 1 skipped. No live step, no upload, loader port untouched; W14 stays NOT DONE (sections 6/7/10/11/15/16/17/19 open).",
      "review_reference": "recon commit b354598 | W9: docs/P4-W9-ATTESTATION.md"
    },
    {
      "core_impact": "no",
      "file": "TOOLS.md",
      "new_sha256": "f9ef5f1e973c8866cc0189a031746ccf9af6ad9335540dbc4eebc1685a9be1d0",
      "old_sha256": "c85e6485dd9f653edf6e6557990fae6723ea39eb680965011cb9c723d0ea1628",
      "phase": "P3b",
      "reason": "status legend + matrix for the three new adapters (PEASS v0.1, GTFOBins v0.1, unix_privesc v0.1) and the PLANNED tool list",
      "review_reference": "recon commit b354598"
    },
    {
      "core_impact": "yes",
      "file": "core/capabilities/catalog.json",
      "new_sha256": "6b24f62e71033247f7c141fcfecdc0fdbc6c62f4359adbb9c47ab741b09c6525",
      "old_sha256": "f36e55d55ee5bce48d6f64084ed8ee8c0970325296ef75a703e1a97b4e8d4970",
      "phase": "W17E (generic primitive surface)",
      "reason": "W17E (2026-10-07): CORE REVISION R4 - the authoritative capability name list gains ioctl.invoke, the capability of the new generic ioctl primitive (a permitted device/command pair is the authorisation; the device policy itself lives in the compiled ioctl policy table, native/target/ps4rf_ioctl_policy_data.h). This is the final catalog digest of the W17 revision. The catalog stays a plain name list and carries no route or provider authority - that authority stays single-sourced in tools/dispatch/matrix.py and is deliberately not duplicated here.",
      "review_reference": "docs/P4-W17-PRIMITIVE-MIGRATION.md",
      "revision": "R4 (W17E generic primitives)"
    },
    {
      "core_impact": "yes",
      "file": "core/models/capability.py",
      "new_sha256": "2052a9e623f7e243b0a29640c50e0c9e3ce30e6d2fe23aa35b0ef3a06f4deb51",
      "old_sha256": "2d999bc7d515fe0d2969b7ca7d20a076849efeea34a14d21fe9c047340b1708c",
      "phase": "W7 / F7",
      "reason": "W7/F7 integration patch, minimal: one conservative authority rule for ProviderType.NATIVE (max_assurance OBSERVED, availability write allowed, availability_rank 25). The ceiling is OBSERVED on purpose: the mere existence of a native provider can never produce PROVEN - PROVEN remains reachable only through the frozen VerificationEvidence path. No other rule, minimum or rank changed.",
      "review_reference": "docs/P4-PROVIDER-WIRING.md (F7 integration patch); CHANGELOG.md W7 entry",
      "revision": "R2 (F7)"
    },
    {
      "core_impact": "yes",
      "file": "core/models/common.py",
      "new_sha256": "0ba8970529c8abda8e83d2cd9fbec302c8d0a5973a32d6a986e43e00c899aa38",
      "old_sha256": "7163f308407edafe33fafb0f4d9de4248e9bfde231b147714661c65ef2133ed9",
      "phase": "W7 / F7",
      "reason": "W7/F7 integration patch, minimal: ProviderType gains the member NATIVE. The W4 requirement table already names NATIVE as an allowed provider for the deferred-privilege operations, but the frozen enum could not express it, so no native provider record was representable at all. Exactly one enum member added, no other change.",
      "review_reference": "docs/P4-PROVIDER-WIRING.md (F7 integration patch); CHANGELOG.md W7 entry",
      "revision": "R2 (F7)"
    },
    {
      "core_impact": "yes",
      "file": "core/rpc/registry.py",
      "new_sha256": "d544609f3ac28b4a1f851f5cf777405e7fe26629febca1c8541aa9fc348af42c",
      "old_sha256": "788ef091bcf9e3f2664a7956941ebaaa575560345cf002592e8d7faacad5cc7c",
      "phase": "W0 / R1 -> W9 -> W11 -> W11.1 -> W12 -> W12-RVA0 -> W12-A-D1 -> W12-A2 -> W12-A3 -> W13 -> W13 release gate -> W13 separation -> W13-C1 -> W13-C2 -> W14 -> W14B -> W17E (generic primitive surface)",
      "reason": "W14B (2026-10-06): CORE REVISION R3 - wire catalogue revision R4 adds exactly one operation, session.shutdown (the W14 \u00a715 authenticated admin shutdown, owner-instructioned in the W14B review). OperationSpec('session.shutdown', None, False, True): read-only (it releases the session's resources and ends the agent's lifetime - no kernel state, no reboot, no loader, no persistence), recovery-safe by policy, and deliberately capability-free because capability-bearing operations are the privileged ones and are never wired on the target agent (the generator's invariant). The authorisation is the authenticated session plus one required argument, capability, whose only admitted value is session.admin (pinned in the provider as PS4RF_SESSION_SHUTDOWN_CAPABILITY); the operation is served only in the resident mode and refuses OPERATION_DEFERRED everywhere else, so the single-session profiles keep exactly the served set they had. Counts move with it: registry 35 -> 36, target wired 16 -> 17, stub routes 16 -> 17, argument rows 49 -> 50. No other core file changed; no live step (no upload, no rearm, loader port untouched). | W17E (2026-10-07): CORE REVISION R4 - the generic primitive surface. Exactly two operations were added to the frozen registry: kernel.snapshot.recipe (OperationSpec('kernel.snapshot.recipe','kernel.read')) and ioctl.invoke (OperationSpec('ioctl.invoke','ioctl.invoke')). Both are read-class, provider-bound primitives driven by the experiment layer: the recipe form carries a profile-defined recipe_ref plus bounded indices (no raw address is expressible), the ioctl form an explicit device policy plus a command allowlist with fixed 24-byte argument blocks (no arbitrary kernel call). Counts move with it: registry 36 -> 38, target wired 17 -> 19, target deferred 18 -> 19, argument rows 50 -> 55. The planned op revision R5 (de-aliasing kernel.snapshot onto the recipe form together with the W15 release/index-bound/response-form machinery) is prepared but NOT applied: kernel.snapshot keeps its frozen alias and its deferred target route. No live step (no upload, no console contact, the loader port is untouched).",
      "review_reference": "docs/P4-W14-RESIDENT-DAEMON.md (R3); CHANGELOG | W17E: docs/P4-W17-PRIMITIVE-MIGRATION.md",
      "revision": "R4 (W17E generic primitives)"
    },
    {
      "core_impact": "yes",
      "file": "core/rpc/handshake.py",
      "new_sha256": "ac745544a65364623c7b41d3255f5ed5d0f601075155a6a4d3b1b53dd3d105bd",
      "old_sha256": "497a77a9021773a51faee5d981920d07e1d4ab1a3285122190952e4c0ba4d203",
      "phase": "W0 / R1",
      "reason": "Core/Wire Revision R1: EFFECTIVE_LAST_SEQ = 2**53-1 enforced in seal()/open() with fail-close SequenceExhausted and no wraparound (D8); shared helper open_authenticated maps InvalidTag to AuthenticationFailed so no library exception escapes the RPC layer (D9)",
      "review_reference": "docs/P4-W0-DECISIONS.md (D8, D9); regenerated catalogs tests/fixtures/crypto + tests/fixtures/parity",
      "revision": "R1 (D8, D9, D12)"
    },
    {
      "core_impact": "no",
      "file": "pyproject.toml",
      "new_sha256": "41b628277db93766d23c826581efe65e4af0d19400d47d1cbdf2d4f1865a98bd",
      "old_sha256": "5307ba2898cbca7c9bec1a9f82b841644d0ef9c8d6457e87287d05142148b4da",
      "phase": "P2 -> P0-A1 (independent audit 1328aa5)",
      "reason": "declared the offline adapter dependency msgpack>=1.0 (msfrpcd MessagePack-RPC client, mock-only usage) | P0-A1 (2026-11-05): declared the disassembly dependency capstone>=5. tools/discovery decodes kernel code through capstone, so four discovery test modules failed at collection in a clean environment while the requirement was undeclared (audit finding A1-10). Declared as a runtime dependency, not a dev extra, because the analysis surface imports it. No version pin was moved and no other dependency changed. | A1-10 follow-up: the requirement is now bounded (capstone>=5,<6) and an offline install path is documented, because an open lower bound is not a pin and the audit's container had neither the package nor an index.",
      "review_reference": "P2 phase (metasploit adapter), commit b264527 | PS4RF independent audit A1, finding A1-10"
    },
    {
      "core_impact": "no",
      "file": "schemas/profile.schema.json",
      "new_sha256": "273d81e9a2e6d858009d39615cf6f8c9603de20537cfbb6f9858ce82e029dd08",
      "old_sha256": "e00ee7da37894ca98e78914be942040b1b89d68ebc125727a0965b7404afb9c7",
      "phase": "W5",
      "reason": "W5 profile schema: strict key allowlist (no runtime address expressible), target identity, locator facts with provenance/confidence, explicit per-operation profile policy",
      "review_reference": "docs/P4-PROFILE-BINDING.md"
    },
    {
      "core_impact": "no",
      "file": "tools/metasploit/adapter.py",
      "new_sha256": "668581416ee6c5909fb512dffff44f9554b159933d8c22b48e7bff0c5ef9909e",
      "old_sha256": "577925495bb64700af01a8487ae9321fe010f585a4077631527d1517be7b8dc8",
      "phase": "P2",
      "reason": "P2 adapter work: mock-first msfrpcd bindings, single-attempt contract, redaction by construction",
      "review_reference": "P2 phase, commit b264527"
    },
    {
      "core_impact": "no",
      "file": "tools/metasploit/mock/msfrpcd_mock.py",
      "new_sha256": "e5ed9de31f135217ac1aaf1ab529f6cbdca9c682bd0966b8430ca9ade72c2c1e",
      "old_sha256": "a33aa228b88fd45d2d57437017b062cac1448370114b2756c7d0ecb50f33eb8e",
      "phase": "P2",
      "reason": "P2 mock hardening: loopback-only msfrpcd mock, token from env per call, never logged",
      "review_reference": "P2 phase, commit b264527"
    },
    {
      "core_impact": "no",
      "file": "tools/metasploit/provider.py",
      "new_sha256": "515da9f6dc35cf0745c6562a51c9efd82be13cb5d6bc6da2c01b6a6d70d92b73",
      "old_sha256": "921aa73c24e1eafc4dab66b13f0c441e8832820e7bf3b2dde382eebd2bb26bcc",
      "phase": "P2",
      "reason": "provider manifest bridge (spec v0.3 \u00a712.2/\u00a712.3): module manifest validation, reliability sum invariant, execution-context mapping, verify.* requirement for privileged capabilities",
      "review_reference": "P2 phase, commit b264527"
    }
  ],
  "manifest": {
    "entries_total": 95,
    "freeze_commit": "1536e35fcb7a67e7fe3150ab148304c501944b08",
    "freeze_tag": "PS4RF-CORE-1.0-MOCK-READY",
    "manifest_sha256": "447513cbd4fc63048906a448e7bc0fcff195c9a5e33d9135b6f9e381abcfa1f6",
    "path": "SHA256SUMS",
    "policy": "re-freeze only with the next planned core/wire revision (W0/D18)"
  },
  "revision": "R1 (D8, D9, D12); R2 (F7); R3 (wire catalogue R4); R4 (W17E generic primitives)",
  "revisions": {
    "R1 (D8, D9, D12)": "docs/P4-W0-DECISIONS.md",
    "R2 (F7)": "docs/P4-PROVIDER-WIRING.md",
    "R3 (wire catalogue R4)": "docs/P4-W14-RESIDENT-DAEMON.md",
    "R4 (W17E generic primitives)": "docs/P4-W17-PRIMITIVE-MIGRATION.md"
  }
}
```

## Summary

| file | phase | core | reason (short) |
|---|---|---|---|
| `HERMES-HANDOFF.md` | P3b/W0 | no | status block after freeze + tool layer |
| `HERMES-TODO.md` | P3b -> W12-A-D1 | no | phase P3b + tool order + pipeline rule; W12 prerequisites closed; W12-RVA0-BINDING fixed; phase A attempt #1 recorded (W12-A-D1) + host fix + `W12 VERIFY LIVE READY R2` |
| `TOOLS.md` | P3b | no | adapter status matrix |
| `CHANGELOG.md` | W0/R1 -> W12-A-D1 | no | post-freeze section (P3b, W0, R1, W1); W12 offline host driver + W12-RVA0-BINDING + W12-A-D1 (compiled table vs policy registry) |
| `core/rpc/handshake.py` | W0/R1 | **yes** | D8 ceiling enforcement, D9 auth mapping |
| `core/rpc/registry.py` | W14B/R3 -> W17E/R4 | **yes** | wire catalogue R4: `session.shutdown` (read-only, recovery-safe, capability-free) added to the frozen registry; W17E: the two generic primitives `kernel.snapshot.recipe` and `ioctl.invoke` (registry 36 -> 38) |
| `core/capabilities/catalog.json` | W17E/R4 | **yes** | the authoritative capability name list gains `ioctl.invoke` (final W17 catalog digest; no route/provider authority in the catalog) |
| `pyproject.toml` | P2 | no | msgpack dependency |
| `tools/metasploit/adapter.py` | P2 | no | mock-first msfrpcd adapter |
| `tools/metasploit/mock/msfrpcd_mock.py` | P2 | no | loopback mock hardening |
| `tools/metasploit/provider.py` | P2 | no | provider manifest bridge |
| `schemas/profile.schema.json` | W5 | no | strict profile schema (key allowlist, locator facts, op policy) |
| `core/models/common.py` | W7/F7 | **yes** | `ProviderType.NATIVE` member added (F7) |
| `core/models/capability.py` | W7/F7 | **yes** | conservative NATIVE authority rule, ceiling OBSERVED (F7) |

9 non-core files drifted with documentation; the five core files above are the
only core drift since the freeze: one under revision R1 (D8/D9/D12,
`core/rpc/handshake.py`), two under revision R2 (the W7/F7 integration patch,
`docs/P4-PROVIDER-WIRING.md`), one under revision R3 (`core/rpc/registry.py`,
wire catalogue revision R4, the W14 §15 authenticated admin shutdown,
`docs/P4-W14-RESIDENT-DAEMON.md`) whose entry now also carries revision R4, and
the W17E pair under revision R4 — `core/rpc/registry.py` again (the two generic
primitives) and `core/capabilities/catalog.json` (the capability name list),
`docs/P4-W17-PRIMITIVE-MIGRATION.md`.
`SHA256SUMS` itself is byte-identical to the freeze (`447513cb…`).
