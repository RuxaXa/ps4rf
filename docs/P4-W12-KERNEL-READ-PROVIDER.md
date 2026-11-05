# P4 W12 — First Bounded `kernel.read` Provider Promotion (offline first)

Status: offline work in progress. **Nothing live until a separately approved live gate.** No writes,
no arbitrary reads, no new privileged surface beyond one bounded read callback.

## Mandate → implementation map

| Mandate | Where |
| --- | --- |
| §1 no arbitrary read: request is `region` / `offset` / `length`, region must come from the active W5 profile, never a raw kernel VA | `tools/profiles/kread.py` (request model), `tools/profiles/regions.py` (registry) |
| §2 bounds: max single read 4096, no negative length, no overflow arithmetic, no wraparound, no cross-region read, `locator + bounded offset` fully inside the region | `tools/profiles/kread.py` |
| §3 allowlist: only already-proven FW13.52 read regions; nothing invented; `aperture_global` is `STRUCTURAL_ONLY` and may not serve as a STRICT identity source; anything not sufficiently proven → `UNRESOLVED` → no read | `tools/profiles/regions.py` |
| §4 capability gate path `REQUEST → Registry → Capability Resolution → effective_grant → W4 Gate → W5 Profile Binding → Boot Binding → W7 Provider Router → native provider`, no bypass, all preconditions | `tools/profiles/kread_capability.py` |
| §5 the W11.2 boottime read is boot-binding evidence, not `kernel.read = PROVEN`; a separate verification flow decides that | `tools/hostctl/kreadverify.py` |
| §6 `ProviderType.NATIVE` yields at most `OBSERVED`; `PROVEN` only via `VerificationEvidence` (F7 policy unchanged) | `kread_capability.py`, `kreadverify.py` |
| §7 the provider receives validated inputs (region id, resolved VA internally, offset, length, bindings, context) and decides no authority | `native/target/ps4rf_kread.c` + adapter |
| §8 one bounded read callback, no writes, no function pointer from host, no arbitrary kernel call, no retry loop | `native/target/ps4rf_kread.c` |
| §9 offline safety gates before live (max length, checked addition, canonical address, containment, no writes/indirect calls/syscall-table/persistent changes, no GPUVM/KeyMgr/CCP/SAMU, reproducible build, manifest hashes) | `native/target/build_manifest.py::gate_kread` |
| §10 negative tests (11 cases) and §11 positive tests | `tests/test_kread_*.py`, `tests/harness/kread_offline.c` |
| §12 resource/evidence fields per read | `kreadverify.py`, `tools/hostctl/evidence.py` |
| §13 W6 differential findings never auto-enter the allowlist (explicit W5/profile review only) | registry doc note |
| §14 health probe correction (`health:port-3232-connect`, `log_activity_observed` outside the verdict) | `tools/hostctl/cli.py::live_health` (done, `tests/test_live_health.py`) |
| §15 deliverable `W12 OFFLINE READY` with commit, hashes, regions, max read, verification plan, matrices, W2→W12 regression, evidence pack | this doc + evidence pack |
| §16 still forbidden: `kernel.write`, arbitrary `kernel.call`, full kernel dump, GPUVM, KeyMgr, CCP, SAMU, SBRAM, EAP/EMC, PUP, fuzzing, races | manifest gate assertions + this doc |

## Frozen interfaces for this wave

**Request (wire-visible shape).** Exactly these keys, nothing else:

```json
{"operation": "kernel.read", "region": "<region name>", "offset": 0, "length": 16}
```

A request carrying any address-ish field (`addr`, `address`, `va`, `kva`, `pointer`, `ptr`) is a
**schema reject**, never a fallback. There is no `region` value that means "raw".

**Registry** (`tools/profiles/regions.py`):

* `Region(name, rva, length, identity_status, sources, notes)`; `IDENTITY_STRICT = 'STRICT_FINGERPRINT'`,
  `IDENTITY_STRUCTURAL_ONLY = 'STRUCTURAL_ONLY'`, `IDENTITY_UNRESOLVED = 'UNRESOLVED'`
* `MAX_READ_LEN = 4096`
* `regions() -> dict[str, Region]`, `get_region(name) -> Region | None`
* `resolve_read(region_name, offset, length) -> ResolvedRead(address, rva, offset, length, region)`
  which raises `KReadReject(reason)` — reasons: `KREAD_UNKNOWN_REGION`, `KREAD_UNRESOLVED_REGION`,
  `KREAD_NEGATIVE_OFFSET`, `KREAD_OFFSET_OVERFLOW`, `KREAD_LENGTH_ZERO`,
  `KREAD_LENGTH_EXCEEDS_MAX`, `KREAD_CROSS_REGION`, `KREAD_NON_CANONICAL_ADDRESS`

**Capability path** (`tools/profiles/kread_capability.py`):

* `decide(request, *, registry, profile, boot_binding, context, capability, recovery, provider) -> GateDecision`
* `GateDecision(outcome='GRANTED'|'REJECTED'|'DEFERRED', stopped_at, reasons, effective_grant, resolved, provider_entry)`
* `provider_entry` is true exactly once and only on `GRANTED`; every refusal names the stage it
  stopped at. Reasons: `KREAD_STALE_BOOT_ID`, `KREAD_WRONG_PROFILE`, `KREAD_VERIFICATION_MISSING`
  (deferred), `KREAD_NATIVE_OBSERVED_ONLY` (deferred), `KREAD_MOCK_PROVEN` (W4 reject),
  `KREAD_RECOVERY_REQUIRED` (no provider entry), plus the schema/registry reasons above.

**Verification** (`tools/hostctl/kreadverify.py`):

* `verify_read_evidence(request, evidence, *, profile, boot_binding, expected) -> report` with
  `verified`, `outcome`, `problems`, `requirement_before`/`requirement_after`, `resolved_address_in_evidence`
  and `request_contained_address: false` — the resolved address lives in evidence only.
* Requirement can move to `PROVEN` only when the verification run is separate (W4/F1 run separation)
  and every field matches: region, requested length, observed byte count, output SHA-256,
  `profile_sha256`, `boot_id`, provider identity.

## Integration review checklist (wave owner, binding for the integration pass)

These are the acceptance points the integration pass must verify one by one; each refusal must stop
**before kernel entry**.

1. **Request schema** exactly `operation`, `region`, `offset`, `length`. No `address`, `va`,
   `kernel_address`, `ptr` or equivalent raw-address input. Unknown fields **fail closed**.
2. **Region registry**: every region explicitly carries region id, profile locator, max size, policy,
   provenance and profile requirement. Only `STRICT_FINGERPRINT` (or explicitly approved bounded
   *research* regions) become readable; `STRUCTURAL_ONLY` is not automatically readable;
   `UNRESOLVED` never. `aperture_global` stays `STRUCTURAL_ONLY` and must not silently turn into a
   trusted identity/read region through W12.
3. **Bounds**: checked arithmetic for `region_base + offset`, `offset + length` and
   `resolved_start + length`; no wraparound; `length` in `1..4096`; the read must lie entirely inside
   **one** region.
4. **Profile + boot binding**: provider entry only when the current `profile_sha256` **and** the
   current boot id **and** the runtime binding all belong to the current target. A stale boot binding
   stops before `kexec`.
5. **Capability / verification**: `NATIVE` stays at most `OBSERVED`; a working native read does not
   prove `PROVEN`. The separate verification run must bind known region, known expected bytes/hash,
   current `profile_sha256`, current boot id, provider identity and the observed bytes. Trigger run
   and verification run are separated for privileged capabilities.
6. **No bootstrap circle**: the capability may not already require `PROVEN kernel.read` in order to
   run `verify.kernel.read`. The narrow bootstrap verify path is: fixed verification region +
   compile/profile-bound locator + fixed bounded expected length → `VerificationEvidence`. Only then
   generic bounded, region-based `kernel.read`. No arbitrary read capability before a passing
   verification.
7. **Callback**: exactly a bounded copy from the resolved, validated source into the payload's own
   result buffer. No kernel writes, no arbitrary call, no host function pointer, no dynamic kernel
   function, no retry loop, no second primitive in the same callback.
8. **`syscall_handler` ABI**: the real target ABI is checked in the manifest **and** the harness; no
   host-ABI assumptions. Arguments are fully validated before kernel entry.
9. **Guard**: the one-shot/execution guard is set before `kexec`; a host retry cannot produce a second
   kernel invocation in the same payload.
10. **Evidence**: `requested_region`, `requested_offset`, `requested_length` **and** separately
    `resolved_rva` and `resolved_runtime_va`; the runtime VA is evidence only and never originates
    from the request.
11. **Mutants** (each must stop before kernel entry): raw address field smuggled in; `length 4097`;
    `length 0`; `offset` exactly `region_end`; `offset + length` one byte over; u64 overflow; stale
    boot id; foreign `profile_sha256`; `STRUCTURAL_ONLY` presented as `STRICT`; `UNRESOLVED` region;
    `NATIVE OBSERVED` without verification; forged `VerificationEvidence`; `MOCK PROVEN`; recovery
    between accept and provider entry.
12. **Positive verification**: at least one fully offline reproducible path — fixed known bytes →
    native bounded read → host re-derived hash → separate verify run → `VerificationEvidence` PASS →
    `kernel.read` reaches the assurance the W4 gate demands. Documented labels: before verify
    `DEFERRED`, after verify `ELIGIBLE`, and the live provider stays **not automatically executed**
    until an explicit live approval.
13. **Manifest gates** before `W12 OFFLINE READY`: max read 4096; no kernel write primitive; no raw
    address inputs; no arbitrary call; no GPUVM; no KeyMgr; no CCP; no SAMU; no persistence;
    reproducible build; provider-matrix parity; W4/W5/W7 gate parity; health regression green; full
    W2→W12 suite green.
14. **Stop** after the integration: `W12 OFFLINE READY` with commit, provider SHA-256, BIN, ELF,
    manifest, build id, allowed regions, region policy matrix, `MAX_READ_LEN`, verification bootstrap
    contract, negative matrix, mutant results, full suite and evidence pack. No upload, no rearm,
    port 9090 untouched.

## Single normative source (no second truth)

| Policy area | Sole owner | Nobody else may re-implement it |
| --- | --- | --- |
| Bounds (checked arithmetic, `1..4096`, one-region containment, canonical check) | `tools/profiles/kread.py` | tests and consumers import `MAX_READ_LEN` and the validators instead of repeating a number or a rule |
| Region policy (identity status, readability policy, profile requirement, locator, max size, provenance) | `tools/profiles/regions.py` | the payload gets its table from the generator output, never from a hand-written list |
| Capability decision (REQUEST → Registry → Capability Resolution → effective_grant → W4 → W5 → Boot Binding → W7) | `tools/profiles/kread_capability.py` | `kreadverify.py` and the CLI call it, they do not re-decide |
| Verification (`VerificationEvidence`, run separation, assurance transition) | `tools/hostctl/kreadverify.py` | no other module may mint or accept a verification claim |
| Provider entry | `tools/profiles/kread_capability.py` (the outcome field) | a provider is entered only via a `GRANTED` decision; nothing infers entry from a read having happened |
| Resource ownership | `tools/hostctl/evidence.py` + the session's single-reader accounting | no ad-hoc evidence dicts outside those paths |

Integration pass rules:

* the runtime kernel address is derived **internally** from the active W5 profile locator + the current
  boot binding + the approved region + the validated offset; it may appear in evidence
  (`resolved_rva`, `resolved_runtime_va`) and nowhere else;
* mutants must be run against the **assembled production path** after integration, not only against
  the individual packages;
* `W12 OFFLINE READY` is reported only when mutants, manifest gates and the full W2→W12 regression are
  green — with commit, provider SHA-256, BIN/ELF/manifest SHA-256, build id, allowed-region matrix,
  `MAX_READ_LEN`, bootstrap verification contract, assurance state before/after verify, the complete
  negative matrix, mutant results, W4/W5/W7 parity, the full suite and the evidence pack. No live
  upload, no rearm, port 9090 untouched.

## Open items

* provider payload module, agent hook and build profile still to be wired for the offline harness
* offline matrices, full W2→W12 regression, evidence pack, `W12 OFFLINE READY` report


## Pre-live closure (W12 LIVE READY)

The pre-live review required seven offline closures; all are delivered.

**Bootstrap verification region.** Exactly one region is named: `image_elf` (RVA `0x0`, 16 bytes,
STRICT_FINGERPRINT, promoted locator `kernel.attest.image_elf`, expected bytes
`7f454c46020101090000000000000000`, expected sha256 `7ef1ae26…`). It is the runner-up of the
pre-live filter and it is the region the **accepted, hash-frozen payload** actually reads: its live
trigger takes the first STRICT row of the generated region table, which is `image_elf` (index 0).
Naming that same region host-side keeps the accepted BIN byte-identical; switching the payload to
`xfast_entry` would be a payload change and needs a fresh artefact review.

> **Superseded by W13-C1** (`docs/P4-W13C1-BOUNDED-REGION-REQUEST.md`): the payload no longer
> picks the region. The trigger is the `kernel.read` request carrying
> `(region_index, offset, length)`; the compiled table row is chosen by the released window, the
> probe above was deleted, and a new payload build has been reviewed offline. The W12 live run and
> its BIN `de9e787d…` stay historical evidence.
(Original pick `xfast_entry` — RVA `0x1C0`, 8 bytes,
STRICT_FINGERPRINT, promoted locator `kernel.attest.xfast_entry`, expected bytes `0f01f86548892425`,
expected sha256 `67bde943…`). It is the window the kbase derivation points at (`kbase = LSTAR - 0x1C0`),
so the bootstrap read also confirms the derivation the provider depends on, and it is pinned code, not
mutable data. Every other STRICT region also qualifies but was not chosen; `boottime` is explicitly
**not** the bootstrap region because it has no promoted W5 locator, so it stays DEFERRED for the
generic provider. `aperture_global` (STRUCTURAL_ONLY) and both UNRESOLVED regions are excluded. The
per-region filter table is in the pre-live pack (`bootstrap-qualification.txt`).

**Contracts.** Bootstrap verification: fixed region + compile/profile-bound locator + fixed bounded
length + expected bytes/hash + current `profile_sha256` + current boot id -> `VerificationEvidence`;
no already-PROVEN `kernel.read` needed. Generic read run: new `run_id`, region `xfast_entry`, offset 0,
length 8, through the normal W4/W5/W7 provider path, one provider entry, host compares the returned
bytes against the bootstrap expectation. Gate states: `DEFERRED` (NATIVE observed only) -> `DEFERRED`
(`KREAD_LIVE_APPROVAL_REQUIRED`) -> `GRANTED` with exactly one provider entry in the approved run.

**Run separation is now a pre-provider-entry assertion.** The capability gate refuses a verification
record that does not declare `separate_from_read: true` (`KREAD_VERIFICATION_NOT_SEPARATE`), and the
verification module still refuses a reused run id (`RUN_NOT_SEPARATE`).

**W12-A3 — the assurance is *verification-derived*, never native-provider authority.** F7 is
unchanged: `ProviderType.NATIVE` alone yields at most `OBSERVED`, and a record that claims more
defers. The `PROVEN` state of a `kernel.read` record exists only because a separate, store-bound
`VerificationEvidence` (`verify.kernel.read`, `outcome PASS`, `separate_from_read: true`, produced in
its own run and its own session) authorises the read — *verification-derived assurance*, in contrast
to any authority the runtime provider could claim by itself. The gate that turns evidence into
assurance is the derivation, and it is not a formatting step:

* `derive_capability_record()` is addressed by the evidence **hash**; it loads the record from the
  store (`VerificationEvidenceStore.load_verification_by_sha256`), where file name, run id and
  canonical hash must agree — a tampered body is `STORE_REHASH_MISMATCH`, a renamed copy is
  `STORE_ID_INVALID`, a re-hashed record loses the old address (`STORE_MISSING`);
* before it stamps `assurance = PROVEN` it re-establishes, itself: `outcome PASS`, `capability
  kernel.read`, `operation verify.kernel.read`, the provider/`provider_type` identity, the current
  `profile_sha256`, the current `boot_id`, the pinned bootstrap window (region/offset/length and the
  expected/observed bytes and hash), `verification_run_id != read_run_id` and a verification session
  different from the session that is about to read;
* the productive phase-B dispatcher takes ids and bindings only — never a prepared record — and
  revalidates the derivation **immediately before the provider entry**; a record that is not the one
  this process derived never reaches the provider (`KREADLIVE_CAPABILITY_NOT_DERIVED`, zero provider
  entries).

Consequence: in the whole W12 path there is no `PROVEN` `kernel.read` record other than the one the
store-bound derivation produced for this session, this boot and this read run.

**Payload unchanged.** The pre-live rebuild is byte-identical to the accepted W12 offline BIN
(`de9e787de514283113bd818277078eab55daf69ffdf0736c583b6adf4667c047`); only host-side modules changed.

**Live sequence** (two logical runs, therefore two uploads and two explicit rearm confirmations):
handshake, `session.status`, binding confirmation, fixed bootstrap `verify.kernel.read`, host
verification, store evidence, re-evaluate the W4 gate, expect `ELIGIBLE`, new run id, exactly one
generic bounded read, host byte/hash comparison, final status, BYE, health.

### Known gaps before the W12 live run (found while checking the rearm)

1. **Host does not know the payload's event type.** The payload sends `kernel.read.bounded`
   (schema `ps4rf.kernel.read.bounded.v1`), but `tools/hostctl/session.py` lists only
   `kernel.attestation`, `boot.binding` and `boot.binding.privileged` in `KNOWN_EVENT_TYPES` — an
   unknown type is dropped silently, so the live event would never reach the verification path.
2. **No host-side live driver for the approved two-run flow.** There is no CLI path that performs
   the fixed bootstrap `verify.kernel.read`, verifies the returned bytes against the pinned
   expectation, writes the `VerificationEvidence`, re-evaluates W4/W5/W7 and then performs the single
   generic bounded read in its own run id (the W11.2 flow has an analogous path,
   `capture_privileged_event` + `--w112-…`, but W12 has none).

Both gaps are offline work; until they are closed the approved live flow cannot execute and no
upload may happen.

## W12-RVA0-BINDING — relative locator vs runtime address (integration finding, fixed)

**Finding.** The accepted RUN B window `image_elf` offset 0 is a *relative* locator: `image_elf` sits
at the image base, so its rva is 0. The W5 profile binding validated that relative value against the
*runtime* address domain (`FIELD_DOMAINS['addr']`, `u64 > 0`) and `kread_capability.decide()`
substituted the unslid resolved address into it - so a valid rva-0 locator was refused as
`PROFILE_UNBOUND` at `w5_profile_binding` **before** any runtime resolution, with zero provider
entries and no read triggered.

**Impact.** The approved RUN B could never be bound: the contract's "exactly one generic bounded read
of `image_elf` offset 0" was unreachable, although the locator, the registry entry, the probe and the
payload were all correct.

**Fix** (owner ruling 2026-10-06: not a payload change - a domain-modelling fix). The two domains are
separate now and each is applied where it belongs:

* `rva` - the relative locator domain (`FIELD_DOMAINS['rva']` via `validate_locator_value`, keyed by
  the locator kind through `LOCATOR_VALUE_DOMAINS`): a locator value is an image position,
  `0 <= rva < 2**64`, and **zero is valid** (`image_elf` at the image base). The W5 binding binds the
  locator and records what it bound (`binding['locator']`); it never validates it as a runtime
  address.
* `runtime_va` - the resolved runtime domain (`FIELD_DOMAINS['runtime_va']`): non-zero and canonical.
  It is applied where the address actually exists, i.e. resolved against the **current** boot's
  kernel base: `regions.checked_kernel_address(kbase, rva)` and `regions.resolve_runtime(resolved,
  kbase)`, with checked arithmetic (`kbase + rva`, then `+ offset`; `offset + length` remains the
  registry's rule). Overflow, a zero base/address, a non-canonical value and a window outside the
  pinned image window fail closed (`KREAD_RUNTIME_OVERFLOW`, `KREAD_ZERO_RUNTIME_ADDRESS`,
  `KREAD_NON_CANONICAL_ADDRESS`, `KREAD_OUTSIDE_IMAGE_WINDOW`). `binding.create_runtime_binding` uses
  the same primitive, so the W5 runtime binding cannot compose an unchecked address either.

**Unchanged.** The payload (BIN `de9e787d...`, ELF `4d4a6365...`, build id `07d6fd12...`) and the
profile document (`profile_sha256 4a6f575c...`) are untouched, and no rebuild happened.
`tools/profiles/regions.py` changed, so its *generated* region table header was regenerated: the
registry-sha256 provenance comment is the only changed line and every region/rva/length byte is
identical, so the payload's compiled table is unchanged.

**Regressions** (`tests/test_rva0_domain_binding.py`, 13 tests): rva 0 is a valid locator;
`runtime_va` 0 is rejected; `kbase + rva0 == kbase`; a nonzero rva behaves exactly as before; an rva
overflow is rejected; a `kbase + rva` overflow is rejected; a non-canonical resolved runtime VA is
rejected; the `image_elf` profile binding is a `PROFILE_MATCH`; the `image_elf` phase B simulation
takes exactly one provider entry after a valid `VerificationEvidence`; and UNRESOLVED,
STRUCTURAL_ONLY, a stale boot binding and a wrong profile are still refused.

## W12-A-D1 — compiled target table vs policy registry (live deviation, fixed)

**Deviation** `W12-A-D1`: `COMPILED_REGION_COUNT_COMPARED_TO_POLICY_REGISTRY_TOTAL` —
disposition `HOST_VERIFIER_BUG`, payload result `READ_SUCCESSFUL_NOT_PROMOTED`, verification result
`REFUSED_FAIL_CLOSED`.

**What happened.** The first (and only) phase A upload delivered the accepted payload; the payload's
one bounded read of `image_elf` rva 0 returned the pinned bytes and the pinned sha256, its
LSTAR-derived kbase matched the host's expectation, the cross check said MATCH, one privileged
callback ran with `kexec_rc` 0 and zero generic provider entries were taken. Then exactly one host
check refused the evidence:

```
generated_table_matches_registry | max_read_len=4096 region_count=9 registry=11
```

**Root cause.** Two different questions were mixed up. The payload compiles the *target table*
(`native/target/gen_kread_regions.py` -> `ps4rf_kread_regions.h`), which **excludes** the
`UNRESOLVED` policy entries by design, so it reports 9 regions. The verifier compared that against
`len(regions.regions())` — the *policy registry total*, 11 entries, including `boottime_node` and
`boottime_bintime`, which are registered `UNRESOLVED` and are never readable or compiled. The
offline simulation had fed the check the same wrong number, so it could not expose the divergence.

**Fix (host-side, no payload change).** The two terms are now separate and normatively documented:

* `regions()` — the full policy registry, `UNRESOLVED` included: the review surface;
* `regions.compiled_regions()` — the target table: registry order minus the refused-by-design
  entries, the single source for the compiled region count, the target table order, the region
  index mapping and live payload parity. It fails closed (`KREAD_TABLE_INVALID`) on a duplicate
  entry, an incomplete non-`UNRESOLVED` entry or an empty table.

`kreadlive` compares the payload's `region_count` against the compiled count, `region_index()` maps
inside the compiled table, and the simulation builds `region_count` through the same production
path. `tests/test_compiled_regions.py` pins the numbers (9 compiled / 11 policy), the accepted and
the refused counts, the index/rva/length claims and the invariants;
`tools/hostctl/mutation_w12a_d1.py` re-introduces the defect in a throwaway copy and requires the
regression to go red (`ALL_MUTANTS_KILLED`).

**Unchanged:** payload BIN/ELF/build id and the profile document. The generated header was
regenerated (provenance comment only; table bytes identical, `--check` clean). Deviation pack
`20261006T120929Z_ps4rf_p4w12-phaseA-deviation` stays untouched; the corrected state is
`W12 VERIFY LIVE READY R2`.
