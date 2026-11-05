# P4 / W10 — Real FW13.52 Profile Promotion + Boot Binding Resolution (offline)

Status: **executed offline, ready for review. No upload, no live run, port 9090 untouched,
no kernel primitive opened.** Owner gate: after this report — STOP.

W10 answers two questions:

1. can a *real* (non-fixture) FW13.52 profile be promoted from evidence that already exists?
   → **yes**, built only from the accepted W9 live evidence plus the pinned FW13.52 research.
2. is there a trustworthy, read-only boot identity on Orbis that a future minimal callback could
   read? → **yes**, one primary candidate with two independent read paths (userland sysctl and a
   fixed kernel variable), documented below with its evidence and its limits.

---

## 1. Deliverables

| What | Artefact |
|---|---|
| real profile candidate | `profiles/fw1352/profile-13.52.json` |
| profile_sha256 | `4a6f575c8b1aa7906d7a86d08fe5cc4e5dc1a2939a2de19fac40c7fa82771766` |
| promotion builder | `tools/profiles/promotion.py` |
| independent validator | `tools/profiles/promotion_validator.py` |
| boot identity contract | `tools/profiles/bootid.py` |
| boot identity candidates | `profiles/fw1352/boot-identity.json` |
| W4/W5/W7 gate report | `tools/profiles/w10_gate.py` → `w10-gate-report.json` in the evidence pack |
| policy matrix | §4 of this document + `window-policy.json` of the W9 pack (unchanged) |
| regressions | `tests/test_profile_promotion.py`, `tests/test_boot_identity.py` |

The W5 fixture `tests/fixtures/profiles/fw1352-fixture.json` is **untouched** — its canonical hash
is still `17f94c4063e945f9db58e7fc651b2f0f5262070b13d768eac2f0164ce32493c3` and a regression test
pins that value. The promotion produced a *new* artefact; nothing was rewritten in place.

## 2. Promotion workflow (as required)

```
W5 fixture  +  W9 measured evidence  ->  candidate  ->  independent validator  ->  promoted profile
```

* `promotion.py` reads the pinned kernel image (sha256 `cf157ffd…`, hash re-verified before use),
  the W9 live evidence of the accepted run, and the W9 window table; it refuses to build anything
  if a single strict window disagrees with the live measurement.
* `promotion_validator.py` re-derives everything from those same sources *independently* (it does
  not read any intermediate value from the builder): pinned bytes at every RVA, live observations,
  slide derivation from the measured `kbase_candidate`, provenance, address scan.
* The validator's self-test proves the five required properties by mutation: each violation is
  caught by the check that owns it.

## 3. Profile identity (only as strong as the evidence)

| field | value | basis |
|---|---|---|
| platform | `ORBIS` | runtime (W9 READY) + capture dossier |
| architecture | `x86-64` | schema vocabulary; the runtime reports `x86_64` (finding W10-F1) |
| firmware_version | `13.52` | **kernel evidence**: 7/7 STRICT_FINGERPRINT windows of the pinned FW13.52 image matched the live kernel byte for byte, host-verified |
| firmware_build_id | `kernel-sha256:cf157ffd…` | content identity of the pinned kernel image (not a vendor string; finding W10-F2) |
| model_family | `PS4 Slim CUH-2116A` | capture dossier (vendor model string of this console) |
| hardware_revision | `B01Y` | tail of the same vendor model string (board revision field) |

`kern.sdk_version = 0.0-prototype` is **not** used anywhere as a 13.52 proof (explicitly excluded).

No runtime address is persisted: the validator proves that none of the five W9 runtime values
(`lstar`, `kbase_candidate`, `kbase_sdk`, `kbase_slide`, `aperture_global`) appears in the
canonical profile bytes, and that no string in the document looks like a kernel address.

## 4. STRICT / STRUCTURAL policy matrix (7 + 1)

| window | RVA | bytes | section / perms | policy |
|---|---|---|---|---|
| `image_elf` | 0x0 | 16 | text / r-x | STRICT_FINGERPRINT |
| `xfast_entry` | 0x1C0 | 8 | text / r-x | STRICT_FINGERPRINT |
| `copyout_prologue` | 0x2BD6A0 | 8 | text / r-x | STRICT_FINGERPRINT |
| `code_anchor` | 0x4CF6A0 | 24 | text / r-x | STRICT_FINGERPRINT |
| `amd_iommu` | 0x7CE9E9 | 16 | text / r-x | STRICT_FINGERPRINT |
| `gbase_vtophys` | 0x815BBC | 16 | text / r-x | STRICT_FINGERPRINT |
| `prison0_static` | 0x111FA18 | 8 | data / rw- | STRICT_FINGERPRINT (relocated: image value + slide) |
| `aperture_global` | 0x23D3DF8 | 8 | outside-loaded-image / r-- | **STRUCTURAL_ONLY** |

`aperture_global` stays STRUCTURAL_ONLY permanently, as agreed, and the three observed values from
different sources are never smoothed into a firmware fingerprint. W10 adds a new, structural
reason for that decision: **the aperture RVA lies outside every `PT_LOAD` segment of the pinned
image** (segment table: `0x0..0xcfe758` r-x, `0xd20000..0x13265e8` rw-), so the bytes the capture
holds there are dump-area content, not loaded image content (finding W10-F3). The validator
excludes it from the identity basis and would reject a profile that used it as a fingerprint.

Sections and permissions are derived from the pinned image's program headers (the image carries no
section table) — finding W10-F2.

## 5. W9 → profile provenance

| profile fact | source | evidence |
|---|---|---|
| expected bytes of the 7 strict windows | pinned `kernel.bin` (RVA → bytes, re-extracted by the validator) | image sha256 `cf157ffd…`; identical to the live observations of the accepted W9 run |
| `prison0_static` expectation | pinned image value | live pointer equals image value + slide (slide from `kbase_candidate` = LSTAR − xfast offset) |
| firmware 13.52 | the strict window match | W9 host verification: `strict_matches 7/7`, `strict_mismatches 0`, `verified: true`, `problems: []` |
| console identity | capture dossier `README.md` | sha256 of that file is recorded in the profile notes |
| policy per window | W9 window table (`native/target/ps4rf_attest_data.h`) | 7 strict + 1 structural enforced by a self-test |

## 6. Validator result

```
[ok] schema_valid                     no schema errors
[ok] canonical_sha256                 declared == recomputed
[ok] not_a_fixture                    fixture=False
[ok] policy_matrix_present            7 STRICT_FINGERPRINT, 1 STRUCTURAL_ONLY
[ok] strict_fingerprints_match        7 windows: pinned == live (one as image value + slide)
[ok] relative_locators_resolve        all locators are integer RVAs inside the image
[ok] provenance_complete              all 8 locators carry the pinned image hash
[ok] no_runtime_address_persisted     none of the 5 W9 runtime values appear in the profile
[ok] structural_only_not_an_identity  aperture_global marked structural, excluded from identity
[ok] gated_ops_explicit_and_fail_closed  14 policy entries, none claimed without evidence
verdict: PASS (profile_sha256 4a6f575c…)
```

Schema revision (documented, drift-logged): locators may carry an optional `policy` key (the W5
fixtures keep validating untouched), and `operation_policy` entries may state
`profile_required: true` with `locator_ref: null` — the explicit "required, but this profile has no
evidence-backed locator yet" state, which fails closed as `LOCATOR_MISSING` (finding W10-F4).

## 7. Boot identity — candidates (offline, FW13.52)

Full machine-readable report: `profiles/fw1352/boot-identity.json`.

**Candidate 1 (primary, userland): `sysctl kern.boottime`.**
`sysctlbyname("kern.boottime")` / MIB `(CTL_KERN=1, KERN_BOOTTIME=21)` — libPS4 exposes
`sysctl`/`sysctlbyname`; needs no privilege beyond the jailbreak. `struct timeval` (tv_sec 8 B,
tv_usec 8 B, little endian). Written once per boot, so it is constant within a boot and new after a
reboot. Read-only. Confidence HIGH.

**Candidate 2 (primary, kernel variable): the same timeval at RVA `0x224c6c8`.**
Datatype `struct timeval` (tv_sec at `0x224c6c8`, tv_usec at `0x224c6cd0`), inside the kernel data
segment. Read-only, one 16-byte read. This is the variable the sysctl node exports, so the two paths
cross-check each other. Confidence HIGH.

**Candidate 3 (structure): the sysctl node at RVA `0x1a5ef90`.**
Number `0x15` (= 21, `KERN_BOOTTIME`), kind `0x80000005` (`CTLFLAG_RD | CTLTYPE_OPAQUE`, i.e.
read-only); name pointer → RVA `0x7dc0e0` ("boottime"); handler pointer into the text segment (RVA
`0x34f430`), whose code returns exactly 16 bytes from RVA `0x224c6c8`; type string `S,timeval`;
description "System boottime"; format string `U`. The node itself is constant — only its data
changes per boot. Confidence HIGH. A future callback reads the *variable*, never calls the handler.

**Candidate 4 (secondary, kernel variable): the bintime twin at RVA `0x224c6b0`.**
`struct bintime { sec; frac }`, written by the same code block as the timeval, so it carries the
same boot instant. Second choice: the timekeeping routine adds into it on every tick, while the
timeval stays as set — read the timeval. Confidence MEDIUM.

**Candidate 5 (secondary, runtime): the KASLR slide.**
`kbase − static_image_base` with `kbase` derived from LSTAR (as in W9). Constant within a boot,
different with high probability across boots — the reason three captures of this firmware show
three different bases (kernel-dump, kernel-live-snapshot, ram-full) plus the W9 live run.
**Not sufficient on its own** and never a boot identity by itself. Confidence MEDIUM.

### Evidence for candidates 2 to 4

The sixteen bytes at `0x224c6c8` decode to the boot instant of the capture, and the bintime twin at
`0x224c6b0` carries the same instant in its second representation:

```
0x224c6c8: sec  = 1789910256  ->  2026-09-20T13:17:36Z
0x224c6cd0: usec = 860896     (valid: 0 <= usec <= 999999)
0x224c6b0: bintime sec 1789910256, frac 0xdc63bd3cfedeccfe = 0.8608968996 s
            -> 0.8608968996 s == usec 860896 / 1e6
```

The dossier was written about 47 minutes after that instant, which is exactly the relationship a
boot instant has to a capture. The sysctl node in the same data region carries the standard layout
(number `0x15` = `KERN_BOOTTIME`, kind read-only opaque, name pointer to the "boottime" string at
RVA `0x7dc0e0`, handler at RVA `0x34f430`, type `S,timeval`, description "System boottime"), and the
handler's machine code loads exactly the address above and copies 16 bytes. The only write to that
address in the whole image sits in the internal clock-set routine (RVA `0x34ea16`), reached from the
RTC/inittodr boot path and from the `kern_time.c` clock-set path — i.e. the variable is written at
boot and only re-written if the clock is set.

**Correction (documented, not hidden):** the first W10 draft named RVA `0x1a5ef80` as the boot
instant. A deeper offline re-verification showed that address holds `time_second` (and `0x1a5ef88`
`time_uptime`) — a pair whose value changes every second within a boot. The pair is now an explicit
non-candidate; only its *difference* is boot-stable and cross-checks the boot instant to about one
second (1789910257 vs 1789910256). The contract, the derivation and the reboot semantics were
unaffected; the address and the demonstrated values were corrected.

### Non-candidates (documented, with reasons)

`session_id` (per session), `payload`/build id (delivery artefact), `pid` and agent start time (per
process), random values (not reproducible), profile hash alone (facts, not boot), firmware version
alone, `kern.sdk_version` (a userland string), RTC/persistent counters (not boot scoped). The full
list with reasons is in `boot-identity.json` and in `tools/profiles/bootid.py`
(`FORBIDDEN_SOURCES`) and is enforced by a regression test.

## 8. Boot ID contract (definition only — no live measurement in W10)

```
boot_id = 'BOOT-' + first 16 hex of
          SHA256( canonical(target identity) || canonical(trustworthy boot instance data) )
```

* **target identity** = platform, architecture, firmware_version, firmware_build_id, model_family,
  hardware_revision, profile_sha256.
* **boot instance data** = `{source, boottime_sec, boottime_usec}` from `sysctl:kern.boottime`
  (secondary optional discriminator: `kbase_slide`, carried as a hex string).
* **Canonicalisation**: the project's canonical JSON (sorted keys, compact separators); the slide is
  a 64-bit value and therefore travels as a hex string, never as a JSON number.
* **Invalid inputs (fail closed)**: `sec == 0` (uninitialised), `sec` before 2001, `sec` in the
  future beyond 24 h of clock skew, `usec` outside `0..999999`, any source other than the two
  accepted paths, a target identity without `profile_sha256`.
* **No secrets** enter the derivation (`no_secret_inputs: true`, enforced by a self-test).
* **Reboot semantics** (offline tests): same firmware + same profile + same boot instance → same
  `boot_id`; new boot value → different `boot_id`; a binding from the old boot is invalid in the
  new boot, while the profile facts themselves stay valid (`facts_persistent: true`).

## 9. W4 / W5 / W7 gate results before and after the promotion

Machine-readable: `w10-gate-report.json` in the evidence pack.

| stage | W5 verdict | notes |
|---|---|---|
| fixture profile | `PROFILE_UNVERIFIED`, `BOOT_BINDING_MISMATCH` | not evidence-backed; nothing usable |
| promoted, no boot binding | `BOOT_BINDING_MISMATCH` only | profile is evidence-backed; the boot binding is the one missing piece |
| promoted + (simulated) binding | **`PROFILE_MATCH`** | the mechanism the owner asked for works |
| promoted + binding + SIMULATED_REBOOT_VECTOR as "current" boot | `BOOT_BINDING_MISMATCH` | facts persist, the binding expires. The vector is a simulated value for the offline gate only and must never be reported as a measured reboot nor enter live evidence |
| promoted + request for a gated operation | `LOCATOR_MISSING` | the profile claims nothing it cannot back |

| stage | W4 (privileged op) | W7 dispatch |
|---|---|---|
| before | `DEFERRED` — `CAPABILITY_MISSING`, `PROFILE_UNBOUND`, `EVIDENCE_MISSING`, `APPROVAL_MISSING`, `NOT_WIRED` | `OPERATION_DEFERRED`, `provider_entry: false`, `stopped_at: capability_resolution`, `profile_sha256: null` |
| after | `DEFERRED` — same list **without** `PROFILE_UNBOUND` | `OPERATION_DEFERRED`, `provider_entry: false`, `stopped_at: capability_resolution`, `profile_sha256: 4a6f575c…` |

Reading: the promotion removes exactly one blocker (the profile step) and changes nothing else —
privileged providers stay deferred, no provider entry is granted, `kernel.read` stays
`OPERATION_DEFERRED`. `BOOT_ID_UNVERIFIED` is now the only remaining hard blocker on the profile
side; the other reasons (capability, evidence, approval, wiring) are unchanged and not in W10's
scope.

## 10. Regressions

* `tests/test_profile_promotion.py` — fixture untouched (hash pinned), self-tests, policy matrix,
  window classification from the segment table, address-free profile, six mutation cases, gated
  operations explicit and fail-closed.
* `tests/test_boot_identity.py` — determinism, id shape, floor/ceiling validation, forbidden
  sources, slide-not-alone, binding invalidation with persistent facts.
* Full suite: **511 passed, 1 skipped** (`pytest.log` in the evidence pack; +24 new W10 tests).

Evidence pack: `~/07-evidence/20261005T204503Z_ps4rf_p4w10-offline` — `VERIFY_OK`, 11 files, including
the promoted profile, the validator report, the gate report, the boot identity candidate report, the
window policy matrix (unchanged from W9) and the suite log. Sources are recorded in `SOURCES.txt`
with the pinned kernel digest and the W9 live-evidence digest.

## 11. Findings (new)

* **W10-F1** — identity vocabulary mismatch: the profile schema uses `x86-64`/`ORBIS` while the
  runtime attestation reports `x86_64`/`orbis`, and the runtime's model string
  (`[REDACTED_RUNTIME_MODEL]`) is not the dossier's model string (`CUH-2116A`). A live binding needs a
  documented normaliser before any comparison; not fixed in W10 (no live path touches it yet).
* **W10-F2** — the pinned image carries program headers but no section table, and no vendor build
  string; `section` is therefore segment-derived and `firmware_build_id` is a content identity.
* **W10-F3** — `aperture_global` lies outside every `PT_LOAD` segment of the pinned image: the
  structural reason behind the permanent STRUCTURAL_ONLY decision.
* **W10-F4** — the W5 schema could not express "profile-bound operation without an
  evidence-backed locator": `profile_required: true` demanded an existing locator. Minimal,
  documented revision (optional locator `policy` key; `locator_ref: null` = explicitly pending,
  fails closed as `LOCATOR_MISSING`), with the parity test updated and the fixtures untouched.
* **W10-F5** — the boot instance is readable *without* any privileged callback (userland
  `sysctlbyname("kern.boottime")`), so W11 may not need a kernel callback for the boot identity at
  all; the kernel-variable path is the cross-check, not the first choice.
* **W10-F6** — two boots inside the same wall-clock second are distinguishable only via
  `tv_usec` (and, if measured, the secondary slide discriminator) — recorded as a contract caveat.
* **W10-F7** — the boot instant lives at RVA `0x224c6c8` (timeval) with the bintime twin at
  `0x224c6b0`; the adjacent `time_second`/`time_uptime` pair at `0x1a5ef80`/`0x1a5ef88` looks like a
  plausible boot time at first glance but changes every second — a trap that an earlier draft of
  this wave fell into and that the deeper re-verification caught. No `boot_epoch`, `boot_count`,
  `boot_id`, `monotonic` or `kern.uptime` string exists in the image (negative evidence), so there is
  no boot *generation* counter — the instant is the only boot-scoped signal.
* **W10-F8** — no second boot of this firmware could be sampled offline: neither the live snapshot
  nor the full RAM capture holds the kernel page with the variable, so "changes per reboot" rests on
  the write-path analysis plus three observed different kernel bases, not on two measured samples.

## 12. What W10 does *not* do

No payload, no upload, no port 9090 contact, no `kernel.read`, no GPUVM/KeyMgr/CCP/SAMU/EAP/EMC/
PUP/Secure Services, no live measurement, no profile bound to a live boot, no hash history
rewritten, no W9 evidence modified. W11 (boot identity live attestation → runtime binding →
separate `verify.kernel.read` → bounded read-only `kernel.read` provider) is **not** implemented.

**STOP after this report.** Next step only on an explicit new order.
