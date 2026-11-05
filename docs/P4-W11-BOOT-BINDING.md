# P4 / W11 — Live Userland Boot Binding (`BOOT_ID_UNVERIFIED` → resolved)

W11 resolves the last hard blocker for a real privileged provider promotion **without any new
privileged operation**: the boot identity is read through the read-only userland `KERN_BOOTTIME`
sysctl, and everything else is host-side derivation.

**Scope actually exercised:** offline only. No payload upload, port 9090 untouched, no `kexec`, no
kernel address, no RVA, no generic `kernel.read`, no GPUVM/KeyMgr/CCP/SAMU. The live run awaits a
rearm confirmation and is the next step after this report.

## 1. What W11 delivers

* a **read-only userland collector** in the target agent (`native/target/ps4rf_boot.{h,c}`), compiled
  only with `PS4RF_TARGET_BOOTID=1`, that reads `KERN_BOOTTIME` **twice** with a bounded pause and
  reports both raw `struct timeval` values plus the stability verdict,
* **one canonical algorithm** (`ps4rf.boot-binding.v1`) with the digest and the short id,
* a **host-side verifier** (`tools/hostctl/boot.py`) that re-checks stability and the timeval domain
  itself, then derives the id and forms the runtime `BootBinding`,
* a full **offline end-to-end proof** through the real agent binary (host build) — stable source
  binds, drifting source stops, absent source stops,
* the **W4/W5/W7 gate result before and after** a binding (`tools/profiles/w11_gate.py`),
* the exact **LOCATOR_MISSING** triple that survives the binding.

## 2. The algorithm (exactly one)

```
canonical object = {
    "schema":         "ps4rf.boot-binding.v1",
    "platform":       "orbis",
    "profile_sha256": "<real profile hash>",
    "boottime":       {"sec": <int>, "usec": <int>}
}
boot_digest = SHA256(JCS(canonical object))
boot_id     = "BOOT-" + first 16 lowercase hex of the digest
```

* The full digest is stored in the runtime evidence; only the short id is used for binding
  comparisons. Nothing secret enters the object, and neither pid, session id, agent start time nor
  any random value is mixed in.
* `platform` is normalised to lower case (`ORBIS` → `orbis`): finding **W10-F1** measured that the
  vocabulary differs between profile and runtime, so the normalisation is explicit and tested.
* **Withdrawal, documented:** the earlier W10 draft (schema `ps4rf.bootid.v1`) folded the target
  identity into the digest. It is removed as an authority; `bootid.w10_draft_boot_id()` only shows
  how the old string was produced. The W10 capture boot id was **recomputed with the final
  algorithm**:

  | value | string |
  |---|---|
  | W10 draft (withdrawn) | `BOOT-bd1e2729373fc597` |
  | W11 algorithm, same inputs | **`BOOT-19d2c790b0769502`** (`19d2c790b076950231b428fd938cb70f9c82b2d754bffab3e62f33db8782fbad`) |
  | simulated second boot (labelled) | `BOOT-75744f622d9982f6` — `SIMULATED_REBOOT_VECTOR` |

  The algorithm is authoritative, the old string is not. The regression test pins the new value.

## 3. Validity rules (all fail closed, no fallback)

Refused: `tv_sec <= 0` · `tv_usec < 0` · `tv_usec >= 1000000` · boottime after the console's own
wall clock (same clock → no skew in play) · missing/malformed `profile_sha256` · target identity not
matching the profile · the sysctl read failing · the two reads inside one session not being byte
identical (`BOOT_SOURCE_NOT_STABLE`) · a simulated/test label claimed as measured. There is **no
fallback to a random or session derived id**: a refused value means `BOOT_ID_UNVERIFIED` stays.

Explicitly unusable as the sole boot identity (machine readable in `bootid.FORBIDDEN_SOURCES`):
session id, payload id, pid, agent start time, random value, `profile_sha256` alone, firmware
version alone, KASLR slide alone, and the `time_second`/`time_uptime` pair (**W10-F7**).

## 4. Collector design (why it needs no privilege)

* The boot instant comes **only** through the platform layer's `boot_timeval()` slot
  (console: `sysctlbyname("kern.boottime")`; host build: the honest stand-in fed by
  `PS4RF_HOST_BOOTTIME`). The W11 module contains **no** `kexec`, **no** `rdmsr`/`wrmsr`, **no**
  kernel address and **no hex constant at all** — enforced twice, by a source test and by the
  artefact gate.
* The plausibility rule "boottime not after the wall clock" uses the console's own userland clock
  (`sceKernelGettimeofday`) — again read-only, no privilege, no kernel data.
* The agent triggers the collection **itself** right after the first `session.status` response
  (one-shot guard, mirroring the W9 pattern): the host never sends an address, a flag or a trigger.
* On failure the agent **stops the session** with the measured reason as the BYE reason
  (`BOOT_READ_FAILED`, `BOOT_SOURCE_NOT_STABLE`, `BOOT_TIME_IMPLAUSIBLE`) before anything else
  happens — no session continues with an unknown boot identity.

## 5. Offline end-to-end results (real agent binary, host build, loopback)

| case | read1 | read2 | run status | agent BYE | host verdict |
|---|---|---|---|---|---|
| stable source | `1789910256.860896` | identical | `OK` | `CLIENT_CLOSE` | PASS — binding `BOOT-19d2c790b0769502` on `4a6f575c…` |
| drifting source (`+1 µs` per read) | `…860898` | `…860899` | `BOOT_SOURCE_NOT_STABLE` | `BOOT_SOURCE_NOT_STABLE` | FAIL (STOP recorded, not hidden) |
| absent source | — | — | `BOOT_READ_FAILED` | `BOOT_READ_FAILED` | FAIL, no id derived |

Stable case, host-side verified: `stability STABLE`, `labels ['MEASURED_THIS_BOOT']`,
`valid_for_this_boot true`, `facts_persistent true`, event flags
`no_kernel_access/no_kexec/no_kernel_address/no_rva_sent_to_host` all true, canonical object exactly
the four agreed keys, `boot_binding_profile_sha256 == 4a6f575c…`.

## 6. W4/W5/W7 gate: before and after the binding

| stage | W5 codes | W4 | W7 |
|---|---|---|---|
| before (no binding) | `BOOT_BINDING_MISMATCH` | `DEFERRED` | `OPERATION_DEFERRED`, no provider entry |
| after (binding) | **`PROFILE_MATCH`** | profile reason gone | still `OPERATION_DEFERRED` |

So the boot reason disappears exactly as the owner expected, and the profile itself stays valid
across boots; only the runtime binding expires.

## 7. What still blocks `kernel.read` (not hidden)

`kernel.read` stays `OPERATION_DEFERRED` — the boot binding does **not** unlock it, and no
workaround is applied. The remaining `LOCATOR_MISSING` triple, reported exactly:

* **operation:** `kernel.read`
* **profile fields:** `addr`, `size`
* **locator:** `operation_policy['kernel.read'].locator_ref = null` (`profile_required: true`) —
  "the profile has no evidence-backed locator for this operation yet (fail closed)"
* W5 detail: `LOCATOR_MISSING: kernel.read: the profile has no evidence-backed locator for this operation yet`

W11 counts as a successful boot-binding run **even though `LOCATOR_MISSING` survives** — the order
of work (bounded read-only provider, then a generic `kernel.read`) remains the owner's decision.

## 8. Reboot semantics (exactly as far as the evidence goes)

* proven now: **this boot → a stable, reproducible boot identity** (two byte-identical reads).
* **not** proven and therefore never claimed: `CROSS_REBOOT_EMPIRICALLY_PROVEN`. No real reboot was
  forced for this test. The cross-boot property stays **`SUPPORTED_BY_WRITE_PATH_ANALYSIS`**
  (single write site in the boot/clock-set path, three observed different kernel bases) until a
  second boot is actually measured. After such a reboot a **new** boot id must appear and the old
  runtime binding must be invalid while the profile facts stay valid.
* `SIMULATED_REBOOT_VECTOR` / `TEST_BOOT_ID` values are offline constructs. They are **never**
  recorded as measured reboots, never enter live evidence and never enter profile provenance. (The
  earlier presentation of `BOOT-0cf8cf468ebabd3c` as "after reboot" was a simulated vector and is
  withdrawn; the corrected, labelled vector of this wave is `BOOT-75744f622d9982f6`.)

## 9. Live sequence prepared (one upload, after rearm only)

1. handshake · 2. `session.status` · 3. the agent's own read-only `KERN_BOOTTIME` collection
(two reads, bounded pause) · 4. host-side canonical binding derivation · 5. `BootBinding` against
the real FW13.52 profile · 6. W5 validator · 7. W4/W7 gate recomputation · 8. final
`session.status` · 9. BYE with cleanup · 10. read-only health checks (FTP 2121, 3232, ICMP).
No `kexec` is needed for W11. Port 9090 is not contacted before the rearm confirmation, and exactly
one upload follows it.

## 10. Evidence and hashes (offline pack)

* payload (host build, `PS4RF_TARGET_BOOTID=1`) and target artefact hashes are listed in the pack's
  `SOURCES.txt`, together with the promoted `profile_sha256`, the pinned kernel digest and the
  boot timeval RVA;
* artefact gates: `rdmsr 0`, `wrmsr 0`, `kexec references 0`, `privileged entry symbols []`,
  `module kernel-range literals 0`, symbols `ps4rf_boot_collect`/`ps4rf_boot_event`/
  `ps4rf_boot_status_name` present (manifest `verdict: PASS`);
* three selftest evidence documents (stable, drifting, absent source) with the frame hash of the
  sealed event;
* gate report, boot-identity artefact, W11 doc, full pytest log (526 passed / 1 skipped).

## 11. Findings

* **W11-F1** — the sysctl is reachable and the whole chain is userland-only: no `kexec` in the W11
  payload at all, which removes the W9-style privileged dependency for the boot identity.
* **W11-F2** — a drifting source is caught **inside one session** (two reads), which is stronger
  than trusting the value's shape; the agent stops before anything else in the session.
* **W11-F3** — `platform` vocabulary differs between profile (`ORBIS`) and runtime (`orbis`); the
  normalisation is explicit, tested, and part of the digest input contract.
* **W11-F4** — the agent build needed one more compile-time guard (`request_op` extraction) to make
  the boot profile work without the attestation profile. The two profiles stay independent (a W11
  build contains no `kexec`, a W9 build no boot module), but the **shared** platform and agent
  sources changed, so a rebuild of the W9 profile is **not bit-identical** to the frozen live
  artefact: rebuilt BIN `eefbb3cb…`, build id `687632292acf98c207d3a6dc02e79f27`, versus the frozen
  live BIN `f70fd896…` (build id `20e188612db876ece995207d3778cb2d`). The frozen packs stay
  untouched as evidence; a future W9 re-run would have to be re-reviewed against the new hash. This
  is recorded drift, not a silent one — the claim "bit-identical" was wrong and is withdrawn here.
* **W11-F5** — `tools/drift_update.py` tracks the frozen manifest pins, not the rebuildable target
  artefact hashes, so this source-level drift is invisible to the automated drift gate and must be
  stated by hand (as above).
