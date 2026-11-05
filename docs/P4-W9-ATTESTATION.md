# P4 / W9 — read-only privileged attestation bring-up

Status: **offline complete**, live step pending an explicit BinLoader rearm (`W9 LIVE READY`).

W9 adds exactly one privileged code path to the PS4RF family: a **fixed, read-only kernel
attestation callback**. It exists to answer one question with measured data — *is this console
really running the FW13.52 kernel image the research evidence describes?* — and nothing else.

## 1. Hard limits (owner brief, unchanged)

Allowed: the authorised syscall 11 / `kexec` bootstrap, one defined read-only kernel callback,
kernel identity / runtime identity capture, LSTAR and the fixed kernel text fingerprints,
bounded copyout into the caller's own buffer, preparation of a W5 profile binding from measured
data, evidence.

Not allowed: generic `kernel.call` / `kernel.read` / `kernel.write`, any host-supplied kernel
address, GPUVM, KeyMgr, CCP, SAMU, SBRAM, EAP/EMC, secure services, PUP, fuzzing, race
experiments, persistence. **W9 opens no capability**: a successful attestation never flips
`kernel.read` to PROVEN — it creates `kernel.attestation` evidence only, and a separate
verification + profile binding step is what may later produce a real capability.

## 2. Design: one callback, no host input

* The host sends **no address, no flag and no trigger** for the privileged step. The agent runs
  the callback itself, once, immediately after its first `session.status` **response**.
* The result is reported as **one sealed EVENT frame** (`0x03`, agent → host, sealed with the
  a2h channel). This is the single documented W9 wire addition, in the same spirit as the W8
  READY frame: the frozen inbound set gains exactly one control frame
  (`HOST_INBOUND_W9 = HOST_INBOUND_W8 + {EVENT}`), `wire.check_inbound` is unchanged, and the
  request/response path is untouched.
* **Single shot, enforced in the payload**: a file-static guard is set *before* the call, so no
  path — not even a second request — can invoke `kexec` twice in one session. The default is
  one kernel callback per session; the brief's optional "identical second call as a repro test"
  is **not** used, and the build manifest records that.
* The callback takes no arguments from the host: `ps4rf_attest_info` carries a caller marker in
  and results out, and the kernel callback writes only into that block.

## 3. The measurement set (fixed, compile-time)

`native/target/ps4rf_attest_data.h` is generated (`gen_attest_table.py --write`, `--check` in
the gates) from pinned evidence:

* image: `~/audits/playstation-ps4/fw1352-ps4b-20260920/kernel-dump/kernel.bin`
  sha256 `cf157ffdbae872a20bbb9a46c8518b53d96c1ed75d4e73878466a295d92eca35`
  (static base the image is relocated for: `0xFFFFFFFFD00D0000`)
* live reference: `socscope-fw1352-phase9-20260928` — anchors A1/A2/A3 matched byte-exact live
  (`socscope9-20260928T114307-me-addrbits.json`)

Every window carries a **policy**, one of exactly two values, machine readable in the generated
table *and* in the build manifest (`gates.attestation.windows[]`, each with
`policy`, `counts_towards_strict_score`, `observed_required_to_equal_expected`):

* **`STRICT_FINGERPRINT`** — the observed bytes must equal the pinned expected value (for the
  relocated window: the pinned value plus the LSTAR-derived slide). A mismatch stops the
  attestation. Only these windows — plus the LSTAR/kbase shape and the cross checks — may ever
  support a `PROFILE_MATCH_CANDIDATE` decision.
* **`STRUCTURAL_ONLY`** — measured and reported as an observation. It never counts towards the
  strict score, never on its own produces `PROFILE_AMBIGUOUS` or `FAILED`, and the host verifier
  must not claim an exact match for it.

| id | rva | len | kind | policy | provenance |
|---|---|---|---|---|---|
| `image_elf` | `0x0` | 16 | static | STRICT_FINGERPRINT | ELF header at the image base (read at the LSTAR-derived base) |
| `amd_iommu` | `0x7CE9E9` | 16 | static | STRICT_FINGERPRINT | phase-9 anchor A1, match: true |
| `gbase_vtophys` | `0x815BBC` | 16 | static | STRICT_FINGERPRINT | phase-9 anchor A2, match: true |
| `code_anchor` | `0x4CF6A0` | 24 | static | STRICT_FINGERPRINT | phase-9 anchor A3 (code), match: true |
| `xfast_entry` | `0x1C0` | 8 | static | STRICT_FINGERPRINT | SDK `fw_defines.h`: `K1352_XFAST_SYSCALL 0x1C0` — LSTAR must point here |
| `copyout_prologue` | `0x2BD6A0` | 8 | static | STRICT_FINGERPRINT | SDK `fw_defines.h`: `K1352_COPYOUT` |
| `prison0_static` | `0x111FA18` | 8 | relocated | STRICT_FINGERPRINT | SDK `fw_defines.h`: `K1352_PRISON_0`; image value + slide must match |
| `aperture_global` | `0x23D3DF8` | 8 | structural | **STRUCTURAL_ONLY** | canonical + 16-aligned observation only — **not** a byte fingerprint |

`aperture_global` is deliberately `STRUCTURAL_ONLY`: the pinned image stores `0xffff82dae4800000`
while the phase-9 live run observed `0xffffe26de4800000`, so its value is boot dependent. That
disagreement is recorded as negative evidence rather than smoothed into a fingerprint. The
generator's self-test and the manifest gate both refuse a table whose policy counts are not
7 × `STRICT_FINGERPRINT` + 1 × `STRUCTURAL_ONLY`, and the parser compares the two values as
plain strings so a silent rename cannot pass.

Runtime identity: the callback reads `rdmsr(0xC0000082)` (LSTAR) and derives
`kbase_candidate = LSTAR - 0x1C0`, validates the shape (canonical, page offset `0x1C0`), then
reads the windows above at `kbase_candidate + rva`. `get_kernel_base()` (the SDK's own
LSTAR-based value, measured in userland) is reported next to it as an independent cross-check;
the host recomputes the relation and the slide (`kbase - 0xFFFFFFFFD00D0000`).

Report vocabulary stays separated: **expected** (pinned evidence), **observed** (this run),
**match** (host-side recomputation).

## 4. Build, gates, artefact

Profile `PS4RF_TARGET_ATTEST=1` (`native/target/build_ps4.sh`, `build_host.sh`). The section
split is enforced by `build_manifest.py --profile w9`, which classifies every disassembled
instruction by owning symbol: **kernel section** = `ps4rf_attest_k*`, everything else owned is
**user**.

Gates (fail closed; the manifest is not written when one fails):

* zero relocations (ids are inline `char[]` on purpose — a `const char *` table would need
  `R_X86_64_RELATIVE` entries)
* kernel section: exactly one `rdmsr`, zero `wrmsr`, zero `syscall`, zero control-register
  access, zero indirect calls
* user section: no privileged instruction, no kernel-space literal (canonical upper-half
  addresses beyond `-0x100000` signed)
* exactly one `syscall 11` wrapper in the whole artefact, and it is the SDK's `kexec`; the
  linked `kexec` / `get_kernel_base` are recorded as the explicit privileged-entry allowance
* every table window is compiled into the artefact

Artefact (live PSK, label `ps4rfd-live-w9`, context `fw13-52-attest-w9`):

* BIN `f70fd8965a6e554571cae7255a416780b06c173734c836507e3c6581f3466bc5`
* ELF `332d69e73a0c6bf06e11f8115b8db1ebab7fb75521dcc973bcbfcb160cb1c12d`
* manifest `16a4d11ad0478944d536c063e328c4fe40909f5d15a1a3068dec04b60962ef64` (build metadata; the payload is the BIN)
* build id `20e188612db876ece995207d3778cb2d`, `0` relocations, reproducible twice (byte
  identical)

## 5. Offline verification

1. **Callback harness** (`tests/harness/attest_offline.c`, run by
   `tests/test_attest_offline.py`): links the *production* callback and replaces only its two
   leaf operations (`ps4rf_attest_k_readmsr`, `ps4rf_attest_k_read8`, weak symbols) plus the
   SDK entry points, then runs five scenarios in separate processes (the one-shot guard is
   per session):

   * `clean_measurement`: **`strict_matches: 7/7`**, `structural_observations: 1`,
     `strict_mismatches: 0` — deliberately *not* reported as "8/8" — **exactly 104 byte reads**,
     cross-check MATCH, event OK
   * `strict_window_changed_amd_iommu`: 6/7 strict with 1 mismatch → run status CALLBACK, i.e.
     **stop** (regression: a STRICT_FINGERPRINT change stops)
   * `corrupted_image_identity`: only the first 16 bytes are read, callback status IMAGE
   * `structural_only_changed_aperture`: the structural window is changed — even to an
     out-of-range value — and the attestation stays **valid**: 7/7 strict, event OK, and the
     observation is documented as `STRUCT_BAD` (regression: structural changes do not fail)
   * `lstar_wrong_shape`: **zero** kernel bytes read, callback status LSTAR_SHAPE
   * `caller_marker_missing`: zero reads, callback status MAGIC
   * one-shot probe: the second invocation is refused with 0 `kexec` calls and 0 reads
   * every scenario asserts `strict_matches + strict_mismatches == 7`, i.e. the structural
     window can never enter the strict score (regression: structural is never an exact match)

2. **Fail-closed host end-to-end** (`ps4rfctl selftest --w9-attestation`): with no kernel
   (`kexec` → `-1`) the agent sends `EVENT {status: FAILED, callback_executed: false,
   kexec_rc: -1}` — no per-entry claims at all — and then ends the session with
   `BYE ATTESTATION_FAILED`. The controller records the event, verifies it, and writes the
   evidence; the W9 checks fail with exact reasons instead of inventing a verdict.

4. **Window policy correction (owner review, 2026-10-05).** The first W9 build counted the
   `STRUCTURAL_ONLY` observation inside the match score and let its range gate stop the run, and
   the report could have been read as "8/8 match". Corrected, minimally, without any new feature:
   the policy is now a generated, machine-readable field per window (table + manifest), scoring
   is strict-only, an out-of-range structural observation is recorded as `STRUCT_BAD` evidence
   but can no longer stop the attestation or produce `FAILED`, and the reported figures are
   `strict_matches: X/7`, `strict_mismatches: 0`, `structural_observations: 1`. Regressions cover
   all three owner rules: structural change → valid with documented observation; strict change →
   stop; structural never counted or claimable as an exact match (a payload that presents one as
   exact is rejected). Payload rebuilt: BIN `f70fd896...` (the pre-correction build
   `966cfb82...` is superseded).

3. **Host-side independent verification** (`tools/hostctl/attest.py`): the host re-derives every
   comparison from its own copy of the expected table and rejects a payload whose claimed status
   contradicts the bytes; a payload that reports "MATCH" for an unread window is caught, and a
   callback that did not run can produce no measurement. The report speaks the strict vocabulary
   — `strict_matches: "7/7"`, `strict_mismatches`, `structural_observations`,
   `structural_results[]` — and names its decision basis explicitly
   (`profile_evidence_basis.structural_only_excluded = ["aperture_global"]`). A STRUCTURAL_ONLY
   window is never in `strict_rows`, is never required to equal the expected value, and a payload
   that presents one as an exact match is rejected.

## 6. Profile and boot binding (unchanged until measured)

`kern.sdk_version = 0.0-prototype` is not a firmware attestation, so W9 keeps
`BOOT_ID_UNVERIFIED` and `PROFILE_UNBOUND`. The only sanctioned path to change that:

fixed attestation → measured fingerprints → comparison with the pinned FW13.52 evidence →
profile candidate → **review** → real W5 profile → `profile_sha256` → boot binding.

No match: STOP. Partial match: STOP with `PROFILE_AMBIGUOUS`. Full match: only
`PROFILE_MATCH_CANDIDATE` until the evidence pack is validated. A profile match alone never
legitimises an invented `boot_id`.

## 7. Live run (after a fresh rearm)

1. exactly one BinLoader upload (port 9090 is never probed: no scan, no `nc`, no `curl`, no
   connect test before the payload)
2. userland handshake + READY
3. `session.status`
4. the agent's fixed attestation callback (one invocation, no host input)
5. bounded copyout into the agent's own block
6. `EVENT` with the attestation result → host verification
7. final `session.status` (resources must be unchanged)
8. controlled exit (BYE)
9. health check on the console

Fail closed (STOP, no retry) on: `kexec` error, callback error, copyout error, unexpected LSTAR
shape, non-canonical kernel pointer, signature mismatch, ambiguous profile, cleanup problem,
`RECOVERY_REQUIRED`, agent hang, unhealthy console.

## 8. Evidence (W9 pack)

commit, exact payload hash, build manifest, expected fingerprints with provenance, observed
fingerprints, observed LSTAR, kbase candidate, all match results, kexec return, callback return,
copyout return (none: caller-buffer write, recorded as such), session state before/after,
resource state, cleanup, target health, profile decision, boot binding decision. No keys, no
session secrets.

## 10. Executed live run (2026-10-05)

Owner rearms the BinLoader -> exactly one upload of the W9 payload (HTTP 200, empty body,
`X-Powered-By: GoldHEN by SiSTRo`), relay log shows the payload connecting from 192.168.1.141
and the session ending cleanly (`host->payload 638 B`, `payload->host 4476 B`, `session
finished`). Result: **PASS**, all host checks green.

Measured on the real console:

* `kexec_rc 0`, callback executed exactly once, **8 byte reads, read only** (no write, no
  `wrmsr`, no second call), callback status `OK`
* LSTAR `0xffffffff998f41c0` -> kbase candidate `0xffffffff998f4000` (page offset `0x1c0`),
  identical to the userland `get_kernel_base()` value -> cross check MATCH, slide
  `0xffffffffc9824000`
* **`strict_matches: 7/7`, `strict_mismatches: 0`**, `structural_observations: 1` (aperture
  `0xffffe7b0e4800000`, `STRUCT_OK`) - host-side recomputation `verified: true`, `problems: []`
* the live aperture value differs from both the pinned image and the phase-9 run: live proof
  that `STRUCTURAL_ONLY` is the correct policy for it; as a fingerprint it would have stopped
  this run spuriously
* session hygiene: 2 requests (status before/after), BYE captured (`reason CLIENT_CLOSE`,
  cleanup `COMPLETE`, `resources: []`) - the W8-D1 root cause is thereby confirmed live with the
  corrected relay, no recovery state, agent exit 0
* health after exit: FTP 2121 banner, 3232 banner, ICMP - loader port untouched, no leftovers

Decision recorded, no promotion: **`PROFILE_MATCH_CANDIDATE`** only. No W5 profile was written,
no `profile_sha256`, no boot binding - `BOOT_ID_UNVERIFIED` / `PROFILE_UNBOUND` stay until the
owner reviews this evidence pack and a profile is created from the reviewed decision. No
capability opened: `kernel.read` stays `OPERATION_DEFERRED`.

Evidence pack (live): `~/07-evidence/20261005T202857Z_ps4rf_p4w9-live` - `VERIFY_OK`
(`live-evidence.json`, `relay-log.txt`, artefact manifest + `SHA256SUMS.ps4.txt`,
`window-policy.json`, summary).

## 9. Deliberate boundaries of this wave

* **No core change.** The frozen registry (35 operations) is untouched: the attestation is not
  an operation, so there is no new primitive and no alternative dispatch path. Verified by test
  (`kernel.attestation` is absent from `default_registry()`). If a request-driven attestation
  operation is wanted later, it is an R3 core revision with its own §70 record — not a W9
  side effect.
* The callback runs only if a session reaches `ACTIVE` and the host asks for a `session.status`
  first; without an established session no privileged code runs.
* W8 artefacts are untouched: the W8 profile build is instruction-identical to the reviewed
  artefact (objdump diff: 0 lines); only the embedded build-id string differs, because the build
  id hashes source text that now carries the `#ifdef PS4RF_TARGET_ATTEST` code.
