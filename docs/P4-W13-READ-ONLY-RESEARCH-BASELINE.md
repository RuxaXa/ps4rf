# P4 W13 — Read-Only Kernel Research Baseline (offline first)

Status: **offline only**. `W13 OFFLINE READY` when this document, the modules and the tests are
green. **No live upload, no rearm, no console contact, port 9090 untouched, no writes, no new
privileged subsystem primitive.**

The W12 primitive is verified (`PS4RF KERNEL_READ_L1 VERIFIED`, tag `PS4RF-KERNEL_READ_L1-VERIFIED`,
live run `RUN-0aa2093b16472b39`). W13 turns it into a *repeatable, bounded, auditable* read-only
research instrument — without loosening a single W12 rule.

## 1. The frozen W12 contract (unchanged, no relief for convenience)

| invariant | where it is enforced |
| --- | --- |
| no raw kernel VA in the request — `region` + `offset` + `length` only | `tools/profiles/kread.py` (`parse_request`, `is_raw_address_key`, `KREAD_SCHEMA_RAW_ADDRESS`) |
| `MAX_READ_LEN` 4096, region window bounded, no cross-region read | `tools/profiles/kread.py`, `tools/profiles/regions.py` (`MAX_READ_LEN`, `resolve_read`) |
| profile binding mandatory | `tools/profiles/binding.py`, `tools/profiles/kread_capability.py` |
| boot binding mandatory | `tools/profiles/binding.py` (`BootBinding`), `KREAD_STALE_BOOT_ID` |
| stored VerificationEvidence mandatory, rehashed | `tools/hostctl/kreadstore.py` (`load_verification_by_sha256`), `tools/hostctl/kreadlive.py` (`derive_capability_record`) |
| W4 approval mandatory | `tools/primitive_iface/gate.py` (`min_assurance_for_grant['kernel'] = PROVEN`) |
| `NATIVE` alone is at most `OBSERVED` | `tools/primitive_iface/schema.py` (F7 finding), `kread_capability.py` |
| runtime VA resolved internally only, never requested | `tools/profiles/regions.py` (`resolve_runtime`, `checked_kernel_address`) |
| no kernel writes, no arbitrary calls, no dump | payload scope (`ps4rf.kernel.read.bounded.v1`), W12 §1 prohibitions |

W13 adds no new request field, no new operation, no new region and no new payload.

## 2. Promotion policy (no implicit promotion)

`IDENTITY_ONLY` · `APPROVED_READ` · `STRUCTURAL_ONLY` · `UNRESOLVED` — implemented in
`tools/research/classification.py`.

A region becomes `APPROVED_READ` only when **all seven** criteria hold, each checked against data
this repository carries:

1. `w5_locator` — the profile carries `locators.<locator>` with `kind: rva` and the registry's rva,
   and the W9 attest table names the same rva/length
2. `provenance_complete` — every file the entry names as provenance exists
3. `profile_binding` — locator `module: kernel`, locator policy agreeing with the identity status
4. `section_permissions_plausible` — declared permissions plausible for the attested kind
   (`static`+strict → `r--`/`r-x`, `relocated` → `rw-`, `structural` → `r--`)
5. `no_known_instability` — not the known boot-dependent region, not `STRUCTURAL_ONLY`
6. `bounds_unambiguous` — rva and length pinned, `0 < length <= MAX_READ_LEN`, no overlap
7. `review_decision` — an explicit documented decision (rationale/purpose) in the module

Rules that follow from the owner's mandate and are enforced in code:

* no region is promoted because a locator exists: the review decision is required in addition;
* no region is promoted because an interesting rva is known;
* `aperture_global` stays `STRUCTURAL_ONLY` (boot dependent: pinned `0xffff82dae4800000` vs
  phase-9 live `0xffffe26de4800000`) — observed, never trusted, never planned;
* `UNRESOLVED` stays unreadable (`KREAD_UNRESOLVED_REGION`), in no plan, in no dataset;
* `IDENTITY_ONLY` regions keep their identity role (image identity, LSTAR/kbase anchor, boot-time
  binding) and are excluded from the research path — the plan, the dataset and the artifact builder
  all refuse them.

## 3. Region classification matrix

`ps4rf.research.region-classification.v1` — counts: {'IDENTITY_ONLY': 3, 'APPROVED_READ': 5, 'STRUCTURAL_ONLY': 1, 'UNRESOLVED': 2}

| region | identity status | W13 class | criteria | rva | length | perms | failing |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `image_elf` | `STRICT_FINGERPRINT` | **`IDENTITY_ONLY`** | 7/7 | 0x0 | 16 | r-x | — |
| `amd_iommu` | `STRICT_FINGERPRINT` | **`APPROVED_READ`** | 7/7 | 0x7ce9e9 | 16 | r-x | — |
| `gbase_vtophys` | `STRICT_FINGERPRINT` | **`APPROVED_READ`** | 7/7 | 0x815bbc | 16 | r-x | — |
| `code_anchor` | `STRICT_FINGERPRINT` | **`APPROVED_READ`** | 7/7 | 0x4cf6a0 | 24 | r-x | — |
| `xfast_entry` | `STRICT_FINGERPRINT` | **`IDENTITY_ONLY`** | 7/7 | 0x1c0 | 8 | r-x | — |
| `copyout_prologue` | `STRICT_FINGERPRINT` | **`APPROVED_READ`** | 7/7 | 0x2bd6a0 | 8 | r-x | — |
| `prison0_static` | `STRICT_FINGERPRINT` | **`APPROVED_READ`** | 7/7 | 0x111fa18 | 8 | rw- | — |
| `aperture_global` | `STRUCTURAL_ONLY` | **`STRUCTURAL_ONLY`** | 6/7 | 0x23d3df8 | 8 | r-- | no_known_instability |
| `boottime` | `STRICT_FINGERPRINT` | **`IDENTITY_ONLY`** | 4/7 | 0x224c6c8 | 16 | — | w5_locator, profile_binding, section_permissions_plausible |
| `boottime_node` | `UNRESOLVED` | **`UNRESOLVED`** | 3/7 | — | — | — | w5_locator, profile_binding, section_permissions_plausible, bounds_unambiguous |
| `boottime_bintime` | `UNRESOLVED` | **`UNRESOLVED`** | 3/7 | — | — | — | w5_locator, profile_binding, section_permissions_plausible, bounds_unambiguous |

Decisions in words (each one documented in `REVIEW_DECISIONS`):

* **`image_elf` → `IDENTITY_ONLY`** — the bootstrap identity window: its bytes *are* the image identity (ELF header at the image base) and the phase-A bootstrap verification reads exactly this window. A research read would duplicate an identity read and add no fact, so it stays the identity window it was approved as (BOOTSTRAP_VERIFY_REGION).
* **`amd_iommu` → `APPROVED_READ`** — re-read the AMD IOMMU anchor window and archive it as a content-addressed research artifact (A1 anchor identity at the live boot)
* **`gbase_vtophys` → `APPROVED_READ`** — re-read the Sony gbase_vtophys anchor (ASCII string constant in the read-only executable image segment) as a structural archive fact of the live image
* **`code_anchor` → `APPROVED_READ`** — archive the 24-byte code window of the A3 anchor (function prologue) for disassembly-side comparison against the pinned image bytes
* **`xfast_entry` → `IDENTITY_ONLY`** — the LSTAR/kbase identity anchor: the kbase of every read is derived from it (kbase = LSTAR - rva). It identifies the boot; it is not a research target, and reading it as research could only re-derive what the session already proved.
* **`copyout_prologue` → `APPROVED_READ`** — archive the copyout prologue (SDK fw_defines K1352_COPYOUT) as the disassembly entry fact for later offline analysis
* **`prison0_static` → `APPROVED_READ`** — archive the relocated pointer window (SDK fw_defines K1352_PRISON_0): the live value minus the verified slide is the one structural fact the pinned image holds
* **`aperture_global` → `STRUCTURAL_ONLY`** — boot dependent by agreement (pinned image value and phase-9 live value differ), so never a byte fingerprint and never a trusted identity source. W13 keeps it STRUCTURAL_ONLY: not a research read target, not in the plan.
* **`boottime` → `IDENTITY_ONLY`** — the FW13.52 boot-binding source (W11.2). Its own profile requirement states that no W5 locator is promoted for it yet, so kernel.read stays deferred: it is an identity/binding window, not an approved research read.
* **`boottime_node` → `UNRESOLVED`** — not pinnable: the evidence names two different rvas for the node and the entry itself says the variable, not the node, is what gets read. Never readable.
* **`boottime_bintime` → `UNRESOLVED`** — MEDIUM confidence only and adjusted by the timekeeping routine on every tick, so its low bits move within a boot. Not sufficiently proven; the candidate rva stays in the evidence and never becomes readable.

## 4. Research read plan

`ps4rf.research.read-plan.v1` · plan id `9c564ee2dad782d92e6e6758ea818a70dd44b72568bbbb7ce29e1a261eb0b58f` · **live status `NOT_RELEASED`** ·
profile `4a6f575c8b1aa790…`

| priority | region | locator | rva | offset | length | expected datatype |
| --- | --- | --- | --- | --- | --- | --- |
| 1 | `amd_iommu` | `kernel.attest.amd_iommu` | 0x7ce9e9 | 0 | 16 | 16-byte window inside the read-only executable image segment (section text / permissions r-x): an ASCII string constant, "AMD IOMMU\0iommu " |
| 2 | `gbase_vtophys` | `kernel.attest.gbase_vtophys` | 0x815bbc | 0 | 16 | 16-byte window inside the read-only executable image segment (section text / permissions r-x): an ASCII string constant, "gbase_vtophys\0gb" |
| 3 | `code_anchor` | `kernel.attest.code_anchor` | 0x4cf6a0 | 0 | 24 | machine code window (function prologue) |
| 4 | `copyout_prologue` | `kernel.attest.copyout_prologue` | 0x2bd6a0 | 0 | 8 | machine code window (function prologue) |
| 5 | `prison0_static` | `kernel.attest.prison0_static` | 0x111fa18 | 0 | 8 | relocated 64-bit pointer (image value + verified slide) |

Per entry the plan carries: region, offset, length, purpose, expected datatype, max length, profile
provenance and the reason the read is safe (owner's §4). The plan is derived from
`classification.approved_read_regions()` — nothing is hand-listed, so a region that loses a criterion
leaves the plan automatically.

Rules the plan obeys (`PLAN_RULES`, all tested):

* one bounded read per entry; region + offset + length only, never an address
* only regions whose W13 class is APPROVED_READ may appear
* offset + length stays inside the region, length <= region max_size <= MAX_READ_LEN (4096)
* the read is bound to the active profile and to the boot the session proved
* a read is authorised by stored VerificationEvidence plus a W4 approval, per read, per session
* the plan itself authorises nothing: it is a reviewed proposal, not a capability

## 5. Target: runtime kernel inventory (read-only facts only)

Collected with `kernel.read`: code fingerprints, small global structures, pointer shapes, section
identity, already-known dispatcher/handler regions, known profile locators — each as a bounded
window with a content hash.

Not in W13: whole-kernel dump, blind scanning of large ranges, unbounded pointer chasing, foreign
arbitrary addresses. Every read that enters the research dataset has to pass the W13 class gate
(`APPROVED_READ`), the frozen request model and the W12 authorisation chain.

## 6. Bounded pointer follow

`ps4rf.research.pointer-follow-policy.v1` — implemented in `tools/research/pointer_follow.py`.

* a pointer is followed only when it comes from an APPROVED_READ result of this W13 plan
* the pointer must be canonical: a relative rva inside the image window, or a kernel-half address that the verified kbase maps back to an rva
* the mapped target must fall into a registered region whose W13 class is APPROVED_READ; otherwise UNRESOLVED_TARGET and STOP
* the target region must be approved separately: a follow never inherits the approval of the read that produced the pointer
* an expected class or range, when given, must hold; a follow is refused otherwise
* a follow produces a candidate request only -- one bounded read, its own session, its own evidence, its own approval. No loops, no chaining, no list walking

Refusal reasons (each one means STOP): `POINTER_SOURCE_NOT_APPROVED_READ`, `POINTER_NOT_CANONICAL`, `UNRESOLVED_TARGET`, `TARGET_REGION_NOT_APPROVED_READ`, `TARGET_REGION_MISMATCH`, `TARGET_OUT_OF_REGION_BOUNDS`, `POINTER_CLASS_MISMATCH`, `POINTER_NOT_FROM_READ_RESULT`.
Expected classes: `code` → ['r-x'], `read_only` → ['r--', 'r-x'], `data` → ['rw-'].
A follow returns a **candidate request** (`region`, `offset`, `length`) plus
`automatic: false` — it never reads, never chains and never inherits an approval.

## 7. W6 integration contract

`ps4rf.research.w6-contract.v1` — implemented in `tools/research/w6_contract.py`.

* workflow: `kernel.read evidence → normalized artifact → W6 differential → OBSERVATION candidates`
* artifact: `ps4rf.differential.inventory.v1`, **relative locators only**; forbidden inside the
  artifact: `runtime_address`, `absolute_address`, `abs_addr`, `slide`, `kbase`, `boot_id` — the boot and
  profile binding stays in the research dataset index so two boots stay comparable
* differential: `python -m tools.differential.cli diff artifacts <before> <after>`
* candidates are `OBSERVATION` with W4 impact `NONE`
  (`tools/differential/candidates.py`) — no W4 reason removed, no provider allowed, no assurance
  raised, no region promoted, no plan entry added; a candidate never triggers a read by itself

## 8. Research dataset

`ps4rf.research.snapshot-index.v1` / `ps4rf.research.snapshot.v1` — implemented in `tools/research/dataset.py`.

Per snapshot exactly: `profile_sha256`, `boot_id`, `kbase`, `read_run_id`, `region`, `offset`,
`length`, `sha256`, `timestamp` (plus `snapshot_id` derived from the facts, the relative `rva`, the
locator, `sensitive_hints`). Raw bytes live content-addressed under `blobs/<sha256>`.

* immutable per boot: a boot's snapshots are only ever appended, and the index is ordered by
  `(boot_id, region, offset, length, sha256)` so `index_sha256` is deterministic;
* duplicate snapshots deduplicate to one blob and one index entry;
* a read-run record is only archived when it records `outcome READ`, exactly one provider entry and
  an intact run separation;
* sensitive-data rule: a window matching 7 patterns (password/passwd/
  secret/api-key/Authorization/PRIVATE KEY/long base64) is flagged `sensitive_review_required` and
  never expanded automatically — there is no auto-expansion anywhere in W13.

## 9. Multi-read is not automatic

W13 does **not** turn the one-shot provider into an unbounded multi-read primitive. One bounded read
per released live run stays the rule. A future multi-read needs its own design and review with:
`max_regions`, `max_total_bytes`, per-region bounds, a single callback, deterministic ordering and an
all-or-stop policy — specified offline first, reviewed separately.

## 10. Verification stays active for every session

Every new session still goes: stored VerificationEvidence → rehash (`STORE_REHASH_MISMATCH` on any
change) → derivation for *this* session/boot/profile/read run → W4 approval. There is no durable
global `PROVEN` state: the W12-A3 receipt is bound to the content hash of the derived record, so a
`PROVEN` record from an earlier session can never be reused.

## 11. First proposed live region

**`amd_iommu`** (priority A, offset 0, length 16, locator `kernel.attest.amd_iommu`, rva
`0x7ce9e9`, section `text`, permissions `r-x`).
Rationale: real W5 locator and W9 attest entry at the same rva, complete provenance, one unambiguous
profile binding, static strict fingerprint (no drift), smallest useful window (16 B), lowest crash
probability (a read-only window inside the executable image segment), and the phase-9 anchor A1 is
already the identity anchor of the strict score — so the read has research value *and* is trivially
comparable against the pinned image.

### 11a. Pre-live section/permission consistency check (resolved)

The earlier wording "rodata string window" in this document was wrong and is withdrawn: the pinned
profile declares the region inside the **`text`** section with **`r-x`**, and the pinned kernel image
confirms it at segment level.

| fact | value | source |
| --- | --- | --- |
| module | `kernel` | profile locator `kernel.attest.amd_iommu` |
| section | `text` | profile locator `section` (the pinned dump carries no section header table: `shnum = 0`, so the section name is the profile's promoted statement, not re-derived here) |
| section permissions | `r-x` | profile locator `permissions` **and** the pinned image's own program header: PT_LOAD flags `r-x`, vaddr `0xffffffffd00d0000`, filesz `0xcfe758` -> rva window `[0x0, 0xcfe758)`, which contains `0x7ce9e9` |
| rva | `0x7ce9e9` (8186345) | profile locator value + W9 attest table entry |
| exact length | 16 | profile expected bytes length + attest table |
| expected bytes | `414d4420494f4d4d5500696f6d6d7520` (`AMD IOMMU\x00iommu `) | profile `expected_bytes` |
| expected SHA256 | `0e5db66bb6e045a242282881beb9525d80f00efdccd3586da7d2692e74d4cc5f` | hash of the profile's pinned bytes, byte-identical to the pinned image at that rva |
| provenance | `kind: evidence`, pinned image sha256 `cf157ffdbae872a20bbb9a46c8518b53d96c1ed75d4e73878466a295d92eca35`, source "kernel.bin (pinned FW13.52 image) + W9 live attestation (byte-exact match)" | profile locator provenance + `native/target/gen_attest_table.py` (`static`/`strict`, phase-9 reference) |
| expected data/code type | 16-byte window inside the read-only executable image segment (`text` / `r-x`) whose content is an ASCII string constant — **not** a rodata section claim | resolved above |

Verification performed offline, read-only, against the pinned artifacts: `kernel.bin` hashes to the
pinned sha256; file offset 0 yields the ELF header (`7f454c46...`, matching `image_elf`); file
offset `0x7ce9e9` yields exactly the expected 16 bytes and their expected SHA256; the containing
PT_LOAD segment is `r-x`. The wording rule is now enforced in code
(`classification.datatype_section_conflict`): a decision or plan text may only name the section the
pinned profile declares, and a `rodata` claim on this region fails the classification criteria.

Alternatives in priority order (all offline, all bounded): `gbase_vtophys` (16 B, ASCII string
constant inside the `text` / `r-x` segment),
`code_anchor` (24 B, code prologue — richest for disassembly), `copyout_prologue` (8 B, code),
`prison0_static` (8 B, relocated pointer — most interesting structurally, but it needs the verified
slide and is therefore last).

Nothing is released: a live read needs the owner's review of this document plus its own approval,
session, stored evidence and rearm.

## 12. Tests

`tests/test_w13_research_baseline.py` — 58 tests, including the owner's §12 list and the
section/permission consistency checks (pinned `amd_iommu` facts, "never described as rodata", the
rule going red on a contradiction): IDENTITY_ONLY not
generically readable, APPROVED_READ readable, STRUCTURAL_ONLY rejected, UNRESOLVED rejected everywhere
(`KREAD_UNRESOLVED_REGION`), stale boot, wrong profile, missing VerificationEvidence, pointer follow
outside an approved target (`UNRESOLVED_TARGET` included), differential output without authorisation
effect, deterministic dataset hashes, duplicate dedup, raw runtime VA still refused. Plus module
self-tests (`tools/research/cli.py --self-test`) for classification, plan, dataset, pointer policy and
the W6 contract round trip.

## 13. Deliverables map

| deliverable | artifact |
| --- | --- |
| Region Classification Matrix | `tools/research/classification.py`, `--matrix` |
| Promotion Policy | same module, `CRITERIA` + `REVIEW_DECISIONS` + `classification_problems()` |
| Research Read Plan | `tools/research/read_plan.py`, `--plan` |
| Dataset Schema | `tools/research/dataset.py`, `SCHEMA_INDEX`/`SCHEMA_SNAPSHOT` |
| W6 Integration Contract | `tools/research/w6_contract.py`, `--contract` |
| Pointer Follow Policy | `tools/research/pointer_follow.py`, `--pointer-policy` |
| Tests / Regression Suite | `tests/test_w13_research_baseline.py` (+ full W2→W13 suite) |
| Evidence Pack + Hashes | `07-evidence/<stamp>_ps4rf_p4w13-offline-ready/` |
| first proposed live region | `amd_iommu` (see §11) |

Boundaries kept: no `kernel.write`, no `kernel.call`, no `kernel.dump`, no GPUVM write/map
manipulation, no KeyMgr mutation, no CCP submit, no SAMU invocation, no SBRAM writes, no fuzzing, no
races. No live step in W13.

## Revision

commit `6a97421b716706cd708cd9b889427d8d8a3fbbb6` (W13 modules are new files; nothing of W12/W9 changed)

* `tools/research/classification.py` 28a1b7e925ca26dec98c84bf2065ac4333c663d68bc825b788ba9f0acb04e290
* `tools/research/read_plan.py` 1c781ab426443d348c38e0515184776c1fc1352613e84f158e49c4ed40b4e451
* `tools/research/dataset.py` 1cf752e9d0bc81dc6add42a7444f84fa47c27743500011556117af1e364e2d2b
* `tools/research/pointer_follow.py` 74a771057201bd729045af7d0d19630bb66c2e860852d956fd3fb3880d2e94ef
* `tools/research/w6_contract.py` 0e0b0fe2ee973292d409f4c4a8a33c36d828e2d6d2990382d52213af79a7bbce
* `tools/research/cli.py` cf267aa7383d75e673fd7f8c255ef644aac91c19f3a95301214da5a59c0f631c
* `tests/test_w13_research_baseline.py` 01cd7581792188586b5a22041cec47dd72686cd8e2580972d38ec6255e0b0cd4
