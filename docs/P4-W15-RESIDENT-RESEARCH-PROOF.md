# W15 — resident kernel.read research proof (offline)

**Wave:** W15 · **Status:** offline, in progress · **Live:** not authorised, not started (no upload,
no rearm, loader port untouched).

Goal: prove that the bounded `kernel.read` provider verified in W12 works in a *later session of the
same resident agent* — one bootstrap, several authenticated sessions, each with its own evidence,
capability and one-shot release.

## 1. Status of the read trigger (review item 1) — already data-driven

The W14 build does **not** contain the old fixed probe path. Evidence:

| question | answer | where |
| --- | --- | --- |
| does the target request carry `region_index`/`offset`/`length`? | yes | `native/target/ps4rf_optable_data.h` args table lines for `kernel.read` (`region_index`, `offset`, `length`, all `PS4RF_T_INT`, required) |
| is `kernel.read` routed to the privileged provider? | yes | same table: `PS4RF_ROUTE_PRIVILEGED_PROVIDER` / `PS4RF_TARGET_WIRED` (catalog revision R3, W14) |
| does the payload still pick the region itself? | **no** | `ps4rf_kread_probe_request()` no longer exists; the only caller of `ps4rf_kread_run()` is the wired provider `ps4rf_stub.c` (one call site), which passes the *parsed request* |
| who owns the bounds? | the provider | `ps4rf_kread_run(info, region_index, offset, length)` — index < compiled count, strict/structural identity, length 1..4096, checked add, region containment |
| is an address inexpressible? | yes | `ps4rf_kread.h`: "the host supplies no address: the request is (region index, offset, length) only… There is no `addr` field anywhere" |

So W13-C1 is **already implemented** (landed with the W14 wiring). No second read path exists. What
W15 adds is the *proof*: the resident rehearsal, the mutants and the evidence pack.

## 2. The window (review item 7)

* region `amd_iommu`, **compiled index `1`** (`PS4RF_KREAD_REGION_IDX_AMD_IOMMU`), identity
  `STRICT_FINGERPRINT`, RVA `0x7CE9E9`, region length 16 (`ps4rf_kread_regions.h`).
* first resident read: offset `0`, length `16`, expected bytes
  `414d4420494f4d5500696f6d6d7520`, expected SHA256
  `0e5db66bb6e045a242282881beb9525d80f00efdccd3586da7d2692e74d4cc5f`.
* no other region in W15.

## 3. Event/response record (review item 3) — complete

`kernel.read.bounded` (`ps4rf.kernel.read.bounded.v1`) already reports: `requested_region`,
`requested_region_index`, `region_identity`, `region_rva`, `requested_offset`, `requested_length`,
`offset_length_sum`, `copied_len`, `bytes_hex`, `sha256`, `sha256_status`, `resolved_rva`,
`resolved_runtime_va`, `callback_executed`, `cb_status(_name)`, `kexec_rc`, `run_status(_name)`,
`lstar`/`kbase_candidate`/`kbase_sdk`/`cross_check`, plus the negative claims
(`host_supplied_address: 0`, `writes_to_kernel: 0`, `single_callback: 1`, `retry: 0`). The host
re-derives every value from its own copy of the expectation.

## 4. W14-D1 (metadata deviation) — fixed with this wave's build

`agent_version` was a hardcoded literal (`ps4rfd-target-w8`) that survived two waves because only the
build id, label and context were asserted. Now a single constant `PS4RF_AGENT_VERSION`
(`ps4rfd-target-w15`) in `ps4rf_agent.h`, used at the HELLO site, and the manifest gate refuses a
literal or a missing constant.

## 5. W15 offline checklist

- [x] review item 1 — data-driven trigger verified (see §1)
- [x] §10 — `agent_version` from a constant; new native build (console + dev-host)
- [x] §1/§4/§6 — the resident rehearsal **runs green offline**: session V (bootstrap verification,
      persisted evidence) → A (`session.status`) → B (fresh session; load+rehash; own SESSION
      capability; fresh §70 approval + fresh W13 release; one bounded read of `amd_iommu / index 1 /
      0 / 16`; exactly one provider entry; the pinned bytes and hash; cleanup COMPLETE) → C (fresh
      session; the *same* release refused with `W13_RELEASE_ALREADY_CONSUMED` **before** the provider
      entry, provider entries 0; `session.status`; authenticated `session.shutdown` → BYE
      `ADMIN_SHUTDOWN`) → silence. Driver: `tools/hostctl/live_w15.py`, proved by
      `tests/test_w15_resident_research.py` against the dev-host daemon with the simulated image.
- [x] §7 — the pinned window comes from the profile's locator (`kernel.attest.amd_iommu`,
      rva `0x7CE9E9`, `414d44…`, sha256 `0e5db66b…`); the rehearsal mints its own §70 approval and
      W13 release per run (`fixtures/approval-w15-read1.json`, `fixtures/release-w15-read1.json`)
- [x] the wired read adapter: `kernel.read` has been wired to the provider since W14, so the record
      arrives as the *response*; `kreadlive.accept_trigger_response` accepts both frozen forms
      (deferred privilege + captured event, and the wired record) and refuses a bare `OK`
- [x] build gates: the console build refuses the simulated image
      (`PS4RF_TARGET_KREAD_SIM`), the host build links it only with the switch, and
      `agent_version_gate()` keeps the version string a constant (W14-D1)
- [ ] §8 — read evidence → W13 dataset blob → snapshot index → W6 differential input, result capped
      at `OBSERVATION` (no authorization change)
- [ ] §9 — the mutants (in progress, `tests/test_w15_mutants.py`)
- [ ] §11 — evidence pack, full regression, `W15 OFFLINE READY`

## 6. Facts for the next session

* Repo `~/projects/ps4rf`, branch `main`.
* W15 scratch: `~/.hermes/cache/scratch/ps4rf-w15/` (`console-w15/`, `dev-host/`, logs).
* W15 console artefact (KREAD + resident, warning-free, reproducible twice, 0 relocations,
  0 undefined symbols): build id `032ffa3eb281384edeffcbb11c84e242`, ELF
  `2ecec70fb6e19e867fc48b081655970898c7df68b1940c6833f7e679336ec66e`, BIN
  `99825e159d75140ceb3a0a072a7f1956511d16a6214d6d62759d244945ec5ee6`, manifest
  `4daff994d6b5b9c8610e1e817173463d365886835a64f690ca18311c0ee68651`.
* The resident rehearsal is driven from `tools/hostctl/live_w14.py`'s shape (controller + dev-host
  daemon) plus the W12/W13 host chain in `tools/hostctl/kreadlive.py` (store, verification, §70
  approval, release, per-session capability derivation).
* W14 live PASS evidence: `~/07-evidence/20261006T_w14b-live/`.
