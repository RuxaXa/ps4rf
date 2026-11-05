# P4-A observation windows — the CCP/KeyMgr observation set of the W16 live step

Scope: the five read-only **observation** windows of the Track A live step, added to the W12/W16
region registry (`tools/profiles/regions.py`) and to the compiled region table of the new target
artefact. This document is the *provenance* of those entries: it carries the exact numbers, the
campaign sources (with their sha256) and what each window answers. Nothing here is a new claim —
every number is quoted from the campaign documents listed below.

## 0. Why these windows exist

Track A (`campaign-ccp-20261007`) ranked 35 CCP/SAMU/keymgr candidates offline. Two of the open
questions are *live* questions and can only be answered by reading bytes on the console:

* **K-2** (unbounded sleep retry in the keymgr claim/bind path): does the keymgr slot pool ever
  leave its idle state in a stock boot, i.e. are the defect paths exercised in operation at all?
* **CCP staging state**: does the eipkas/CCP staging page hold a message after a stock GPU
  workload, and what do the submit-side globals hold?

Both are **read-only** questions. The owner decision of 2026-10-07 (`work/A-LIVE-DECISION-20261007.md`,
sha256 `ce86bbd4…`) chose the authorization shape **(B) payload bootstrap self-read** for these
windows and the window set *W16 identity windows + keymgr slot pool + K-L1 + CCP-L1 in one
artefact*.

## 1. The windows (exact numbers)

| region | rva | length | what it is |
|---|---|---|---|
| `keymgr_ctx_lock` | `0x2668008` | `0x58` (88) | keyMgrCtx sx-lock object (name pointer at +0), the claim/bind sleep channel at `0x2668028` and the neighbouring counters (`0x2668030/0x2668038/0x2668040`) |
| `keymgr_sm_gate` | `0x266C800` | `0x60` (96) | "sm loaded" gate (u32 at +0), SM handle at +8, SM sx-lock at +0x10 and the following service fields |
| `ccp_stage_msg` | `0x2694000` | `0x40` (64) | the eipkas ioctl's kernel staging page: one CCP message (memcpy of exactly 0x40 bytes from the user buffer, C-97) |
| `ccp_stage_ptr` | `0x2694060` | `0x8` (8) | the submit-side global the second-stage builder is handed (`[0x2694060]` as its third argument, C-30/C-100) |
| `ccp_client_a_buf` | `0x2658000` | `0x80` (128) | the CCP client-A staging buffer: one 0x80-byte command staged before submit (`cmd=0x09134000, size=0x80`, `B-doublefetch.md`) |

The keymgr slot pool `0x266C8E0` (length `0x800`, 64 records stride `0x20`) is **already** a
registered observation window of the W16 revision candidate (`keymgr_pool`); the three K-L1
addresses together are `0x2668008` (len `0x58`) + `0x266C800` (len `0x60`) + `0x266C8E0`
(len `0x800`) = 2,232 bytes (`A-keymgr-lifetime.md`, section "candidate K-L1-poolstate").

## 2. Sources (read-only, quoted)

| source | sha256 | what it supplies |
|---|---|---|
| `campaign-ccp-20261007/work/A-keymgr-lifetime.md` | `0a5e8d01be6470a8cc182283a979281dde4add9cf1ee5ea6757916e5ecef0f09` | K-L1 window list + lengths, pool layout, PASS/FAIL criterion |
| `campaign-ccp-20261007/work/B-doublefetch.md` | `f8cf6da8ecf4784798b4998f2049e193035e5f55cc73f3a5b982e829406a2f8e` | CCP client-A staging buffer `0x2658000`, 0x80-byte message |
| `campaign-ccp-20261007/work/A-validation-matrix.md` | `b2d1c404c6439eb01abf5f117969536be93f974a488700e20c954b3658a95e48` | eipkas staging page `0x2694000` (C-97/C-99, 0x40-byte messages), `0x2694060` (C-30/C-100) |
| `campaign-ccp-20261007/work/TOP10-REPORT-20261007.md` | `cad0b36576ef611850777dde0bb8dc303e7ab1f255ac79b7cca7ef1c9d1555f0` | section 5 "live-read proposals" (K-L1 / CCP-L1) |
| `campaign-ccp-20261007/work/A-LIVE-DECISION-20261007.md` | `ce86bbd4f50100d0f1aab3fb428e7df8d15933e3dccf3e66282ead6b219c7908` | the owner decision: shape (B), this window set |

The campaign lives outside this repository (`~/audits/ps4b-soc-workbench/`); the hashes above pin
the exact revisions the numbers were taken from.

## 3. Classification rules carried into the registry

* Every window is **`STRUCTURAL_ONLY`** — runtime state whose bytes change within a boot. A byte
  fingerprint of them would fail a healthy console, so they can never serve as an identity source
  and never enter the W16 binding window set (`binding_window_indices()` selects STRICT rows only).
* Every window is pinned by `rva` + `length`; `length` is the hard cap of one read into it and
  stays well inside `MAX_READ_LEN` (4096).
* Reads are **one window per session** on the same lifetime cursor as the binding step: session 1
  spends its single privileged transition on the boot binding, sessions 2–6 read the five STRICT
  binding windows, sessions 7–12 read these six observation windows (pool + five here). The
  "one privileged transition per session" invariant stays literal.
* No host value reaches any of this: the row indices are compile-time constants of the generated
  table (selected by provenance, not by a hand-written list in the module), the offset is 0 and
  the length is the row's own.

## 4. What a wave answers (PASS/FAIL, per source)

* **K-L1**: PASS = the pool shows at least one record with `count>0`, `tag != 0xFFFFFFFF` or a head
  other than record `0xBE` (pool hot ⇒ the K-2 defect paths are exercised); FAIL = all idle
  (pool cold in that window). Source: `A-keymgr-lifetime.md`.
* **CCP-L1**: PASS = one of the staging windows is non-zero / holds a message-shaped block after a
  stock GPU workload; FAIL = all-zero staging in every observed session. Source: `TOP10-REPORT`
  section 5 + `A-validation-matrix.md` C-97/C-99/C-100.

Neither verdict is a vulnerability claim: both are *observations* that decide whether the offline
candidates K-2 / BDF-CCP-01 are reachable in operation at all.
