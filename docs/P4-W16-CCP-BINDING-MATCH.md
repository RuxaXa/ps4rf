# P4/W16 — live byte-match of the CCP/keymgr binding windows

**Status: PREPARED OFFLINE — NOT EXECUTED. No live action, no approval, no promotion.**
Owner review pending (section 6). The revision candidate `profile-13.52-ccp1.json` stays a
*candidate* until the live byte-match below has run and passed.

---

## 1. Why W16 exists

`docs/P4-CCP-ACCEPTANCE-REQ.md` (section 7) states the promotion precondition for the CCP profile
revision verbatim: *"...the binding windows need a live byte-match (W16) before the revision can be
promoted."* Revision 2 adds six keymgr/CCP locators to `profiles/fw1352/profile-13.52-ccp1.json`;
five are 16-byte fingerprints taken from the pinned FW13.52 image, the sixth is the keymgr slot
pool. W16 is the read-only live wave that matches them, and nothing more.

W16 therefore has exactly two deliverables:

1. a payload whose compiled region table serves the six windows (this document, section 3), and
2. a read wave that reads each window once, live, and byte-compares it host-side — gated by owner
   approval + release + re-arm (section 6).

## 2. The window set (what gets matched)

| # | compiled index | region | rva | len | policy | expected bytes (pinned image) |
|---|---|---|---|---|---|---|
| 1 | 9 | `ccp_submit_entry` | 0x625330 | 16 | STRICT_FINGERPRINT | `554889e54157415641554154534883ec` |
| 2 | 10 | `ccp_device_gate` | 0x3B2EE0 | 16 | STRICT_FINGERPRINT | `554889e548b9100000000000003831c0` |
| 3 | 11 | `keymgr_claim_entry` | 0x62C570 | 16 | STRICT_FINGERPRINT | `554889e54157415653504989fe488d3d` |
| 4 | 12 | `keymgr_bind_entry` | 0x62BF50 | 16 | STRICT_FINGERPRINT | `554889e54157415641554154534881ec` |
| 5 | 13 | `keymgr_release_entry` | 0x62C610 | 16 | STRICT_FINGERPRINT | `554889e541565389fb488d3de8b90302` |
| 6 | 14 | `keymgr_pool` | 0x266C8E0 | 2048 | STRUCTURAL_ONLY | — (runtime slot state, no fingerprint) |

Sources, both repository files, nothing retyped: the rva and the expected bytes of rows 1–5 are the
locator values of `profiles/fw1352/profile-13.52-ccp1.json`; the pool window is the same file's
`keymgr.snapshot.pool` locator (base + 64 records × 32 bytes), and `profiles/fw1352/ccp-layouts.json`
records the RPMs the windows were decoded at. Both files name the pinned image
(`kernel.bin`, sha256 `cf157ffd…d92eca35`) as their provenance.

Rows 1–5 are *identity* windows: the live bytes must equal the pinned bytes, or the revision is not
this firmware and may not be promoted. Row 6 is an *observation*: the slot pool's bytes are runtime
state (occupancy, tags, generations), so it is `STRUCTURAL_ONLY` — readable as an observation, never
as an identity source, and never part of the fingerprint set. That is the same rule the W9/W10
aperture window already follows.

## 3. The artefact

Built from the repository tree, twice, byte-identical (the build asserts it):

* label `ps4rfd-live-w16-1`, context `fw13-52-resident-w16-1`, build id `2602d86309b574e6ba1c2e207186c9bb`
* `ps4rfd.bin` sha256 `dd1b3681f5624dcfbb0d98364c42161b2f6f10299246308f088e34a12080bcfa`, 83,956 bytes
* `ps4rfd.elf` sha256 `2b87f5a829194d2057b3e6cf29ec35b2a6696aca56ab9ade6a0a48db63f140d0`, 119,248 bytes
* `build_manifest.json` sha256 `5975a6e9fe9b0ddeb524a3444a3e7036b0ef7e797725778672d9267872b0eba8`
* build: `PS4RF_TARGET_KREAD=1 PS4RF_TARGET_BOOTBIND=1 PS4RF_AGENT_RESIDENT=1`
  `PS4RF_AGENT_LABEL=ps4rfd-live-w16-1 PS4RF_AGENT_CONTEXT=fw13-52-resident-w16-1`
  `sh native/target/build_ps4.sh <out> <libPS4-sdk> <psk>` (same PSK as W15; no new key material)
* manifest gates: `verdict PASS`, `kread.ok = true`, 0 relocations, 0 undefined symbols,
  region table 15 rows / 13 STRICT_FINGERPRINT / 2 STRUCTURAL_ONLY / 2 refused UNRESOLVED,
  `registry: tools/profiles/regions.py`
* the BIN carries every resident marker (`B00`…`B10`) and all fifteen region names
* **append-only proof:** against `git show HEAD:native/target/ps4rf_kread_regions.h`, the nine W12/W15
  rows are identical in index, name, rva, length and identity, all nine `PS4RF_KREAD_REGION_IDX_*`
  defines keep their values (boottime stays index 8, the boot-binding row), and the six W16 rows are
  added at indices 9–14.
* delta vs the live-proven R3 artefact (`306903ac…`): +240 bytes of BIN, identical build switches,
  one added region table and nothing else touched in the read path.

## 4. What changed, and why each pin moved

Every change below is either the new data or a *restatement* of a gate that pinned the old nine-row
shape. No check was deleted; the W12/W15 numbers stay recorded in the messages.

* `tools/profiles/regions.py` — six new entries, appended after the W9..W11.2 entries (indices 0–8
  must not move); `CCP_PROVENANCE` names the three repository sources; `registry_problems()` now also
  pins that the five text windows stay `STRICT_FINGERPRINT` and that `keymgr_pool` stays
  `STRUCTURAL_ONLY` and never an identity source.
* `native/target/ps4rf_kread_regions.h` — regenerated (`gen_kread_regions.py --write`); 17 policy
  entries, 15 compiled, 2 refused.
* `native/target/build_manifest.py` (`gate_kread`) — region-table counts restated to 13 STRICT + 2
  STRUCTURAL over 15 rows, `structural_only_regions == ['aperture_global', 'keymgr_pool']`, and two
  new checks: the five CCP/keymgr windows must be in the STRICT set, and `keymgr_pool` must be in the
  compiled table. The W9/W10 window checks are unchanged.
* `tests/test_regions.py` — `CCP_STRICT`/`CCP_STRUCTURAL`/`NON_STRICT_PINNED` membership; the
  aperture test is restated as *the non-strict proven regions*; the locator test now resolves the
  CCP locators against the revision candidate and asserts they are **absent** from the promoted
  profile (the candidate is not promoted); new `test_w16_ccp_windows_match_the_revision_candidate`
  pins every rva/length against the candidate, the append-only indices and the boottime index.
* `tests/test_compiled_regions.py` — the W12-A-D1 deviation test restated 9/11 → 15/17; the wrong
  counts 8/9/11 stay refused as recorded history; the live-shape and simulation checks read the
  compiled count instead of a constant.
* `tests/harness/kread_offline.c` — the simulated image stands for the loaded kernel image and is
  sized to the pinned dump (0x2A00000); the `keymgr_pool` window ends past the W12-era 0x2400000
  stand-in, which the harness's own table check correctly refused.
* `tools/research/classification.py` — six W13 review decisions (five `IDENTITY_ONLY`, the pool
  `STRUCTURAL_ONLY`), `KNOWN_UNSTABLE` extended, and the "single STRUCTURAL_ONLY region" invariant
  restated to the two named regions. Note what this says: **the CCP windows are not research read
  targets.** Their W5-locator criterion fails while the revision is a candidate, so nothing is
  promoted implicitly by this wave.
* `tools/research/binding_match.py` (**new**, offline) — the authorization model for the byte match:
  the window set derived from the registry plus the candidate (never retyped,
  `window_set_sha256 = 74a2596e…`), the approval rules for the scope `w16-binding-match` (which
  refuse the research scope, a release field and any unpinned window), a one-shot ledger bound to
  the revision and the window set, and the byte match itself, which is delegated to the existing
  bounded-event verifier. It deliberately authorises *only* a byte match: no research read, no
  release, no address. `tests/test_w16_binding_match.py` (18 tests) holds all of that down,
  including the refusals (see section 6 for the read path this model would still need).
* `tests/test_target_build.py` — the generated region header joins the generated optable as an
  exempt data table in the "no kernel symbols in target sources" scan (both *record* frozen names;
  neither carries a call or a transition). Every hand-written target source stays scanned.
* `tests/test_w15_resident_research.py` — the cached dev-host rehearsal daemon is now keyed to the
  generated region-table hash. It compiles `PS4RF_KREAD_REGION_COUNT` into its event, so a stale
  cache reported 9 while the table had 15 and failed the rehearsal for the wrong reason.
* `docs/P4-CCP-ACCEPTANCE-REQ.md` — untouched (it is the owner's spec); this document is the W16
  phase record.

## 5. Offline verification (all green, reproducible)

* `gen_kread_regions.py --check` — header in sync with the canonical registry.
* `regions.py --self-test` — `17 policy entries, 15 compiled for the payload, max read 4096 (ok)`.
* registry numbers vs the revision candidate — rva, length (from the fingerprint hex) and policy
  match for all six windows; the layouts artefact agrees on the five text windows.
* `pytest tests/` — the W16-related modules are green (`test_regions`, `test_compiled_regions`,
  `test_kread_offline`, `test_kread_request`, `test_kreadlive`, `test_kread_capability`,
  `test_kernel_read_bounded_event`, `test_profile_binding`, `test_profile_promotion`,
  `test_target_build` (minus the pre-existing failure below), `test_w13_research_baseline`,
  `test_w15_resident_research`, `test_w16_binding_match`).
* `binding_match.py --self-test` — `PASS` (5 windows, window set `74a2596e…`); the window table in
  section 2 was re-checked against the derived set: rva, index, length and bytes agree for all five.
* **Pre-existing red, not caused by W16** (verified by running them on the clean tree at `6db407d`):
  1. `test_target_build.py::test_offline_controller_agent_end_to_end` — the host-side frozen response
     schema for `session.status` does not know the four W15 fields
     (`boot_status`, `boot_detail`, `boot_sec`, `boot_usec`) that the daemon already emits
     (`ARGUMENT_INVALID: unknown result field(s)`).
  2. six `tests/test_boot_binding_live.py` end-to-end cases — `TypeError: 'NoneType' object is not
     subscriptable` in the staged-sheet path.
  Both belong to the W15 surface, not to the region table; neither is touched here, and neither may
  be silently "fixed" inside W16.
* Artifact verification record: `~/.hermes/cache/scratch/ps4rf-w16/w16-artifact-verification.json`.

## 6. The live wave: ready to run, but its read path is an owner decision

Everything offline is built and green (section 3 + 5). What is **missing is not a detail**: no
read path in the repository may serve these five windows today, and that is the project's own
design, not a gap in the payload. The three rules that close the door, each in the file that owns
it:

1. `tools/hostctl/kreadlive.py` — `run_generic_read()` refuses a window that is neither the pinned
   bootstrap region nor carries a release id: *"the window reads <region>, which is not the pinned
   bootstrap region ... and it carries no release id: only the pinned bootstrap window or an
   owner-released window may be read"*.
2. `tools/research/release.py` — a release is refused for every region that is not
   `APPROVED_READ` (`W13_RELEASE_NOT_APPROVED_READ`), and the W13 review keeps these five windows
   `IDENTITY_ONLY` **on purpose**: a fingerprint of the pinned image is not a research read target,
   and W16 must not smuggle one into the research plan to get a release.
3. `tools/research/approval.py` — the approval knows exactly one read scope
   (`w13-research-read`), which by owner rule 3 makes a release mandatory.

So the live byte match needs **one owner decision** about its authorization. Three viable shapes,
smallest first:

* **(B) payload bootstrap self-read (recommended).** Generalise what W11.2 already does for the
  boot window: after the boot binding, the payload reads the five windows itself (compile-time
  indices from the table, offset 0, length 16, one read per session, no host input, no release),
  reports index + bytes in its identity, and the host byte-matches against the pinned bytes (the
  `tools/hostctl/bootpriv.py` shape). Reuses a **live-proven** mechanism, changes no read-path rule,
  keeps the host as the judge. New payload authority: five fixed reads per lifetime — which is
  exactly what the owner would be approving. Build: native (the five-row step + the identity
  fields), host (`verify_binding_block`), gates, mutants, a new artefact.
* **(C) a second, narrower host read scope.** Keep every read host-authorised: the approval
  declares scope `w16-binding-match` instead of the research scope, pins the candidate revision
  hash and the five windows, and authorises one read per window per lifetime with **no release**
  (this is the model already built in `tools/research/binding_match.py`: window set derived from
  the registry + candidate, `window_set_sha256 = 74a2596e…`, one-shot ledger, byte match through
  the existing bounded-event verifier). This is the only shape that touches the frozen read path
  (rule 1 above would have to admit identity windows under this scope), so it is an amendment of a
  rule the owner set — hence the decision, not a patch I make on my own.
* **(A) the designed vehicle: `kernel.snapshot`.** `docs/P4-PRIMITIVE-INTERFACES.md` gives the
  contract — *range policy → read → SHA-256 → compare → only on match are data released; mismatch
  is `PROFILE_MISMATCH`, the buffer is zeroized* — i.e. a profile-declared range compared against a
  pinned digest, which is precisely a binding match, and it cannot leak bytes on a mismatch. It is
  also `deferred`, has no provider, and the W13-C2 scope decision froze it: *"They stay deferred,
  unwired and without a provider."* Building it is the Stage-0…3 program of
  `P4-CCP-ACCEPTANCE-REQ.md` (capability gate `PROVEN`, freeze gates G1–G8), not a W16 step.

**What W16 needs from the owner, therefore, is the choice above** — plus, once the shape is chosen
and built, the usual gates: a §70 approval transcribed for the wave, artifact review of the new
payload, a fresh single-use re-arm, exactly one upload, one read per window, host-side byte match,
evidence archived. Until then: nothing is uploaded, the console is not contacted, and the revision
candidate stays a candidate (its schema validation and canonical stamp `88c1279f…` are already
done, so the byte match is the only remaining precondition).

**Stops that stay in force:** no upload for ping/status/telemetry; the re-arm word is single-use; a
mismatch in boot id, profile hash or payload binding stops before the provider entry; nothing here
touches `/dev/eipkas`, the CCP submit path or any write surface.

## 7. What W16 does not do

* It does not promote the revision, does not register `ccp.submit`/`verify.ccp.submit`, and does not
  change any operation policy.
* It does not read the campaign's K-L1 telemetry globals (0x2668008 / 0x266C800) — those belong to
  the research campaign, not to the promotion, and would be a separate window set with its own review.
* It does not touch the CCP submit path, the device-ioctl gate's passability question, or the
  unresolved "which primitive stores new key material into a slot" question — all three stay open
  research items in `ccp-layouts.json`.
