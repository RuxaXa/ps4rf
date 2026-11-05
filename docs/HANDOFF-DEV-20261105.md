# PS4RF — developer handoff (2026-11-05, after S1.9)

Source handoff of the offline exploit-discovery engine PS4RF. From here on, code development
and architecture work are done by the receiving side; this document is the complete state, the
contracts, and the open defects. No new engine features were added for this handoff.

* Repository: `/home/hermes/work/ps4rf-a1`, branch `a1-disposition`
* Commit at handoff: see `HANDOFF-MANIFEST.txt` (`commit` line) and `git log -1`
* Baseline tags: `s14-measurement-baseline`, `s15-proof-dimensions`, `s16-partial-baseline`,
  `s17-partial-baseline`, `s18-partial-baseline`, `s19-partial-baseline`
* Phase documents: `docs/S1.8-FINDINGS.md`, `docs/S1.8-BENCHMARK-CONCEPT.md`,
  `docs/S1.9-FINDINGS.md`, `docs/S1.9-MEASUREMENT.md`, A1 audit:
  `audits/ps4rf-audit-handoff-20261105/` (not in this package, see §9)

---

## 1. What the engine is

A read-only, offline engine over a dumped PS4 kernel image. It answers, for each kernel
function: *which object does this release site free, who owns it, does it reach an entry a
non-privileged caller can use, and what would a defect there yield* — with an explicit
strength (`may` / `must`) and an explicit reason whenever it refuses to answer.

Design rule enforced throughout: **a pattern is not evidence.** Every claim carries the
instruction witness or the reason it could not be made. Nothing is ranked up to a stronger
reading to make the output look better; refusals are first-class results (1 910 refusals in
S1.7, 204 unattributed release sites in S1.9).

## 2. Module map (`tools/discovery/`, ~17 k lines)

| module | lines | responsibility |
|---|---|---|
| `image.py` | 370 | the only place that knows how a dump is laid out: base, sections, `KernelImage`, `FunctionIndex`, `FunctionRecord` |
| `inventory.py` | 56 | function-inventory adapters (Ghidra sqlite for the primary image, sweep-derived starts for the reference image) |
| `patterns.py` | 1 405 | `FunctionView` (CFG), `ScanContext`, detectors D2/D3/D5/D6/D7/D8, release-site extraction, refcount guards |
| `lifecycle.py` | 1 299 | D1/D4 ownership and table-slot lifecycle over versioned memory states (uses the strict CFG view) |
| `memory.py` | 576 | versioned value/memory domain: slot identity, kills, joins |
| `summaries.py` | 1 813 | interprocedural ownership summaries per function (1 171 functions: 638 complete / 530 partial / 3 refused) |
| `handles.py` | 494 | handle/object identity and reference accounting, refcount deltas |
| `ownership.py` | 387 | which calls release, which allocate (catalog; names are never trusted) |
| `objectflow.py` | 393 | proves two sites act on the same object, owner pass-on |
| `locks.py` | 779 | lock primitives, modes, pairing, scope |
| `lockscope.py` | 718 | lock-scope dataflow for D3 |
| `chains.py` | 708 | chain composer over entries × primitives × objects |
| `entries.py` | 453 | entry inventory: sysent, cdevsw, other dispatch tables; reachability |
| `authz.py` | 459 | privilege reachability from the userland-visible dispatch slot |
| `semgraph.py` | 663 | semantic primitive graph, joined only where the binary proves the join |
| `graph.py` | 83 | graph export (JSON + Graphviz DOT) |
| `validate.py` | 349 | reference matrix: hard facts must pass, scanner labels are measured |
| `corpus.py`, `splits.py`, `holdback.py`, `seal.py` | 227 / 265 / 128 / 88 | training/blind separation, immutable splits, held-back families, read-audit hooks |
| `predict.py`, `blindscore.py`, `blindrun.py`, `blind/` | 161 / 196 / 69 | blind-run protocol (queue → predictions → score) |
| `differential.py`, `callee_match.py`, `index_audit.py` | 319 / 170 / 223 | cross-firmware binding and index comparability |
| `queue.py` | 263 | candidate queue, nine required fields per candidate |
| `cli.py` | 526 | the pipeline commands (`all`, `facts`, `validate`, `scan`, `queue`, `graph`, `semgraph`, `chainmap`, `blind`) |
| `s11*.py`, `s12*.py` | 239–354 | the reproducible evidence packs of sprints 1.1 / 1.2 (frozen; they re-derive their numbers from run artefacts) |

Everything is read-only except the explicit `--out`/`--outdir` artefacts.

## 3. Firmware interface

The engine never ships a firmware image. Two configuration files describe the images:

`tools/discovery/data/fw/fw1352.json` (role `primary`) and `fw900.json` (role `reference`):

```json
{"image": {"path": "<absolute path to your dump>", "sha256": "<image hash>",
           "base": "0xffffffffd00d0000", "size": "0x2a00000", "purity": "NOT_PRISTINE"},
 "tables": {"sysent": {"rva": "0x1102b70", "stride": 48, ...}},
 "anchors": {"free": "0x96e0", "fdrop_release": "0xc28d0", ...},
 "inventory": {"hint": "<path to Ghidra sqlite>", "kind": "sqlite:functions(addr,size,name)"}}
```

To analyse a different image: change `path` and `sha256`, adjust `base`/`size`, re-resolve the
`tables`/`anchors` RVAs for that build, and either provide an inventory of the same shape or
set `"kind": "sweep"` (function starts derived from call targets and prologues — that is how
the 9.00 reference image is handled). There is **no** environment-variable override; the JSON
is the single source of truth, and `validate.py` loads it through `Environment.load`.

Anchors are the load-bearing facts: `free` and `fdrop_release` define what counts as a release
site. They are resolved once per firmware and pinned in `data/fw/*.json`.

## 4. Scanner input/output

```
python -m tools.discovery.cli scan --fw 13.52 --out scan.json
```

Input: the image described by `data/fw/fw1352.json`, the entry inventory, the ownership and
lock catalogs under `data/reference/`.

Output (`scan.json`), stable keys:

* `firmware`, `scanned_functions`, `elapsed_s`, `image_sha256`
* `findings[]`: `detector`, `bug_class`, `function{rva,size,name}`, `slot`, `rank` (1–3),
  `site_rvas`, `claims{}`, `counter_evidence{}`, `subsystem`
* `counts_by_detector`, `counts_by_rank`, `observation_counts`

`rank` semantics: 1 = actionable claim backed by the detector's full evidence; 2 = claim with
a named cap; 3 = recorded but refused, with the reason in `counter_evidence`. **A rank is not a
proof.** Detector-level claims always name their witnesses, e.g.
`claims.release_sites`, `claims.path_between_without_kill`,
`claims.same_object.identity_registers`, `claims.release_kinds[]` with `drop_site`/`guard_site`.

Downstream: `semgraph` (object/lock/entry graph), `chainmap` (entry → primitive chains with
`proof_levels`), `graph` (subsystem export), `queue` (prioritised candidates), `blind` (sealed
run). Their artefacts all keep the same provenance discipline: every node/edge carries the site
that justifies it.

## 5. Reproducible commands

```bash
# dependencies: the engine imports capstone at runtime
python3.12 -m venv .venv && . .venv/bin/activate
pip install -e ".[dev]"          # pyproject.toml pins the constraints
pip freeze > requirements-freeze.txt   # generated, see HANDOFF-MANIFEST.txt

# tests
pytest tests/ -q -k discovery    # 311 passed, 1187 deselected  (S1.9 + patch 01)
pytest tests/ -q                 # includes 7 known failures outside discovery, see §7

# fixtures are generated from assembler sources and byte-checked
python3 tests/fixtures/discovery/gen_cfg.py --check
python3 tests/fixtures/discovery/gen_double_release.py --check
python3 tests/fixtures/discovery/gen_lock_coverage.py --check
python3 tests/fixtures/discovery/gen_summaries.py --check

# pipeline against a configured image
python -m tools.discovery.cli facts
python -m tools.discovery.cli validate
python -m tools.discovery.cli scan    --fw 13.52 --out scan.json
python -m tools.discovery.cli chainmap --fw 13.52 --scan scan.json --out chains.json
```

Runtime on the 13.52 image (2 053 functions): `scan` 111.7 s / 177.5 MB peak RSS,
`chainmap` 17.3 s. On 9.00 (1 091 functions): `scan` 42.4 s / 150.1 MB.

## 6. State of the claims

* 259 release sites were censused; **62 are attributed, all `may`, none `must`**
  (S1.7: 7, S1.8: 24). 204 remain unattributed, by measured frequency: `frame_slot` 101,
  `field_load:untracked_base` 45, `constant` 21, `global_pointer` 12,
  `indirect_load:indexed` 12, `unresolvable:*` 11, `field_load:tracked_base` 2.
* 12 ownership transfers are `CONDITIONAL`, 0 `PROVEN`; 6 negative controls refute correctly.
* Chains: 395 (235 `CFG_REACHABLE`, 160 `UNREACHED`). 0 chains carry a `must` hop.
* Scanner labels: actionable level recall 1.0, precision 1.0, FPR 0.0 on the labelled firmware
  pair (`aio_multi_delete`, 13.52 fixed / 9.00 vulnerable) — the negative stays quiet, the
  positive is found by D1, not by D2.
* Image purity: `NOT_PRISTINE` (26 kpatch sites, `sysent[11]` hijacked). No finding may be
  reported as a pristine-kernel result; findings landing on a kpatch site must say so.

## 7. Known defects and blockers (open)

1. **P4 blind test is blocked.** `splits.verify()` → `blind_claim: False`; 0 independent
   holdout cases; `assert_blind()` raises `SplitError: kind 'train' can never carry a blind
   claim`; all 19 families have `image_sha256: null`; one live leak remains in
   `data/families/families.json`. The path forward is `docs/S1.8-BENCHMARK-CONCEPT.md`:
   labels from a firmware-version differential, two independent evidence lines per label,
   8/6/6 splits, envelopes hashed before the run. Until that exists, report `BLOCKED`.
2. **Schema drift on `session.status`** (3 declared fields vs 15 emitted) causes 7 test
   failures outside the discovery subset. Pre-existing, unrelated to the discovery engine.
3. **CFG is still not whole-program.** Indirect jumps (143 in the 13.52 sweep), `ret` targets
   and cross-function tail jumps contribute no edge. Paths needing them are `UNKNOWN`, not
   absent. Widening this is a candidate for the next phase and needs the same
   negative-control discipline as S1.9.
4. **`0x3ba7b0:0x3baca1` lost its attribution** when the branch edges landed: the path now
   splits and the value is no longer single-valued. Explaining it is open, not excused.
5. **D3 coverage is instruction-ordered within each block after developer patch 01.** A
   store before the first observed lock call in the same block is now exposed; a store after
   it is not. The remaining boundary is unchanged: lock identities, unlock points,
   caller-held locks and missing CFG edges are not modeled, so D3 stays rank 2. See
   `docs/DEVELOPER-TAKEOVER-01.md` and `docs/PATCH-01-COUNTERCHECK.md`.
6. **A1 findings**: A1-08 `OPEN`, A1-09 `PARTIAL` (unlabelled functions are `unknown`, never
   true negatives). `REQ_CHAIN_STABILITY` is not closable offline.
7. **No PROVEN hop exists on the real image.** Everything is `may`/`partial`. Do not promote a
   claim without a new witness; the S1.8 and S1.9 refusals are deliberate.

## 8. Prohibited — these constraints stay in force

* No Sony firmware in the repository, in artefacts or in this package.
* No known PoCs, exploit write-ups or root-cause hints as *discovery input*. The corpus under
  `data/corpus/` is training material and calibration only, and is marked as burned; it must
  never enter the blind path.
* No artificial ranking-up of findings. A refusal is a result.
* No hardware action, no console contact, no payload execution as part of engine work.
* Afterglow stays a separate, frozen workstream (11 open QA blockers). It is not developed here.
* `NOT_PRISTINE` image: no finding from it may be presented as a pristine-kernel result.
* No secrets, tokens, passwords or connection strings in any document or artefact.

## 9. What is in this package, and what is not

In: the discovery engine sources, `core/`, `ctl/`, `mock/` needed by the tests, all tests, all
synthetic fixtures and their generators, the data corpus and catalogs, `docs/`.

Not in, by construction:

* **Firmware images** — neither `kernel.bin` (13.52) nor `fw900-kernel-48m.bin`. Only their
  SHA-256 values appear, in `data/fw/*.json` and in the phase documents. `data/fw/*.json` also
  still points at the local paths of the original analysis machine; re-point them (§3).
* **Held-back answers** — the two `held_back` entries in `data/training/references.json`
  (`pppwn-cycle2`, `relapse-cycle2`) had their `expected`/`entries` payloads redacted. The
  entries stay so the leak checks and the blind-claim accounting still see them.
* **Audit handoff and evidence packs** — `audits/ps4rf-s18-evidence-20261105/` and
  `audits/ps4rf-audit-handoff-20261105/` remain on the analysis machine; the A1 audit refers
  to a different, older scope than S1.8/S1.9 phase status.
* **No secrets and no personal console data** were present to remove; the package was scanned
  for private keys, tokens and credential strings.

## 10. How to start

1. `git log --oneline -1` and `git tag | tail -6` — confirm you are on the handoff commit.
2. `pytest tests/ -q -k discovery` — expect `301 passed, 1187 deselected`.
3. Run the three fixture `--check` commands; a drift means the source and the fixture data disagree.
4. Read `docs/S1.9-FINDINGS.md` §1–§3 before touching `patterns.py`: the CFG and D2 interact,
   and changing one alone reproduces the false alarm described there.
5. Point `data/fw/fw1352.json` at your own image and re-verify `facts` and `validate` before
   trusting any number in `docs/S1.9-MEASUREMENT.md` — those numbers belong to the image with
   SHA-256 `cf157ffd…`, not to any other build.
