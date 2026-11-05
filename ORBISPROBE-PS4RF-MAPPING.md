# ORBISPROBE-PS4RF-MAPPING

Integration mapping between the real OrbisProbe code base and the PS4RF core.
Companion to `ORBISPROBE-INVENTORY.md` (same directory); all conflict hypotheses
C-1…C-8 verified against source at commit `3ee779f` on 2026-10-05.

**Binding source-of-truth split (from the spec, unverändert):**

```
PS4RF     = profiles, capabilities, experiments, runs, evidence, resources
OrbisProbe= discovery, reasoning, ranking, hypotheses, assessment,
            experiment proposals, classification
```

Decision vocabulary (from the spec):

- `REUSE` — pure logic, no hardware I/O, no own truth → use as library inside the adapter.
- `ADAPT` — concept right, coupling wrong → wrapper + data conversion.
- `REPLACE` — duplicates a PS4RF subsystem (profiles/evidence/execution) → PS4RF wins;
  legacy code is deprecated only after parity tests (K11).
- `KEEP_EXTERNAL` — independently useful, no overlap → optionally usable via adapter.

Adapter path: repo convention `tools/<tool>/` (see `tools/metasploit/`) is used, so the
adapter lives at `tools/orbisprobe/`; the spec's shorthand `ps4rf/orbisprobe/adapter.py`
refers to the same artifact.

---

## 1. Component mapping (skeleton C-rows, filled)

| OrbisProbe Konzept | PS4RF Konzept | Vorläufig | Ergebnis (verified) |
|---|---|---|---|
| Candidate/Findings: `ResearchLead` + `LeadStore` (leads/model.py, store.py) | `candidate.schema.json` (placeholder) + `core/models/candidate.py` `CandidateRecord` | ADAPT (ID- und Status-Mapping auf K/U-NNN + §44-Stati) | **ADAPT confirmed.** Field coverage: CandidateRecord{id, surface_id, source, state, history[Transition]} vs ResearchLead's 30+ fields — PS4RF record is by design a thin envelope; lead_id/scores/edges live in the OrbisProbe artifact and stay there. `CandidateSource.ORBISPROBE` already exists (core/models/candidate.py:6). Requires: ID scheme + status table (§2 C-5, §3.2). §44 text is **not** in the handoff repo (UNKNOWN) — no K/U-NNN allocator exists yet; v0.1 adapter preserves the OrbisProbe `lead_id` as `id` (no invented format) plus an id-map hook. |
| Experiment-Vorschlag: authored JSON plans + `runner.py` (own execution format) | `experiment.schema.json` IR + Proposal-Pfad; `core/experiment/compiler.py` (YAML→IR→canonical sha256) | ADAPT | **ADAPT confirmed, one-way.** OrbisProbe emits **neither** PS4RF IR **nor** a machine-readable proposal object: plans are hand-authored JSON for its own runner (schema.py:37-72), and no code generates them (verified: no producer module). The adapter must build PS4RF experiment docs (YAML) from lead + evidence-action data; OrbisProbe's plan format is not reused for execution. Every proposal goes through PS4RF safety gates (compile → budget → policy). |
| Evidence-Auswertung: EvidenceLog JSONL, evidence_pass packages, leads store (own persistence, no DB) | Evidence Store (read-only for OrbisProbe; `core/evidence/store.py` InMemoryEvidenceStore, hash-bound) | ADAPT/REPLACE | **ADAPT (ingest) + REPLACE (persistence).** OrbisProbe keeps writing its own artifacts **outside** PS4RF SoT; PS4RF never reads OrbisProbe's live state as truth. Evidence consumed by the adapter is imported as hash-referenced artifacts (path + sha256 + run_id) into the PS4RF store; leads-store state is not evidence. C-2 confirmed → owns-no-truth rule enforced at the boundary. |
| Firmware-Wissen: hardcoded RVAs/constants in 5 non-test locations; own `live/profile.py` 13.52 profile | `profile.schema.json` via PS4RF API | REPLACE bei Hardcodes | **REPLACE confirmed** (K1 hits, inventory §8): `leads/migration.py:218-321`, `live/profile.py:46-84`, `live/classification.py:27-67`, `live/attach.py:221`, both trace payload `.c` files. Adapter rule: no RVAs, no firmware constants; anything firmware-related must arrive via PS4RF profile data or stay inside OrbisProbe's offline analysis and never in a proposal. |
| Tool-Aufrufe: direct subprocesses (Ghidra headless argv, angr/triton workers), ssh via transport | `tools/{ghidra,rizin,angr,...}` Adapter | ADAPT | **ADAPT confirmed (C-3).** Direct exec exists: `ghidra_backend.py:256-290` (analyzeHeadless + Java postScript), `angr_backend.py:48-68,130-161`, `triton_backend.py:50-107`, `transport.py` ssh. Integration boundary: PS4RF owns tool adapters; the OrbisProbe adapter must not invoke engines itself. In v0.1 the adapter is a pure data translator (no subprocess at all). |
| Ranking: lead scoring + scheduler + gates (`leads/`) | discovery/ranking | REUSE/ADAPT | **REUSE (pure logic) + ADAPT (data).** Scoring/scheduler/gates are offline pure functions over the leads model with no I/O — reusable as logic; but it consumes OrbisProbe's own dataclasses, so the adapter converts PS4RF-visible artifacts ↔ model objects. Dependency: `leads/` imports only stdlib + the enum modules `orbisprobe.analysis` / `orbisprobe.schema` (verified) — no hardware, no network. |
| Safety-Logik: core policy, live policy, leads gates, evidence-pass gates | Live Safety Gates (v0.1 §48) | REPLACE — Gates nur in PS4RF | **REPLACE confirmed (C-6).** OrbisProbe *has* real gates (plan policy.py, runner sha/latch, leads/gates.py, live/policy.py fail-closed order) but they form a **parallel** stack that would drift from PS4RF's. Binding rule: execution decisions are taken by PS4RF gates only; OrbisProbe gates apply inside OrbisProbe's own offline tooling. The adapter surfaces the gap cases (`evaluate_action_gate` refusal fields) as proposal preconditions, never as authorization. |
| Reporting: markdown reports, review bundles, JSON CLI outputs | Evidence + `ps4rfctl show` | ADAPT | **ADAPT confirmed.** OrbisProbe report formats (report.py, review/REVIEW-REQUEST.json, campaign-summary.json) are keepable as external annexes; PS4RF reporting reads PS4RF evidence and may reference OrbisProbe artifacts by hash. No template reuse needed beyond markdown text. |
| Payload-Delivery / Live-Exec: **exists** — `live/` transport, payloads, console delivery | in OrbisProbe verboten → REPLACE durch PS4RF-Primitive | REPLACE durch PS4RF-Primitive | **REPLACE confirmed (C-4), and the skeleton's premise corrected:** live execution code **is present and complete** in OrbisProbe (ssh transport, `POST /payload` to `:9090`, three C payloads, console bridge, kernel readers). It is **off-limits for the integration**: the adapter must not import `orbisprobe.live` and no PS4RF proposal may carry live steps through it. Any future live path is built from PS4RF primitives, never via OrbisProbe transport. |
| CLI: full argparse CLI (leads, evidence-pass, analyze, prove, surfaces) | `ps4rfctl` + Adapter | KEEP_EXTERNAL | **KEEP_EXTERNAL confirmed.** The `orbisprobe` CLI remains an offline research front-end; PS4RF integration happens at the adapter boundary (library/data), not by driving its CLI from PS4RF. |

## 2. Conflict hypotheses C-1…C-8 — verified verdicts

- **C-1 Firmware-RVAs in OrbisProbe → Profil-Pflicht — CONFIRMED.** Six kernel VAs in `leads/migration.py:218-321` (`0xffffffffd05ac8f0`, `0xffffffffd0698e90`, `0xffffffffd016efa0`, `0xffffffffd0568e10`, `0xffffffffd048f350`, `0xffffffffd00d7f10`); the 13.52 profile block in `live/profile.py:46-84`; range constants in `live/classification.py:27-67`; payload constants (`TRACE_FW_EXPECTED 1352`, `HOOK_RVA 0x4DDF73u`, `CAVE_RVA 0x72B240u`, `KERNEL_TEXT_LEN 0xCFE758u`, …) in `ps4_live1/live2_trace_payload.c`. Rule: profiles are PS4RF truth; no new RVAs anywhere in the adapter or proposals.
- **C-2 eigene Evidence-Persistenz → PS4RF-SoT — CONFIRMED.** Own stores exist (leads store JSON `orbisprobe-research-leads-v1`; evidence-pass packages; JSONL logs; live evidence rows; analysis cache). No database. Rule upheld by treating all of these as **external artifacts**; PS4RF evidence store is the only SoT for runs/evidence.
- **C-3 Tool-Subprocess ohne Adapter — CONFIRMED.** Direct subprocesses to Ghidra/angr/Triton, and `ssh` in the live transport. Adapter v0.1 executes nothing; future engine use must be re-routed through PS4RF tool adapters.
- **C-4 eigene Experiment-Ausführung/Hardwareaufrufe — CONFIRMED.** `runner.py` executes plans against targets (`targets/command_adapter.py`), and `live/` reaches a real console (ssh, sockets, HTTP payload delivery, kernel read/write on-console). Adapter hard rule: no execution, no payload delivery, no `orbisprobe.live` import.
- **C-5 eigene Candidate-IDs/-Stati — CONFIRMED.** Lead IDs `V5-P1-<12hex>`, `legacy-action-<12hex>`, literals `RC-001`/`GC-*`/`GPUVM-*`/`SEC-*`; 12 `LeadStatus` values + 8 `LeadDisposition` values vs PS4RF's 11 `CandidateState` values and the K/U-NNN id scheme. Mapping table in §3.2; §44 text unavailable in the handoff (recorded as open decision, no invented formats).
- **C-6 fehlende oder abweichende Safety-Checks — CONFIRMED (partial, mitigated).** Checks are not missing; they are a second, independent safety stack (see §1 row). Conflict is resolved by the SoT rule: gates only in PS4RF.
- **C-7 Abhängigkeits-/Versionskonflikte — PARTIAL.** `capstone==5.0.9` hard pin (pyproject.toml:10); note the module reports `__version__ == 5.0.7` (capstone packaging quirk — verified in scratch venv, dist metadata says 5.0.9). angr/triton run in **separate interpreter envs** via worker scripts, so their pins (`angr==9.2.184`, `pycparser==2.22`) do not enter the main interpreter. Python requirement `>=3.11` vs PS4RF 3.13: compatible. No conflicting pins found for PS4RF's own deps (pydantic/cryptography/PyYAML/jsonschema/rfc8785). Fresh offline suite: 568 passed / 19 failed / 67 skipped (failures = engine envs absent, see C-8). Residual risk: none for v0.1 (adapter has no third-party imports beyond PS4RF's own).
- **C-8 hardwareabhängige Tests ohne Mock — PARTIAL (not hardware).** No test touches hardware or network (live tests use harness fakes; verified in inventory §13). What fails without external resources: 19 tests needing Ghidra/angr envs (**no skip guards** — plain failures, not skips) and migration/audit tests reading an absolute audit path outside the repo. 67 skips are environment-gated by design. Consequence: PS4RF CI cannot run the OrbisProbe suite as-is without either the engine envs or skip guards; the adapter's own parity tests are therefore self-contained.

## 3. Adapter v0.1 (against the mock core)

### 3.1 Interface and hard rules

Spec interface (verbatim semantics), implemented in `tools/orbisprobe/adapter.py`:

```python
class OrbisProbeAdapter(Protocol):
    def discover(self, context: DiscoveryContext) -> list[Candidate]: ...
    def rank(self, candidates: Sequence[Candidate]) -> RankedCandidates: ...
    def prove(self, candidate: Candidate) -> ProofReport: ...
    def propose_experiment(self, candidate: Candidate, context: SessionContext) -> ExperimentIR: ...
    def consume_evidence(self, run: RunRecord) -> None: ...
    def reclassify(self, candidate: Candidate, evidence: EvidenceBundle) -> Candidate: ...
    def minimize(self, candidate: Candidate, evidence: EvidenceBundle) -> Reproducer: ...
```

Hard rules (from the spec, binding):

1. Profiles/Candidates/Evidence only via PS4RF APIs.
2. Proposals always pass the PS4RF safety gate.
3. The adapter executes nothing itself.
4. No new RVAs.
5. No payload delivery.

### 3.2 Status mapping v0.1 (LeadStatus/LeadDisposition → CandidateState)

Conservative, evidence-driven, no automatic escalation; every transition is written to
`CandidateRecord.history` with `actor` = `orbisprobe:<lead_id>` (the actor string carries
the origin, since `CandidateRecord` forbids extra fields).

| OrbisProbe | → CandidateState | Condition |
|---|---|---|
| DISCOVERED, SCORED, EDGE_ANALYZED | OBSERVATION | — |
| CLOSURE_PENDING, EVIDENCE_PROBE_READY | ANOMALY | — |
| PROOF_MODE | ANOMALY | actor note `proof_mode` |
| VULNERABILITY_CANDIDATE | EXPLOIT_CANDIDATE | **requires** a reproducer artifact (spec: "ab EXPLOIT_CANDIDATE Pflicht-Reproducer"); `discover` downgrades to ANOMALY with an actor note when no reproducer is known, `reclassify` refuses without one (fail-closed) |
| SAFE_INVARIANT | CLOSED | actor note `safe_invariant` |
| DOWNGRADED, PARKED, ARTIFACT_BLOCKED | PARKED | actor note = original status |
| DISPROVED | CLOSED | actor note `disproved` |
| evidence-pass: SAFE_CLOSED | CLOSED | — |
| evidence-pass: EVIDENCE_CONFLICT | no transition | state retained; conflict recorded externally; needs human/PS4RF decision |

PS4RF states `BUG`, `LOGIC_BUG`, `CRASH`, `PRIMITIVE`, `EXPLOITABLE`, `CHAINABLE` are **not**
derivable from OrbisProbe status values alone — the adapter must not assign them from
status; they require PS4RF evidence (crash/logic observation) and stay for the PS4RF side.

### 3.3 Data flow (v0.1, offline only)

```
OrbisProbe artifact (leads store JSON / evidence-pass package / plan JSON)
        │  read-only, hash-recorded
        ▼
tools/orbisprobe/adapter.py  (pure conversion, no execution, no network)
        │  CandidateRecord / experiment YAML → core.experiment.compile_experiment → IR + sha256
        │  evidence references (path+sha256+run_id) → PS4RF evidence store
        ▼
PS4RF models / gates / ps4rfctl        (sole source of truth)
```

### 3.4 Parity tests (implemented: `tests/test_orbisprobe_adapter.py`, offline)

Status 2026-10-05: implemented and green — `23 passed + 1 skipped` (the skip is the
env-gated cross-check; run with `ORBISPROBE_PYTHON`/`ORBISPROBE_SRC` it passes against
the real OrbisProbe code, verified once). Full ps4rf suite: `35 passed, 1 skipped`.

1. Status mapping: exhaustive table test over all 12 LeadStatus + 8 disposition values; unknown value → explicit refusal.
2. `discover`: fixture leads store (real schema `orbisprobe-research-leads-v1`, two leads) → `CandidateRecord`s with `source=ORBISPROBE`, history actor `orbisprobe:<lead_id>`; id passthrough documented.
3. `rank`: deterministic ordering on fixture, tie-break stable; no I/O.
4. `propose_experiment`: candidate → YAML doc → `compile_experiment` → canonical sha256 stable across runs; must refuse for anything non-offline (no live steps can be produced by construction); output re-validated against PS4RF rules (budget check).
5. `consume_evidence` / `reclassify` / `minimize`: with a synthetic `RunRecord`/`EvidenceBundle` fixture — hash-bound ingestion into the InMemoryEvidenceStore; reclassify applies §3.2 with fail-closed reproducer rule; minimize produces a hash-referenced Reproducer envelope (PS4RF schema pending → minimal documented envelope).
6. No-execution guard: assert adapter module source imports no `subprocess`/`socket`/`http`/`ssh` and no `orbisprobe.live` (static import test).

## 4. Open decisions (carried to the adapter phase)

1. **ID allocation K/U-NNN (§44)** — §44 text absent from handoff; v0.1 keeps `lead_id` as id with a remap hook; needs the §44 document or a PS4RF-side allocator decision.
2. **Reproducer schema** — PS4RF has no `Reproducer` model yet (only RESEARCH-MODEL.md:8 describes the chain); v0.1 emits a minimal hash-bound envelope (reproducer = {run_id, path, sha256, plan_sha256}).
3. **RunRecord / EvidenceBundle types** — not yet defined in PS4RF; v0.1 defines them as draft dataclasses inside the adapter package, marked provisional.
4. **Live payloads** — OrbisProbe's `live/` stays unused; future PS4RF live primitives (P5) will replace its role. No porting of its transport.

## 5. References

- `ORBISPROBE-INVENTORY.md` — sections cited per row (esp. §4, §5, §6, §8, §10, §11, §13).
- Source: `https://github.com/RuxaXa/Orbisprobe` @ `3ee779f257d3784b5f2cdd768b3dd264b00744f0`.
- Spec: `docs/spec-history/Pasted_text(2).txt` §10.2/§10.3, K12 order; `Pasted_text(20261005-115353).txt` (SoT split, "ab EXPLOIT_CANDIDATE Pflicht-Reproducer", :109).
