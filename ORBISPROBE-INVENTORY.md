# ORBISPROBE-INVENTORY

Source inventory of the real OrbisProbe code base, produced for PS4RF P1 (integration
phase). Compiled 2026-10-05 by Hermes from static source reading plus the PS4RF
inventory extractor; every section cites `path:line` at commit
`3ee779f257d3784b5f2cdd768b3dd264b00744f0`.

## Source under inventory

| Item | Value |
|---|---|
| Repository | `https://github.com/RuxaXa/Orbisprobe` (public) |
| Commit | `3ee779f257d3784b5f2cdd768b3dd264b00744f0` — "feat: publish OrbisProbe v0.3 development worktree" |
| Version | `0.3.0.dev0` (`pyproject.toml:7`, `orbisprobe/__init__.py`) |
| Local clone used | `/home/hermes/projects/orbisprobe` (HEAD == remote main, clean) |
| Delivered zip (chat) | `orbisprobe-v0.3-dev-wip-20261005.zip`, sha256 `6e9e4de3…be4fa` — 3 files older than main |
| Extractor draft | `ORBISPROBE-INVENTORY.draft.md` (3692 lines, 185 modules, 0 parse errors) |
| Baseline evidence | `~/audits/ps4b-soc-workbench/ps4rf-p1-orbisprobe-20261005/BASELINE.md` |
| Size | 93 package modules / 21,754 lines; 67 test files / 12,300 lines; 25 scripts; 7 Ghidra Java scripts; 30 git commits |

Method: static reading and greps only; no OrbisProbe or PS4RF code was executed
against any target during this inventory. The test numbers in section 13 were
produced by an offline suite run in a scratch venv (see 13).

---

## 1. Module

Top-level layout (231 files excluding `.git`):

```
README.md  SECURITY.md  HARDENING-REPORT.md  CHANGELOG.md  BASELINE-SHA256SUMS
pyproject.toml  examples/  docs/  scripts/  tests/
orbisprobe/            # the package (93 modules, 21,754 lines)
```

Package map (module counts per directory, Python only):

- `orbisprobe/` root: `schema.py` (131 L, plan vocabulary), `policy.py` (214 L, gates),
  `runner.py` (490 L, execution/restore), `evidence.py` (94 L, JSONL log),
  `report.py` (23 L), `cli.py` (408 L, argparse dispatch).
- `orbisprobe/analysis/` (5 modules): `binary.py` (flat x86-64 byte image, capstone),
  `dataflow.py` (register-lifetime engine), `memop.py` (facts evaluator),
  `sinkfirst.py` (1176 L sink-first record model), `ranking.py`.
- `orbisprobe/analyzers/memop_scan.py` (42 L, `scan-memops` triage heuristic).
- `orbisprobe/backends/` (11 modules + `workers/` + `ghidra_scripts/*.java`):
  `base.py` (contracts), `registry.py`, `orchestrator.py`, `cache.py`, `consensus.py`,
  `dynamic.py`, `native_backend.py` (capstone), `angr_backend.py`, `ghidra_backend.py`,
  `triton_backend.py`, `workers/{angr,triton}_worker.py`.
- `orbisprobe/evidence_pass/` (14 modules): deterministic evidence-pass package
  (build/verify/review/remediate) — see section 6.
- `orbisprobe/harness/` (3 modules): hash-bound offline execution descriptions
  (`m2b-harness-v1`), stub registry (`STUB_REGISTRY_VERSION = '1'`).
- `orbisprobe/leads/` (10 modules): ResearchLead model, scoring, scheduler, gates,
  store, migration, audit — see sections 4/5.
- `orbisprobe/live/` (25 modules + `payload/`): everything that can reach a real PS4 —
  see sections 9–11.
- `orbisprobe/surfaces/` (10 modules): privilege-surface scanners
  (`TRACK_ORDER = ('svm', 'iommu', 'secure', 'memctl')`, `privilege.py:14`).
- `orbisprobe/targets/` (3 modules): `Target` ABC, `offline.py`, `command_adapter.py`.

## 2. Entry points

Console script: `orbisprobe = orbisprobe.cli:main` (`pyproject.toml:23`).

CLI commands (all in `orbisprobe/cli.py` unless noted):

- `validate <experiment.json> --max-risk R` — policy validation + canonical plan SHA-256 (`cli.py:109-111,190-197`).
- `run <experiment.json> --plan-sha256 <hex> [--adapter CMD] [--evidence PATH] [--dry-run]` — exactly-one execution path (`cli.py:113-119,199-229`).
- `backends [--json]` — engine availability (`cli.py:131-138`).
- `analyze-dataflow <binary> --base --function …`, `prove-path <binary> …` (`cli.py:140-165`).
- `privilege-surface {svm,iommu,secure,memctl,all} <binary>` (`cli.py:167-183`).
- `scan-memops <binary>` (`cli.py:121-125`).
- `report <evidence.jsonl>` (`cli.py:127-129`).
- `leads scan|score|rank|show|next|rehydrate|action` (`orbisprobe/leads/cli.py:14-49`).
- `evidence-pass build|verify|review-plan|review-record|remediate|recover` (`orbisprobe/evidence_pass/cli.py:55-94`).

Library entry points a PS4RF adapter would call: `Experiment.from_json`, `Policy.validate`,
`experiment_sha256` (`schema.py:59-72,130`); `Runner.run` (`runner.py:44`); `EvidenceLog`
(`evidence.py:69`); `BackendOrchestrator.run` (`orchestrator.py`); `LeadStore.load/save`,
`score_lead`, `rank_leads`, `ResearchScheduler` (`leads/`); `evaluate_action_gate`
(`leads/gates.py`); `build_pass`/`verify_package` (`evidence_pass/builder.py:65`,
`verify.py:192`).

Operator scripts (`scripts/`, 25 files) are not package API; they include the live
campaign drivers (`live0_smoke.py`, `live1_ab.py`, `live2_toctou.py`, `live21…live29_*.py`),
`migrate_v03_leads.py` and `build_release.py`. They call package APIs directly.

## 3. Data models

Core (`orbisprobe/schema.py`):
- `RiskClass`: `offline, read_only, volatile_user, volatile_shared, reversible_kernel_ram, active_request, persistent` (`schema.py:10-17`).
- `EvidenceState`: `CONFIRMED, SUPPORTED, INFERRED, UNKNOWN, DISPROVED, REVIDIERT` (`schema.py:19-25`; `REVIDIERT` has no producer in source — see gaps).
- `Experiment` dataclass fields: `id, title, hypothesis, risk, controlled_input, validation, consumer, expected_effect, observable, experiment, preconditions[], forbidden_sinks[], reachable_sinks[], validation_steps[], steps[], oracles[], restore_steps[], stop_on[], metadata{}` (`schema.py:37-57`).
- `Step(kind, args)`, `Oracle(kind, args)` (`schema.py:27-35`); canonical form = sorted-key JSON, `allow_nan=False` (`schema.py:120-127`).

Backends (`orbisprobe/backends/base.py`):
- `BackendIdentity{name, version, independence_family, capabilities, implementation}`;
- `BackendResult{identity, status, data, evidence[], errors[], unknowns[], partial, metrics}` (`base.py:204-273`);
- `BackendEvidence{kind, subject, value, address, confidence, provenance}` with confidence `SUPPORTED|INFERRED|UNKNOWN|DISPROVED`; `CONFIRMED` rejected from backends (`base.py:153-201`);
- `ResourceLimits{timeout_seconds=60, memory_mb=2048, state_ceiling=128, maximum_function_count=4096, maximum_graph_size=100000, maximum_steps=100000}` (`base.py:100-115`);
- statuses: `COMPLETED, BACKEND_UNAVAILABLE, ANALYSIS_INCOMPLETE, TIMEOUT, RESOURCE_LIMIT, PARTIAL, ERROR` (`base.py:35-42`);
- consensus classifications: `UNKNOWN, SUPPORTED, STRONGLY_SUPPORTED, MULTI_MODAL_STRONG_SUPPORT, CONFIRMED, EVIDENCE_CONFLICT, DISPROVED, REVIDIERT` (`consensus.py:26-34`; `CONFIRMED` needs a runtime channel + ≥2 families, `consensus.py:226-236`).

Leads (`orbisprobe/leads/model.py`, frozen dataclasses, closed schema):
- `ResearchLead` fields: `lead_id, origin, root, source, sink, hardware_class, user_influence, candidate_invariant, known_edges, unknown_edges, evidence, observable, persistence_risk, runtime_requirements, risk_class, status, control_score(0-5), sink_score(0-5), gap_score(0-5), edge_distance, closure_cost, evidence_value(0-5), lead_score, evidence_actions, budget, mode, legacy_status` (`model.py:281-309`).
- `EvidenceAction` fields incl. 9 hard-safety booleans (`persistent_effect, unknown_mmio, invalid_pointer, kernel_code_mutation, kernel_write, arbitrary_address, destructive_mmio, persistent_state_target, secure_state_modification`) and 7 exploit-gate booleans (`model.py:104-134`).
- `HardwareSinkClass` (14 values, `analysis/sinkfirst.py:34-50`), `UserInfluence` (7 values, `sinkfirst.py:67-74`), `LeadBudget{discovery, closure, proof}` (`model.py:82-101`).

Evidence pass (`orbisprobe/evidence_pass/model.py`): `ActionStatus` (5), `ActionResult` (7),
`LeadDisposition` (8: `PROOF_MODE_READY, CLOSURE_PENDING, VULNERABILITY_CANDIDATE, SAFE_CLOSED, DOWNGRADED, PARKED, ARTIFACT_BLOCKED, EVIDENCE_CONFLICT`), `ReviewState` (4),
`ResultFreshness`, `ReviewMode`; models `EvidenceReference`, `ClaimTrace`, `ActionOutcome`,
`Metrics` (`model.py:13-82,229-380`).

Live models: plans/authorization (`live/plan.py`), identity/session (`live/identity.py`),
candidate records (`live/candidate.py`), policy levels (`live/policy.py`), profile
constants (`live/profile.py`), plus LIVE2.x analysis record types (pure data).

## 4. Candidate model

There is no class named `Candidate`; the candidate concept is `ResearchLead`, and the
action concept is `EvidenceAction`.

- **Fields/IDs**: see section 3. `lead_id` forms observed: migrated `V5-P1-<12hex>` /
  `V5-P2-<12hex>` (first 12 hex chars of `sha256(key)`, `leads/migration.py:24-26,327,388`),
  action ids `legacy-action-<12hex>` and literals (`gc-address-map`, `pm4-extent`, …),
  and fixed human ids `RC-001`, `GC-ADDRESS-LEAD`, `GC-HQD-EXTENT-OWNERSHIP`,
  `GC-PM4-IB-OWNERSHIP`, `GPUVM-PARTIAL-MAP-GENERIC`, `GC-RING-SIZES`, `SEC-TAG1-TAG9`
  (`migration.py:327-551`). Example: `V5-P1-0393feccbbfc`.
- **Status values** (12): `DISCOVERED, SCORED, EDGE_ANALYZED, CLOSURE_PENDING,
  EVIDENCE_PROBE_READY, PROOF_MODE, VULNERABILITY_CANDIDATE, SAFE_INVARIANT, DOWNGRADED,
  PARKED, ARTIFACT_BLOCKED, DISPROVED` (`leads/model.py:18-30`).
- **Transitions**: no FSM; status is *derived* by the activation policy and re-applied on
  score/rehydrate (`leads/scoring.py:71-90`): EDGE-0 → `PROOF_MODE`; EDGE-1 → `CLOSURE_PENDING`;
  EDGE-2 → `CLOSURE_PENDING` iff score ≥ 35 and cost ∈ {COST-1, COST-2, COST-3} else `PARKED`;
  EDGE-3PLUS → `PARKED`; artifact/cost-blocked → `ARTIFACT_BLOCKED`. `LeadStore` re-checks
  stored statuses against the policy and rejects contradictions (`leads/store.py:24-36`).
  Rehydration for parked leads requires a matching resolved edge or artifact (`scheduler.py:181-217`).
  `EVIDENCE_PROBE_READY` and `VULNERABILITY_CANDIDATE` are never assigned inside `leads/`;
  the producer is the evidence-pass workflow (`LeadDisposition` side).
- **Hard invariants**: EDGE-3PLUS must not carry active statuses; unknown-edge count must
  match edge distance (`model.py:327-374`).

## 5. Experiment model

- **Format**: plain JSON document parsed into `Experiment` (`schema.py:38-72`); no YAML, no
  separate IR. Field set in section 3. Step kinds observed across repo: `read_file`,
  `hash_file` (offline target), `read_memory`, `write_memory`, `check_precondition`,
  `snapshot_state`, `execute_named_case` (examples); unknown kinds pass through to the
  target adapter. Oracles: `changed`, `sha256_equal`, `field_equals` (`runner.py:471-490`).
- **Execution logic**: `Runner.run` (`runner.py:44-230`). Gates before any target step:
  structural validation; `Policy.validate`; required `expected_plan_sha256` that must equal
  the canonical `experiment_sha256(exp)`. Evidence plan record is written *before*
  execution; storage failure ⇒ `runtime_failure` with zero target contact (`runner.py:87-111`).
  Mutation tracking `NOT_MUTATED → MUTATION_ATTEMPTED → MUTATED_CONFIRMED` with byte
  readback; `stop_on` conditions abort; restore mandatory for `reversible_kernel_ram`;
  restore readback must equal saved original bytes or the run is `restore_failure` and the
  Runner latches against later mutating plans (`runner.py:213-230`, `SECURITY.md:16`).
- **Where implemented**: `orbisprobe/schema.py` (vocabulary), `policy.py` (gates),
  `runner.py` (execution), CLI `validate`/`run`; external targets only via
  `targets/command_adapter.py` (argv array, no shell, JSON stdio, 30 s default timeout,
  error taxonomy `adapter_timeout|adapter_spawn_failure|adapter_exit_failure|malformed_adapter_response`).
- **Proposals**: plans are authored inputs (`examples/`) or fixed smoke-matrix constructions
  (`scripts/run_smoke_matrix.py:44-68` builds canned live experiments in code); there is no
  discovery engine that turns an insight/candidate into a plan — `propose_experiment` in the
  PS4RF sense does not exist here yet (relevant for the adapter, section mapping).

## 6. Evidence model

No database anywhere; five file-based mechanisms:

1. **Run evidence log** — `EvidenceLog` append-only JSONL, one `Event{run_id, experiment_id, kind, data, ts}` per line, flushed + `fsync` per append, key-based redaction (`api_key|authorization|cookie|credential|passwd|password|private_key|secret|token`), large `data_hex` replaced by preview+length+sha256 (`evidence.py:11-94`). Written wherever `--evidence` points; used by `orbisprobe run`/`report`.
2. **Evidence-pass package** (flagship, deterministic): package with `action-plan.json`,
   `action-journal.json`, `action-results/<id>.json`, `leads-before.json`, `leads-final.json`,
   `source-manifest.json`, `claims.json`, `copy-events.json`, `evidence/<name>`,
   `metrics.json`, `campaign-summary.json`, `SHA256SUMS` (`evidence_pass/builder.py:90-127`),
   plus post-freeze annexes `verification-result.json` and `review/*`
   (`verify.py:624`, `review.py:77-143`). Schemas: `orbisprobe-evidence-pass-v1`,
   `…-verification-v1`, `…-review-request-v1`, `…-remediation-v1`. Verification recomputes
   every derived value and requires a byte-identical double rebuild (`verify.py:192-608`).
3. **Leads store** — single JSON file, schema `orbisprobe-research-leads-v1`, atomic
   symlink/hardlink-safe writes, source-overlap protection (`leads/store.py:13-62`,
   `leads/safe_io.py`). Own persistence of candidate state.
4. **Live evidence rows** — hash-bound record writing for live modules (`live/evidence.py:99-115`).
5. **Analysis cache** — `~/.cache/orbisprobe/analysis`, keys = sha256 over request+versions+
   fingerprints, HMAC-signed with per-root key, mode 0600 (`backends/cache.py`).

## 7. Tool dependencies

- `capstone==5.0.9` — hard pin (`pyproject.toml:10`). Note: the installed *distribution*
  reports 5.0.9 while `capstone.__version__` reports `5.0.7` (capstone module quirk,
  verified in the scratch venv 2026-10-05).
- **angr** (optional extra `angr==9.2.184`, `pycparser==2.22`, `pyproject.toml:12-13`) —
  invoked as an out-of-process worker: argv `[interpreter, orbisprobe/backends/workers/angr_worker.py]`,
  JSON on stdin, interpreter from `ORBISPROBE_ANGR_PYTHON` else `<cwd>/.backend-envs/angr/bin/python`;
  `RLIMIT_AS` = memory_mb, `RLIMIT_CORE=0`; timeout = limits (`angr_backend.py:48-68,130-161`).
- **Ghidra headless** — `ORBISPROBE_GHIDRA_HOME` else `/home/hermes/tools/ghidra_12.1.3_PUBLIC` else `/opt/ghidra`;
  `ORBISPROBE_JAVA_HOME` else three hard-coded JDK candidates (`ghidra_backend.py:53-73`).
  Exact argv in `ghidra_backend.py:256-290`: `analyzeHeadless <project> OrbisProbe -import <binary>
  -overwrite -processor x86:LE:64:default -cspec gcc -loader BinaryLoader -loader-baseAddr <hex>
  -analysisTimeoutPerFile <t-5> -max-cpu 1 -scriptPath <dir> -postScript OrbisProbeExport.java
  <out.json> <hex(function)> <maximum_graph_size> -deleteProject` (+ `-noanalysis` for >1 MiB
  inputs), env adds `GHIDRA_HEADLESS_MAXMEM`, process group killed on timeout
  (`ghidra_backend.py:216-232`); result schema `orbisprobe-ghidra-pcode-v1`, written by
  `ghidra_scripts/OrbisProbeExport.java` (7 Java scripts in-tree).
- **Triton** — dynamic worker, interpreter `ORBISPROBE_TRITON_PYTHON` else
  `<repo>/.backend-envs/triton/bin/python`; version pinned only in docs (`1.0.0rc4`,
  `docs/M2B-REPORT.md:14,29`) (`triton_backend.py:50-107`).
- **ssh** (system binary, live only), plus remote `ss`/`pgrep`/`cat`/`bash` on the LAN worker
  (`live/transport.py:119-176`); `http.client` for payload delivery (below).
- **binaryninja** — placeholder row only, always `BACKEND_UNAVAILABLE` (`cli.py:239-255`).
- No `shell=True` anywhere in the repo (verified grep; explicit `shell=False` at
  `angr_backend.py:143`, `ghidra_backend.py:223`, `triton_backend.py:97,249`).
- Rizin, AFL++, Unicorn, boofuzz, Scapy, mitmproxy, syzkaller: **not present** in this repo
  (note for PS4RF TOOLS.md, which lists them as planned adapters).

## 8. Firmware hardcodes (K1 risk)

Non-test locations (concentrated; full census in analysis root):

- `orbisprobe/leads/migration.py:218-321` — six firmware addresses as literal strings
  (`0xffffffffd05ac8f0`, `0xffffffffd0698e90`, `0xffffffffd016efa0`, `0xffffffffd0568e10`,
  `0xffffffffd048f350`, `0xffffffffd00d7f10`) driving hardware class, unknown-edge lists
  and reasons for the 104 migrated V5 records.
- `orbisprobe/live/profile.py:46-84` — the FW 13.52 kernel profile: dump sha256 `cf157f…ca35`,
  dump size `44040192`, image span `0x2A10000`, `text_end 0xCFE758`, `data_end 0x16665E8`,
  content RVAs `0x0/0x100000/0x140000`, relocated field `(0x18,8)`, `prison0` `0x0111FA18`
  (Δ `0x1A5C0C0`), `m_temp` Δ `0x1A42F70`, `allproc` `0x01B28538`, `rootvnode` `0x02136E90`,
  `proc_layout`. Profile selected by key `"13.52"` (`profile.py:81-84`).
- `orbisprobe/live/classification.py:27-67` — canonical ranges (`0xFFFF800000000000`,
  `0xFFFFFF8000000000`–`0xFFFFFF8400000000`, low MMIO window) and text/data end constants.
- `orbisprobe/live/payload/ps4_live1_trace_payload.c:296-307` and
  `ps4_live2_trace_payload.c:305-337` — `TRACE_FW_EXPECTED 1352`, hook/cave RVAs
  (`HOOK_RVA 0x4DDF73`, `HOOK_WIN_RVA 0x4DDF63`, `CAVE_RVA 0x72B240`, `RET_RVA 0x4DDF78`,
  `CALLEE_RVA 0x4AE200`, `A3_ANCHOR_RVA 0x4DC9F0`), `KERNEL_TEXT_LEN 0xCFE758`, embedded
  original instruction bytes.
- `scripts/*` (operator scripts, e.g. `live210_closure.py:38-39` `DUMP_BASE`,
  `live24_analysis.py:32-40` `RC001` and call sites, `live29_reclass.py:26-27`) — largest
  volume of uppercase kernel addresses; not package code.
- `live/attach.py:221` — greeting firmware consistency check (`fw in (1352, 0x1352)`; advisory only, see section 11).

Test/fixture data mirrors the same addresses (`tests/test_live22_transfer.py:33-39`,
`tests/test_lead_migration.py`, `tests/fixtures/evidence_pass/case_E.json`) and adds fake
profiles fw 9.00 / 11.00 (`tests/test_sinkfirst_primitives.py`) — do not count as
production surface. Verdict: firmware knowledge in *package code* exists in
`leads/migration.py`, `live/profile.py`, `live/classification.py`, `live/attach.py` and the
two trace payload C sources.

## 9. PS4 hardcodes (non-firmware)

- Endpoints/ports: console `192.168.1.141`, worker `neo@192.168.1.148`
  (`live/ps4_target.py:67-70`, `live/transport.py:39-47`); `9090` GoldHEN Payloader,
  `9025` bridge payload port, `9026` bridge host port, `19026` local SSH forward
  (`transport.py:42-45`); klog `3232` (`ps4_target.py:69`); FTP `2121` named as non-loader
  observable (`attach.py:21`). `9027` and `libkernel` occur nowhere.
- Worker build paths: `/home/neo/bls-oracle/sdk/libPS4`, `/home/neo/m6build/live0`
  (`transport.py:46-47`); scratch paths `/tmp/console_bridge.py`, `/tmp/bridge_ctl.sh`,
  `/tmp/console_bridge.log` (`transport.py:155-156`, `attach.py:123`).
- Device/process/syscall surface: `/dev/gc` ioctl ids `0xc0848119` / `0xc00c8110`
  (`leads/migration.py:420,574`); `ScePthread` in payloads; `ScePartyDaemon` as default
  process name in scripts/tests; frame grammar `#` + 8 lowercase hex (max `0x40000`),
  status tokens `OK/ERR` (`live/channel.py:23-25,68`); command tokens
  `PING/INFO/READ/WRITE/VERIFY/KREAD_USER/RACE/DRW/DR/DRSTOP/RTRACE/TR/QUIT`
  (`ps4_live0_payload.c:1021-1076`); TRACE grammar `req=/op=/stage=` (`trace_client.py:51-58`).
- Kernel ranges in payload C: `KERNEL_MIN 0xFFFF800000000000`, MMIO `0xE0000000`–`0x100000000`
  (`ps4_live0_payload.c:49-52`); SCE net error codes `0x80410104/0x80410123`.
- Hosts/paths/ports appear in `ps4_target.py`, `transport.py`, `payload/console_bridge.py`,
  both trace payloads, and operator scripts.

## 10. Live execution (core risk)

All network/hardware I/O lives in `orbisprobe/live/` and its payloads:

- `live/transport.py` — `WorkerConsoleTransport`: `ssh` subprocess (`:119-126`), hex file
  upload (`:128-144`), bridge start/stop via `bash /tmp/bridge_ctl.sh` (`:147-176`),
  `/proc/net/tcp` read (`:179-199`), `ssh -N -L 127.0.0.1:19026:127.0.0.1:9026` tunnel
  (`:201-223`), local TCP channel (`:237`), remote build (`:256-287`), payload fetch
  (`:289-297`), **payload delivery via `HTTPConnection(console_ip, 9090)` + `POST /payload`**
  (`:300-313`), tunnel teardown (`:337-344`).
- `live/ps4_target.py` — `Ps4LiveTarget`: reads/writes through an injected channel; klog TCP
  `(console_host, 3232)` (`:1364`); mutating path guarded by ownership/staleness checks,
  `policy.evaluate`, dry-run suppression, readback/restore (`:1163-1313`).
- `live/channel.py` — framed `ConsoleChannel` over a caller-injected socket; creates no socket itself.
- `live/payload/console_bridge.py` — worker-side relay listening `0.0.0.0:9025` and
  `127.0.0.1:9026` (`:56-63`); `bridge_ctl.sh` wrapper.
- `live/payload/ps4_live0_payload.c` / `ps4_live1_trace_payload.c` /
  `ps4_live2_trace_payload.c` — on-console command servers: outbound `sceNetSocket`+`connect`
  to `HOST_IP:PORT` (`192.168.1.148:9025`), kernel read via libPS4 `get_memory_dump`;
  live0 exposes bounded READ plus self-buffer-only WRITE/VERIFY; live1/live2 add the FW13.52
  trace blocks (live1's write ops compiled out; live2 has a fail-closed 15-bit preflight).
  No bind/listen in any payload; no raw syscalls (libPS4 wrappers only).
- `live/attach.py` — attach state machine over an injected `ssh` callable; local JSON ledger.
- `live/trace_client.py` — TRACE correlator over injected send/recv callables; no sockets.
- Delivery chain (live0): build on worker → hex-encoded ssh upload → base64 fetch → one
  `POST /payload` to 9090 → payload dials worker 9025 → `console_bridge.py` splices to
  9026 → host reaches it via SSH forward 19026 → `ConsoleChannel` session.
- The live1/live2 trace payloads have **no delivery path in the repo** (`transport.py`
  builds live0 only); their deploying scripts were not part of the reviewed paths.

## 11. Safety gates

Present and substantive:

- **Core plan gates** (`policy.py`): 16 hard-blocked sinks unioned into every policy (cannot
  be removed by caller override); risk ladder (`max_risk`); persistent never executable;
  templates never executable; reversible-kernel-RAM read/write/readback/restore/readback
  contract with address+length binding; live plans need all research fields, explicit
  `forbidden_sinks` ⊇ policy sinks, preconditions each with a non-mutating
  `check_precondition` step; limits `max_read_bytes 0x10000`, `max_write_bytes 0x1000`,
  `max_iterations 10000`.
- **Execution gates** (`runner.py`): plan SHA-256 must match; evidence-before-execution;
  mutation/restore state machine with byte readback; restore failure latches the runner.
- **Leads gates** (`leads/gates.py:17-72`): EVIDENCE_PROBE gate (9 hard-safety booleans,
  risk != persistent, cost != COST-BLOCKED, required probe fields); EXPLOIT_TEST gate adds
  7 fields; DISCOVERY_MODE forbids EXPLOIT_TEST (`scheduler.py:147-168`).
- **Live policy** (`live/policy.py:125-234`): fail-closed order — declared-sink/keyword hard
  block; level match; identity required; staleness; plan↔identity binding (session, target,
  kernel base); per-read class/max/MMIO; per-write class/max/complete restore; mutating
  refused under LIVE0-R. Adapter write path adds ownership, staleness, canary-difference.
- **Evidence-pass gates**: plan construction requires every action to pass the leads gate
  and the pass SafetyPolicy; destructive/overlap flags must be false; source immutability
  captured and re-verified; rebuild determinism; hash-bound review gate; no auto-remediation.

Known gaps (verified, relevant to PS4RF integration):

1. `transport.send_payload` itself consults **no** policy/plan object — authorization lives
   in out-of-package caller scripts (`transport.py:300-334`).
2. `ps4_target.get_klog` honours only `dry_run` (no `policy.evaluate`) and `close()` sends
   QUIT even in dry-run (`ps4_target.py:1358-1361,1494-1499`).
3. Greeting firmware mismatch is advisory (`fw_consistent=False` only, `attach.py:219-223`).
4. The C payloads are the last barrier for their own command sets.

## 12. Reporting

- `report.py` — compact Markdown evidence-log summary (events, kinds, per-run sections).
- `leads rank` — tabular ranking with next action; `leads show/action/next` JSON modes.
- Evidence-pass — `review/REVIEW-REQUEST.json` + `REVIEW-INSTRUCTIONS.md` (standard: 3
  questions; adversarial: +6 targets), `verification-result.json`, `campaign-summary.json`,
  `metrics.json`, `legacy-parked-audit.md`.
- JSON stdout for `backends`, `analyze-dataflow`, `prove-path`, `privilege-surface`.
- No HTML/templating; no image output.

## 13. Tests

- 67 test files, 12,300 lines; no `tests/conftest.py`.
- **Fresh offline run (this inventory, 2026-10-05)**: `568 passed, 19 failed, 67 skipped
  in 60.17s` in a scratch venv with `capstone==5.0.9` + `pytest 9.1.1`, no
  Ghidra/angr/Triton envs. The 19 failures are exactly the no-skip-guard external-engine
  tests: `test_angr_backend.py` (8), `test_ghidra_backend.py` (3), `test_m2a_fixtures.py` (3),
  `test_m2a_research_cases.py` (2), `test_multi_backend_cli.py` (3). The 67 skips are
  environment-gated (Triton, M2-B, kernel dump). This matches the WIP-STATUS figure
  (568/19/67); the delivered zip's own claim of "654 passed" requires the excluded
  `.backend-envs` and is cited, not re-verified here.
- **Hardware/network**: none. All live tests are mock/harness-only (`tests/live0_harness.py`
  fakes the channel; live tests assert no loader/9090 contact, e.g. `test_live22_attach.py:155-157`).
- **External absolute-path dependency**: `tests/test_lead_migration.py:27-31` and
  `tests/test_lead_audit.py:21,72` read `/home/hermes/audits/ps4b-soc-workbench/campaign-20260923/restart-v5/`
  (exists on this host; outside the repo ⇒ these fail, not skip, elsewhere).
- Evidence-pass has 28 dedicated tests (units + regressions A–J/F1–F7 coverage).

## Cross-cutting notes for the mapping

- Source-of-truth split candidates: OrbisProbe owns discovery/ranking/proof *logic* and its
  own stores; PS4RF owns profiles/evidence/runs — direct overlaps listed in the mapping doc.
- The adapter seam most compatible with the real code: read/write `LeadStore` JSON +
  evidence-pass packages + `Experiment` JSON via the CLI/library, never live modules.

## Open questions (UNKNOWN from source)

- Producer of `EVIDENCE_PROBE_READY`/`VULNERABILITY_CANDIDATE` lead statuses (only the
  evidence-pass disposition side exists).
- Production author of `rebuild-pass.py` expected by verification.
- Whether `REVIDIERT` is ever emitted; delivery path for live1/live2 trace payloads.
- Where the `.backend-envs` spec is version-controlled (excluded from repo).
