# W14 — resident `ps4rfd` (§2 life cycle, §3 exit conditions, §12/§13 transport)

**Wave:** W14 · **Status:** daemon landed and green offline — W14 **not** complete
**Live:** not started, not authorized (no upload, no console contact, loader port untouched)

This document covers the part of W14 that is landed: the resident daemon over the existing
dial-out transport, its life cycle, its exit conditions and the offline controller that drives it.
It does **not** claim §4 (session-inheritance audit), §6, §7, §14 (identity in HELLO), §15
(authenticated admin shutdown), §16/§17 (scenario and stress runs) or §18/§19 (evidence pack,
`W14 OFFLINE READY`). Those stay open and are listed in §8 below.

## 1. What the wave had to solve

Stage A made the *single* read path explicit (dispatcher → one wired privileged provider). The
remaining W14 problem is the *time* axis: one bootstrap per boot, then a resident agent that serves
several separate authenticated sessions, each with its own isolation and its own release, without a
new payload per read and without a second, special trigger.

The daemon adds no operation, no wire frame, no provider and no privilege. It adds *when* a session
may start, *what* a session is allowed to be, and *how* the agent ends.

## 2. Life cycle (normative)

```text
BOOTSTRAP ──► RESIDENT_IDLE ──► SESSION_ACTIVE ──► SESSION_CLEANUP ──► RESIDENT_IDLE ──► …
                    │                                     │
                    └────────────── EXITED ◄───────────────┘   (only on an exit condition)
```

| state | meaning | a session may start here |
| --- | --- | --- |
| `BOOTSTRAP` | boot inputs are formed once per boot (pre-session boot read/profile); no session | no |
| `RESIDENT_IDLE` | bootstrapped, no session bound to the agent | **yes** |
| `SESSION_ACTIVE` | exactly one session runs the frozen `ps4rf_agent_run` | no (§13) |
| `SESSION_CLEANUP` | the session ended, per-session resources are being released | no |
| `EXITED` | an exit condition fired; the agent is done and will not serve again | no |

* One bootstrap per boot: `ps4rf_daemon_bootstrap()` either establishes the boot inputs or fails
  closed (`BOOTSTRAP_FAILED`, exit reason internal integrity failure). It is never retried inside a
  run.
* A normal `BYE` ends the **session**, never the agent. After `SESSION_CLEANUP` the agent is back in
  `RESIDENT_IDLE` and the next dial-in is served.
* The acceptance gate is a single function, `ps4rf_daemon_accept()`: `ACCEPT` only in
  `RESIDENT_IDLE` and only while no session is bound. The active flag alone keeps it closed, so a
  state and a flag that disagree can never open the gate.
* `ps4rf_daemon_run()` keeps the intervals (`lifetime_s`, `idle_s`) and the session budget
  (`max_sessions`) of the configuration; a *run* ending is a driver decision, not an agent exit.

## 3. Transport (§12, §13) and the refusal notice

* Sessions are accepted over the **existing dial-out transport**: the daemon dials the configured
  research endpoint with `net_connect`. There is no listener, no port and no health probe on the
  agent side — the loader port is never named, opened or probed by the agent after bootstrap.
* The offline **controller listens per session** (`tools/hostctl/resident.py`): accept → handshake →
  READY → REQUEST/RESPONSE → BYE → close. A controller with its listener open *is* the session
  attempt; a dial that cannot connect is recorded as `dial_misses` and is **never fatal** — a
  resident agent must survive a missing controller.
* §13 caps the agent at **one active research session**. A further connection that reaches the
  agent while a session is active is refused **on that connection** with a notice and closed
  (`busy_refusals`), at most one per session: after the session, the next attempt must be served
  again.
* The notice is emitted **before any handshake**, so it cannot be authenticated and therefore carries
  **no authority**. Its complete field set is fixed and validated strictly by the host:

```json
{"active_sessions":1,"agent_version":"ps4rfd-daemon-w14","build_id":"…","msg":"SESSION_BUSY",
 "sessions_served":1,"state":"SESSION_ACTIVE"}
```

  It carries no session id, no nonce, no key material, no host input and no region — a refusal is a
  reason for a closed connection, never a protocol frame and never a state change. The host parser
  fails closed on any other shape (`BusyNoticeError`).

## 4. Exit conditions (§3)

The agent leaves its life cycle **only** for the four reasons of the spec. `exit_reason` is
`NONE` for every other outcome (`ADMIN_SHUTDOWN` is declared vocabulary;

§15 is the wave part that will produce it, and no code path returns it yet):

| exit reason | trigger |
| --- | --- |
| `ADMIN_SHUTDOWN` | §15 authenticated admin shutdown — **no producer in this wave** |
| `PROTOCOL_CORRUPTION` | the frozen handshake cannot be completed, a frame type is outside the frozen table, or a session id is replayed (checked at the session checkpoint, before any request is served) |
| `RECOVERY_REQUIRED_UNSAFE` | `RECOVERY_REQUIRED` **with an unsafe agent state** (recorded violation or an in-flight request) |
| `INTERNAL_INTEGRITY_FAILURE` | the boot inputs cannot be established, or the boot inputs changed since bootstrap, or a session ended without a complete cleanup |

Two cases that must **not** end the agent, and do not:

* a **lost transport** (reset/IO failure): the session ends, the boot-wide recovery flag is recorded
  if one was raised, the agent stays resident and serves the next session;
* `RECOVERY_REQUIRED` with a **sound** agent state: recorded (`recovery_required` is boot-wide, §11,
  and is never reset automatically), the agent stays resident.

## 5. Ownership, recovery and the checkpoint seam

* **§10 per session.** Every session re-enters through `ps4rf_agent_run`, and every session end must
  show *held resources = `[]`* **and** cleanup `COMPLETE` — demanded, not hoped for. A session that
  ends with a live object (whatever ended it: a clean `BYE`, a lost transport or a recovery stop) is
  an integrity failure and ends the agent: a resident agent owns no object across sessions.
* **§11 boot-wide.** `recovery_required` is a property of the *boot*, not of a session; once set it
  is reported but never cleared automatically. Recovery-safety evaluation stays in the frozen
  telemetry/evidence path.
* **§5 boot cache.** Bootstrap caches the boot inputs; **every** session re-reads them before the
  handshake and before any privileged step. A change means the cache no longer describes this boot:
  the session is refused and the agent exits (`INTERNAL_INTEGRITY_FAILURE`). The re-read happens
  before a single frame is sent — asserted end to end.
* **Session ids (§4).** The session id comes from the frozen handshake, is recorded per session and
  must never repeat. A replay is detected at the session checkpoint and ends the session with
  `SERVER_CLOSE` **before** any request is served.
* **Checkpoint seam.** The seam between the frozen loop and the daemon carries *no* request, no
  argument object and no address: `typedef int (*ps4rf_agent_checkpoint_fn)(void *ctx)` — the
  callback is asked "should this session continue?" and may only refuse or end it. It is installed
  once by the daemon and uninstalled on every run path (asserted), so a non-resident build has no
  live callback.

## 6. Report, driver and controller

* The daemon's run report is frozen-vocabulary canonical JSON: `attempts`, `sessions_served`,
  `sessions_failed`, `busy_refusals`, `dial_misses`, `bootstrap_failures`, `transitions`,
  `recovery_required`, `boot_inputs` (`MEASURED`|`UNRESOLVED`), `boot_sec`/`boot_usec`, `session_id`
  count and ids, `last_bye`, `exit_reason`, `exit_detail`, `stop`, `state`. No key material and no
  host input is ever reported.
* **Console entry point.** `native/target/ps4rfd_target.c` picks the daemon under
  `PS4RF_TARGET_RESIDENT` (`build_ps4.sh PS4RF_AGENT_RESIDENT=1`, profile `w12` with label
  `ps4rfd-live-w14`/context `fw13-52-resident-w14`): one upload, one lifetime, several sessions.
  The other profiles keep exactly the single-session entry point they had, the console build takes
  its run bounds from the generated config (`PS4RF_TARGET_MAX_SESSIONS` is a *run* bound; `0` lets
  the authenticated admin shutdown end the lifetime, with `lifetime_s` as the fail-safe), and the
  manifest gate `--resident` reads the entry point, the linked object and the absence of any
  listener in the module. The console build emits no report: it has no output channel, so the
  evidence is host-side (frames, BYE, cleanup, identity) plus the silence after an admin shutdown.
* `tools/hostctl/live_w14.py` is the live run sheet as code: session A, the controller gap that
  must not end the agent, session B (fresh ids, nonce, transcript, keys; stable lifetime facts),
  session C with the authenticated admin shutdown, then a silence check. It skips connections that
  never speak (a stray is not a session attempt) and consumes the §13 busy notice for evidence.
  `tests/test_w14_live_controller.py` drives it offline against the dev-host build of the same
  daemon, so the sheet is proved before it is ever pointed at a console.
* `native/target/ps4rfd_host.c` gains the offline `--resident` mode (`--connect`, `--sessions`,
  `--idle-rounds`, `--idle-pause-ms`, `--no-refuse-while-busy`) next to the unchanged single-session
  path. Its in-process `--selftest` line is now valid JSON (the previous `"selftest": PASS` was not
  parseable, which is why the suite can assert its exact field values).
* `tools/hostctl/resident.py` is the host side: per-session listener, strict notice parser, report
  consistency check (`report_is_consistent`) and the daemon report/exit code side by side.

## 7. Verification in this wave

* `tests/harness/daemon_state_check.c` links the **production** `ps4rf_daemon.c` and asks the
  questions that need no socket: the frozen vocabulary, `ACCEPT` only in `RESIDENT_IDLE`,
  `SESSION_BUSY` in every other state (including the flag/state disagreement case), the notice as a
  strict canonical document, the run report as valid canonical JSON.
* `tests/test_w14_daemon.py` — 26 tests: the harness above; the structural properties (the daemon
  dispatches no operation, has exactly one session call site behind the gate, never listens, reaches
  no privileged primitive, has exactly one producer per exit reason, has no `ADMIN_SHUTDOWN`
  producer, never leaves the checkpoint installed, and the console + host builds both carry the
  module); the controller helpers; and the end-to-end scenarios with real sockets:
  two sessions in one run with a §13 refusal each and fresh session ids; `--no-refuse-while-busy`
  serving sequentially without ever offering a connection; a lost transport staying resident;
  a session with held resources ending the agent; protocol corruption in the frame loop; a refused
  handshake; a replayed session id; boot-input drift refusing the session before any frame; a
  bootstrap failure ending the agent before any accept; and "no controller" as a run stop rather
  than an exit condition.
* `native/target/build_manifest.py` gains `gate_agent_source()`: the session-loop property
  ("the agent names no kernel.read") and the daemon's structural properties as **source** gates,
  comment-stripped and ELF-free, wired into the manifest verdict and called from
  `tests/test_target_build.py` (the W13-C2 note in `HERMES-TODO.md` asked for exactly this variant,
  because `gate_kread` needs a console artefact).
* `gate_kread` itself was restated to the stage-A/R3 reality: the deleted trigger block must stay
  **absent**, the one shot has exactly one session-entry re-arm and no reset outside it, and the
  target row must be the R3 wired-privileged-provider row while the host route table keeps its four
  frozen routes. The gate is now **exercised** by
  `tests/test_target_build.py::test_console_kread_build_gate_passes_when_the_sdk_is_present`, which
  builds the console KREAD artefact twice and requires verdict PASS. Console KREAD build: verdict
  **PASS**, 0 relocations, 0 undefined symbols, build id `b9226334e4e2fadb1b00fae82c2583c0`,
  reproducible twice — byte-identical to the artefact that failed the stale gate, i.e. only the
  expectations moved, not the payload.

## 8. Sources touched

| source | change |
| --- | --- |
| `native/target/ps4rf_daemon.h` | new: life cycle, request/notice/report contract, driver configuration |
| `native/target/ps4rf_daemon.c` | new: state machine, acceptance gate, bootstrap + per-session re-check, session record/replay check, exit evaluation, notice/report builders |
| `native/target/ps4rf_agent.{c,h}` | the checkpoint seam (`ps4rf_agent_set_checkpoint`), `bye_reason_out` on `ps4rf_agent_run`, op-name extraction only in the fixed-step builds |
| `native/target/ps4rfd_host.c` | `--resident` mode + `run_resident()`; `--selftest` output becomes valid JSON |
| `native/target/build_host.sh`, `build_ps4.sh` | the daemon module is compiled and linked in both builds |
| `tests/harness/daemon_state_check.c` | new: production-code state machine harness |
| `tests/test_w14_daemon.py` | new: 26 tests (§7) |
| `tests/test_target_build.py` | calls the new source gate |
| `native/target/build_manifest.py` | `gate_agent_source()` |
| `tools/hostctl/resident.py` | new: offline controller, notice parser, report check |
| docs / `CHANGELOG.md` / `HERMES-TODO.md` | this file and the wave's entries |

No frozen wire source, no generated catalog, no operation, no route, no provider and no release
semantics changed in this step.

## 9. Still open in W14 (unchanged scope)

§6 the host-side `VerificationEvidence` re-load/re-canonicalize/re-bind per session and the
"`CapabilityRecord` never reused" rule; §7 multi-read rehearsals with separate releases; §10 the
per-session evidence records and the daemon-lifetime record; §11 the two- and three-session offline
end-to-end runs; §15 the authenticated admin shutdown operation (block new sessions, drain, cleanup,
exit) — the four-reason vocabulary already carries it, but nothing produces it yet; §16 the ten
offline scenarios; §17 the 50+/100-session stress/leak run; §19 the `W14 OFFLINE READY` report,
evidence pack and **STOP** (no upload).

## 9a. Follow-up (W14B review): identity, isolation, recovery, backoff

§14 identity every session announces. `build_hello()` now emits the identity block -- `build_id`
(the identity `build_ps4.sh` injects), `platform` (`ps4` / `host-standin`, a compile-time fact),
`profile_id` (null when this build has no bound profile), `boot_id` (null on the agent side: the
W11 rule is that the digest is a host-side derivation), `boot_sec` / `boot_usec` (null, never `0`,
when the boot instant is unresolved), `boot_status` and `session_state`
(`READY` / `RECOVERY_REQUIRED`). Static fields are per agent lifetime, boot fields per boot, and
the nonce is generated fresh per session -- so transcript and both directional key sets differ for
every session. `tools/hostctl/session.py` exposes the block (`agent_identity`, `IDENTITY_FIELDS`)
and `tools/hostctl/resident.py::freshness_report()` turns the demands into explicit checks: same
identity, own nonce, own session id, own transcript, own key material, and a recovery flag that may
be raised between sessions but never lowered.

§2 isolation. `ps4rf_res_teardown()` is the single session teardown: it releases every live object
of the session's resource set before the BYE reports the cleanup state, and it *refuses* a set it
cannot attribute to a session (destroying those objects would consume state the caller cannot prove
it owns). The agent runs it on every exit path, `ps4rf_secure_zero`-style wiping covers the session
key material, nonce prefixes and session id (`agent_finish()` is the only way out once the keys
exist -- a source gate asserts that), and the runtime is a fresh object per session. What survives
is exactly what is boot- or lifetime-scoped: boot identity, the boot-wide recovery flag, the daemon
build identity and the bounded session-id ring (size reported, window documented).

§4/§5/§11 recovery. `ps4rf_daemon_session_recovery_required()` is the one decision that turns a
finished session into a boot state, and it is deliberately narrow: broken protocol obligation,
undelivered answer to a *mutating* operation, work still in flight, leftovers, or a teardown that
refused. A lost transport with nothing unfinished is **not** in that list -- a plain EOF or RST ends
a session, not a boot. A leftover object used to end the agent; it no longer does: the teardown
reaps it, the cleanup state is COMPLETE and the boot stays out of recovery. The boot-wide flag is
announced in every subsequent HELLO and enforced by the router *before* any provider entry; the
only thing that clears it is a new agent lifetime (`ps4rf_daemon_bootstrap()` runs once per boot and
the session path never writes 0 there). `session.status` reports `session_state` and
`mutating_allowed` from the live runtime, so a controller sees the state before it asks for work.

§6 dial-out backoff. Every miss doubles the pause from `--idle-pause-ms` up to
`--backoff-max-ms` (default 30 s), with a 50 ms floor that wins over a smaller cap -- a missing
controller costs time, never a busy loop and never an unbounded wait. A dial miss touches no boot
input, no recovery state and no capability state; the report carries `dial_misses` (consecutive,
drives the stop), `dial_misses_total` and `dial_backoff_us`.

Report additions: `cleanup_reaped`, `cleanup_refusals`, `cleanup_state`, `held_after_cleanup`,
`undelivered_responses`, `undelivered_mutations`, `dial_misses_total`, `dial_backoff_us`,
`recovery_source`, `recovery_transitions`.

## 9b. Follow-up (W14B review): the authenticated admin shutdown (§15), wire catalogue R4

The one operation the frozen catalogue gained: `session.shutdown`.

* **Core, revision R3 of the frozen model** (`core/rpc/registry.py`, one line):
  `OperationSpec('session.shutdown', None, False, True)` — read-only, recovery-safe. It carries *no*
  capability on purpose: capability-bearing operations are the privileged ones and are **never wired
  on the target agent** (a frozen invariant the generator enforces and this revision keeps).
* **Wire contract** (`tools/primitive_iface/schema.py` + `docs/P4-PRIMITIVE-INTERFACES.md`): one
  required argument `capability`, whose only admitted value is `session.admin`; result
  `{"status": "ACCEPTED"}`; errors `ARGUMENT_INVALID` / `CAPABILITY_REQUIRED`. The admitted value is
  pinned in the provider (`PS4RF_SESSION_SHUTDOWN_CAPABILITY`), so the declaration the caller makes
  is checked in exactly one place.
* **Authorization, honestly stated.** The *authentication* is the session: only a request inside an
  AEAD-authenticated session reaches this point, and the operation is never served on a bare
  connection. The `capability` argument is the caller's *declaration*, not a trust boundary — the
  boundary is the session (plus, for privileged work, the host-side chain). What the target adds is
  that the declaration must be the one the contract names, and that the operation is refused outside
  the resident mode.
* **Scope.** Served by the resident agent only: `ps4rf_agent_set_resident(1)` is set once per
  lifetime by the daemon, and `op_session_shutdown()` refuses with `OPERATION_DEFERRED` anywhere else,
  so the single-session profiles (the console one-session entry point, the plain host driver) keep
  exactly the served set they had. The generator's `TARGET_WIRED_OPS` carries the operation with that
  scoping spelled out.
* **Semantics.** The handler *requests* the end, it does not perform one: it sets
  `rt->admin_shutdown`, the session loop sends the acknowledgement first and then ends the session
  with BYE reason `ADMIN_SHUTDOWN`, and the daemon turns that into the fourth exit reason
  (`ADMIN_SHUTDOWN`, stop `EXIT_CONDITION`, process exit 0). One exit path, no second one in a
  provider. It changes no kernel state, triggers no reboot, reaches no loader and installs no
  persistence — asserted by the `admin_shutdown` source gate.
* **Policy in recovery.** The catalogue marks the operation recovery-safe, so a boot in recovery
  serves it: a controller that has to stop an agent whose boot is in recovery must be able to.
* **Also fixed here (§8/§15).** An attempt that never became a session — a wrong PSK, a truncated
  answer, a port scanner, a pre-handshake "shutdown" — is now *refused* rather than fatal: it is
  counted (`sessions_failed`), changes no boot state, and the agent keeps serving. An unauthenticated
  peer with a kill switch is exactly what a resident agent must not have. Frame-level corruption
  *inside* an authenticated session stays a fatal `PROTOCOL_CORRUPTION` exit.

Counts moved with the operation: registry 35 → 36, target table `wired` 16 → 17, stub routes 16 → 17,
argument rows 49 → 50, table sha256 `5a8e819ccd75122b…`.

## 10. Safety

No live action, no upload, no console contact, no loader-port contact, no `kernel.write`, no
`kernel.call`, no `kernel.dump`, no persistence, no firmware patch. W13 stays closed: no further
one-shot read, and the consumed releases are never reused.
