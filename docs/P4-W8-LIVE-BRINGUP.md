# P4 / W8 — Live Userland Bring-up + Target Attestation

Status: **offline complete, no console contact yet.** This document is the contract for the
first controlled live step of the `ps4rfd` userland agent (PS4 Slim, FW 13.52). Nothing in
this wave touches the kernel: the 14 deferred privilege providers and the host-chain
provider stay `OPERATION_DEFERRED` with `provider_entry = false`.

## 1. Scope

Allowed in W8 (nothing else):

* userland agent, network transport, handshake, READY, target identity, boot identity where
  read-only provable
* `session.ping`, `session.status`, `telemetry.read`
* the agent's own `memory.alloc` / `memory.free`
* `sync.gate.*` / `sync.barrier.*` inside the agent's own process
* evidence, controlled agent exit

Forbidden in W8: syscall 11 / kexec, kernel callbacks, kernel reads/writes/dumps, GPUVM,
KeyMgr, CCP, SAMU, SBRAM, EAP/EMC, PUP, secure services, foreign process memory, firmware
patching, persistent system changes, and every form of automatic live send.

## 2. Target build (offline, before any deployment)

`native/target/build_ps4.sh OUTDIR SDK [PSK_FILE]` builds the payload twice and compares the
ELF and the flat BIN; `native/target/build_manifest.py` then runs the static gates and writes
the manifest (ELF/BIN SHA-256, compiler/linker/objcopy versions, SDK artefact hashes, section
table, entry point, undefined symbols, runtime dependencies, source hashes, gate results).

Single translation unit plus the frozen wire sources, compiled with the live-proven libPS4
regime (`-Os -march=btver2 -m64 -fpie -fPIC -fno-builtin`, `-T SDK/linker.x -nostartfiles
-nostdlib`, `crt0.s`), `objcopy -O binary` for the delivery form.

Gates (fail closed):

| gate | rule |
| --- | --- |
| relocations | `readelf -rW` must show **zero** `R_X86_64*` entries (the loader applies none) |
| forbidden symbols | no `kexec`, `jailbreak`, `disable_aslr`, `get_kernel_base`, `gpuvm`, `keymgr`, `ccp_`, `samu`, `sbl_`, `kpayload` |
| forbidden code | no control-register access, no `syscall` sequence with number 11 (disassembly level) |
| loader port | the PayLoader port constant is absent from `.rodata`/`.data`; the payload never talks to the loader |
| single endpoint | exactly one IPv4 literal in the whole artefact, and it is the configured relay host |
| reproducibility | two independent builds byte-identical (ELF **and** BIN) |

Structural properties of the sources (checked in `tests/test_target_build.py`):

* the operation table is **generated** from the frozen core (`core/rpc/registry.py` + the W3
  interface + the W7 router matrix) by `native/target/gen_optable.py`; 35 operations, 15
  wired on the target, 20 deferred with a named reason
* the frozen wire sources contain no target conditional, so the payload cannot compile a wire
  variant of its own
* exactly one provider entry site exists (`ps4rf_provider_enter`), and it sits behind the
  wired-route decision

## 3. Wire parity before deployment

* the W2 catalogues (HELLO, HELLO_ACK, transcript, AUTH/AUTH_ACK, directional keys, AEAD
  vectors, request/response framing, max-frame boundary, canonical JSON/JCS) replay with zero
  mismatches **compiled with the target codegen flags** (`-march=btver2 -Os -fpie`), not only
  with the host defaults — `tests/test_target_build.py::test_wire_catalogs_replay_with_target_codegen_flags`
* the agent uses only frozen entry points (`ps4rf_agent_handshake`, channels, framing,
  canonicalization, transcript, key derivation, nonce prefixes)

## 4. READY — the one W8 wire addition (D13)

D13 kept type `0x05` reserved and stated that it "receives active wire semantics only once
shape, encryption status, capability content and state transition are fully specified".
W8 specifies exactly that — the specification below is the whole definition:

* **shape** — canonical JSON object with `msg = "READY"`, `agent`, `target`, `boot`,
  `capabilities`, `provider`, `profile`, `limits`, `protocol_version`, `nonce_source`
* **encryption** — sealed with the agent-to-host channel like every other frame after
  AUTH_ACK; it is the first agent-to-host frame (sequence 0)
* **content** — measured target facts (each with its own `OK`/`UNRESOLVED` status and the API
  that answered), boot binding, wired/deferred capability counts with the table hash, provider
  identity/state, the negotiated limits, and the entropy source actually used for the nonce
* **state transition** — the agent sends it exactly once, after AUTH_ACK and before it serves
  any REQUEST; the W8 host controller requires it (`READY` absent, duplicated or out of order
  fails the session). The pre-existing host tolerance for a peer that never sends READY stays
  unchanged, so the mock path is unaffected.

Everything else about the direction rule is untouched: the host still accepts only
RESPONSE/EVENT/BYE through the frozen check and refuses every other type.

## 5. Attestation rules

* every fact is measured; a fact the agent cannot prove becomes `UNRESOLVED`, never a derived
  guess, and the `source` field names what answered (`kern.osrelease`, `kern.version`,
  `kern.sdk_version`, `hw.model`, `kern.boottime`, `getpid`)
* platform and architecture are build facts and are labelled as such
* `boot_id` is derived only from measured boot facts (firmware identity + model + boot time);
  relaunching the agent must not change it. Without those facts the status is
  `BOOT_ID_UNVERIFIED`, no identifier is emitted and W5 runtime binding stays fail closed
* the FW 13.52 W5 fixtures stay fixtures: the attestation reports
  `profile.status = "UNBOUND"` and `profile.sha256 = null`; a real profile requires a later
  review step

## 6. Transport and delivery

* the console agent is the **client**: it connects out (reverse TCP) to the relay host
  `192.168.1.148`; semantic roles stay AGENT = console, HOST = research side
* host listener: the bridge on the relay host forwards the agent's connection into an SSH
  tunnel; the controller (`ps4rfctl listen`) accepts it on the research side. Defaults:
  payload-facing port `9028`, bridge host port `9029`, local controller port `19029`
* **delivery rule**: port 9090 is single accept. No scan, no `nc`, no `curl`, no connect test,
  no connectivity check — exactly **one** upload, and only after the owner confirms the
  BinLoader rearm (`ps4rfctl live --rearm-confirmed`). The controller's live mode refuses to
  upload without that flag and records the state (`BLOCKED`) instead
* GoldHEN is a bootstrap provider only; PS4RF does not depend on it after the payload runs

## 7. Live sequence (approved order, nothing else)

1. `session.ping` → `pong`
2. `session.status` (frozen state + held resources)
3. `telemetry.read`
4. `memory.alloc` (small, agent-owned)
5. `memory.free` of exactly that ref
6. `sync.gate.create` (parties 2)
7. lane 1 `sync.gate.arrive`
8. lane 2 `sync.gate.arrive`
9. `sync.gate.wait` (bounded, `released = false` while the gate is closed)
10. `sync.gate.release`
11. `sync.gate.wait` (now `released = true`)
12. `sync.gate.destroy`
13. final `session.status`
14. negative: `kernel.read` → `OPERATION_DEFERRED`, detail states `provider_entry=false`

`kernel.read` arguments must be safe numbers (the canonical number policy caps at 2^53−1), so
the refusal under test is the route refusal, not an argument error.

## 8. Exit, resources, health

* controlled exit: the host half-closes, the agent sees EOF, sends `BYE` (frozen body) and
  returns from `_main`; lifetime (900 s) and idle (180 s) bounds are backstops with reason
  `SERVER_CLOSE`
* resource invariant: no held memory/gate/barrier refs at close; the BYE cleanup state is
  `COMPLETE` (a leftover reports `PARTIAL`, and the agent's own invariant check would end the
  session with `RECOVERY_REQUIRED`)
* health after exit uses only the known safe read-only checks (FTP banner 2121, port 3232,
  ICMP). Port 9090 is never contacted again
* on `PARTIAL`, `UNCERTAIN`, `CLEANUP_FAILED`, `RECOVERY_REQUIRED`, a hang or a crash: **STOP**,
  no automatic retry

## 9. Evidence pack

`w8-evidence.json` (written by the controller into the pack directory) contains: the exact PS4RF commit
and core revision (R2/F7), payload ELF/BIN hashes and the build manifest hash, the
reproducibility result, the wire parity result, the handshake transcript hash, the READY
attestation (target identity, boot binding status, negotiated limits, capabilities), every
request id with its full response, the derived `provider_entry` per request, resource
transitions and cleanup state, the final session state, the negative `kernel.read` trace, the
BYE, timestamps and the health result. Neither the pre-shared key nor any session key
material is stored — the pack records only that a key file was used.

## 10. Executed live run (2026-10-05) and its one open item

The controlled live step was executed on 2026-10-05 after the owner confirmed the BinLoader
rearm: one upload (HTTP 200, `X-Powered-By: GoldHEN by SiSTRo`), the agent connected out from
192.168.1.141 (relay log), and the full session ran: HELLO/AUTH/READY with attestation
(`ps4rfd-target w8-1`, build `b5ece0c3…`, model `[REDACTED_RUNTIME_MODEL]`, pid 47, platform orbis,
`BOOT_ID_UNVERIFIED` because the read-only firmware string is not the 13.52 identity), then
**14/14 requests**: ping, status, telemetry, alloc/free (`mem:0C3C94EAB9A32638`), the full
gate cycle (`wait` closed → release → `wait` released), destroy, final status with
`held_resources: []` and `cleanup.state COMPLETE`, and the negative `kernel.read`
(`OPERATION_DEFERRED`, detail `provider_entry=false`, no provider handler entered). Health
after exit: FTP 2121 (`220 GoldHEN FTP server v2.2`), 3232 banner, ICMP 7.96 ms. Verdict: PASS.

**Open item — the BYE was not captured.** Root cause found and fixed offline: the relay of the
live harness (OrbisProbe `console_bridge.py`) ends both directions with
`shutdown(SHUT_RDWR)` as soon as one direction ends, so the BYE the agent sends *after* the
host's half close could not traverse. Evidence for that reading: the offline path without a
relay captured the BYE, and the live byte counts (payload→host 4566 B) are exactly the offline
count (4639 B) minus a BYE frame.

Fix: `tools/relay/half_close_bridge.py` propagates the half close (`shutdown(SHUT_WR)` only)
and keeps the reverse direction alive; `tools/hostctl/relay.py` pushes/starts it on the relay
host and opens the two tunnels **without ever probing them** (a probe would consume the relay's
single accept - the same reasoning as the loader-port rule). `tests/test_relay_half_close.py`
pins the wire behaviour and the full offline topology; a network self test over the worker
(relay + both tunnels + the host build of the agent) reproduced the whole session including
the captured BYE (`reason: CLIENT_CLOSE`, held resources `[]`, cleanup `COMPLETE`, agent exit 0
with `bye_reason: CLIENT_CLOSE`, 13 provider entries, 0 violations). A live re-run that
captures the BYE on the console would be a second payload upload and therefore needs a fresh
explicit approval and rearm.

## 10a. W8-D1 deviation record (accepted)

    id:           W8-D1
    title:        LIVE_BYE_NOT_CAPTURED_DUE_TO_RELAY_FULL_CLOSE
    disposition:  ACCEPTED -> VERIFIED_FIXED (2026-10-05, W10)
                  The corrected half-close relay captured the BYE live in the W9 run of
                  2026-10-05: reason CLIENT_CLOSE, cleanup COMPLETE, resources [] and no
                  recovery state, with the session ended cleanly afterwards. The D1 root cause is
                  therefore fixed *and* demonstrated live; the W9 live evidence pack is the proof.
                  The original W8 live pack stays as executed and is not re-captured.
    decided by:   owner review, 2026-10-05 (ACCEPTED), W9 live evidence (VERIFIED_FIXED)

    reason:       The transport relay ended the reverse direction before the final BYE frame.
                  The live resource state and the target health were clean. The root cause was
                  reproduced offline and the corrected relay path captures the expected BYE
                  deterministically.

    constraint:   No second live W8 upload just to re-capture the BYE.
                  No retroactive change to the executed live run; the live evidence pack stays
                  as executed.

Accepted W8 state (owner review):

* exactly one BinLoader upload
* real PS4 userland agent proven (relay log: payload connected from 192.168.1.141)
* authenticated handshake and READY
* 14/14 expected requests
* memory ref released cleanly
* gate lifecycle clean (closed -> release -> released)
* final held_resources empty
* cleanup COMPLETE
* kernel.read correctly OPERATION_DEFERRED
* provider_entry = false, no privileged provider entered
* relay log documents the session end
* PS4 health green afterwards
* missing live BYE explained by the relay full-close behaviour
* relay fix reproduced offline and proven with BYE + CLIENT_CLOSE + CLEANUP COMPLETE

Evidence references (kept separate on purpose):

* live run, unchanged: ``~/07-evidence/20261005T195043Z_ps4rf_p4w8-live`` - ``VERIFY_OK``,
  SHA256SUMS self hash ``11942a122c8a1e81eee4597d726f52c8f5b1182d69cbc889a0f9ad62e33eb4a1``
* relay fix, separate: ``~/07-evidence/20261005T195347Z_ps4rf_p4w8-relay-fix`` - ``VERIFY_OK``,
  SHA256SUMS self hash ``0182a76f8deeb7ed1adc3e1f29c886f153e41e376b7d7ae86f1b5d27e59911c9``
* commits: ``55edcbb`` (W8 offline half) -> ``67f526e`` (W8 follow-up, relay half close)

## 11. Stop condition

W8 ends with **STOP for review**. Not part of W8: kexec, kernel reads, runtime kbase, kernel
profile validation, GPUVM, KeyMgr, CCP, SAMU. W9 (the first read-only privileged bring-up) is
released separately.
