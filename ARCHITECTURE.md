# PS4RF Architecture

## Host and target

The host is authoritative for orchestration, experiment IR, profiles, evidence, discovery and adapter integration. The target agent exposes bounded primitives only.

```text
Research Host
    |
    +-- ps4rfctl
    +-- Experiment Engine
    +-- Evidence Store
    +-- OrbisProbe / tool adapters
    |
    +==== authenticated versioned RPC ====> ps4rfd / MockAgent
                                             |
                                             +-- userland primitives
                                             +-- kernel primitives
                                             +-- GPUVM / KeyMgr / CCP / SAMU
```

## Handshake roles

Semantic roles are independent of TCP connect/accept direction.

```text
AGENT (ps4rfd / MockAgent): HELLO -> HELLO_ACK <- ; AUTH -> AUTH_ACK <-
HOST  (ps4rfctl):           <- HELLO ; HELLO_ACK -> ; <- AUTH ; AUTH_ACK ->
```

The transcript is the SHA-256 of JCS canonical `AGENT_HELLO || HOST_HELLO_ACK`. The host selects authenticated runtime limits.

## Capabilities

Two independent axes:

- Availability: `UNKNOWN`, `AVAILABLE`, `DEGRADED`, `UNAVAILABLE`
- Assurance: `UNVERIFIED`, `OBSERVED`, `PROVEN`

`PROVEN + UNAVAILABLE` is not granted, but evidence quality remains PROVEN.

## BOOT and SESSION

- SESSION records bind to `session_id` and `boot_id`.
- BOOT records bind to exactly one boot and never survive reboot.
- Persistent facts live in profiles/evidence and are re-ingested each boot.
- Session runtime availability overrides boot availability when concrete; assurance is merged conservatively by evidence strength.

## Recovery

Uncertain cleanup or a stuck execution can poison the session/console and enter `RECOVERY_REQUIRED`. Only explicitly recovery-safe read operations are allowed until recovery/reboot.

## Concurrency

RPC supports bounded concurrent in-flight requests correlated by request IDs. Barrier is an automatic rendezvous; Gate is manually released and exists specifically for deterministic race/TOCTOU experiments.
