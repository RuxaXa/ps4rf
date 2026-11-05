# PS4RF Research Model

PS4RF organizes research into four top-level activities.

1. **OBSERVE** — attack surfaces, reachability, taint, state, logs and firmware differences.
2. **EXPERIMENT** — data-driven bounded experiments, invariants, cleanup and race coordination.
3. **DISCOVER** — structural/stateful/race/differential fuzzing, triage, deduplication and ranking.
4. **EXPLOIT RESEARCH** — reproducer to primitive to exploit provider to chain.

## Surface domains

`browser`, `media`, `network`, `usb`, `bt`, `fs`, `ipc`, `kernel`, `gpu`, `pup`, `secure_service`, `package`, `savegame`.

## Candidate lifecycle

```text
OBSERVATION -> ANOMALY -> BUG -> PRIMITIVE -> EXPLOIT_CANDIDATE -> EXPLOITABLE -> CHAINABLE
                         \-> CLOSED / PARKED
```

## Initial invariants

- `INV_SLOT_001`: released slot must not remain usable.
- `INV_GPUVM_001`: no stale descriptor after unmap.
- `INV_CCP_001`: no unauthorized partial FROM_SLOT key length.
- `INV_CCP_002`: failure of message N must not leak partial state into N+1.
- `INV_PUP_001`: failed validation resets secure state.
- `INV_EAP_001`: validated staging must not be replaceable before consumption.
