# Safety and Execution Rules

- `PROVEN` requires store-bound `VerificationEvidence` and provider authority.
- Mutating calls are rejected in `RECOVERY_REQUIRED`.
- No automatic retry after hang, panic, crash or unexpected target state.
- No generic `call(address, args)` kernel RPC.
- No arbitrary kernel-write RPC.
- Only registered primitives may be executed by the agent.
- Firmware addresses must resolve through a profile.
- Cleanup fails closed. Unknown state becomes `UNCERTAIN`, marks the console dirty and requires recovery.
- Evidence must never be invented. No PASS without a real run.
- Scanner or adapter findings do not automatically trigger exploit execution.
- BinLoader port 9090 must never be probed before payload delivery on the real PS4 research workflow.
