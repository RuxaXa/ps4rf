# PS4 Research Context

## Platforms

- Primary research target: PS4 Slim, firmware 13.52.
- Reference target: firmware 9.00 for comparison and differential work.

## Research domains already explored

Kernel, syscalls/ioctls, GPUVM, KeyMgr, CCP, SAMU, PUP, SBL/secure services, SBRAM, EAP/EMC, GPU, WebKit/userland, TOCTOU/double-fetch and firmware diffing.

## Existing experiment names to preserve

`historical_hmac_prefix`, `zero_key_c3`, `slot_release_reuse`, `slot_ownership_toctou`, `gpuvm_validate_unmap_use`, `gpuvm_stale_descriptor`, `ccp_double_fetch`, `ccp_multi_message_failure`, `pup_valid_invalid_valid`, `pup_state_accumulation`, `eap_staging_toctou`, `sbram_cross_processor_canary`.

## Important transition

The framework should avoid one-off payload development for every hypothesis. Missing low-level capability extends the agent; new research questions should normally become experiments.
