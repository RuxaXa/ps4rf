/* ps4rf_ioctl_policy_data.h -- first-version command policy (W17).

Values mirror tests/fixtures/experiments/ioctl-policy-v1.json; the command
decoding comes from the frozen pup_update analysis (one dispatcher, one jump
table, sub 0 = Q6 worker, sub 3 = OWN-1). Experiment contents (window geometry,
markers, segment layout) are NOT here -- they live in the experiments.

W17F: the last two columns are the argument block's pointer field and the upper
bound of the write payload that field may receive.

* the pointer field is the offset of the u64 the driver reads as a USER address.
  The provider always replaces it with the address of its own transfer buffer, so
  the caller of the RPC never supplies an address -- and never sees one used.
* W18: for the submit family (0xC0184401, handler 0x638230) the driver reads the
  block as { u64 cpuaddr@0x00, u64 size@0x08, u32 mode@0x10 }. The cpuaddr goes to
  gpuvm.c `map` (extractCpuAddrUser -> vm_fault_quick_hold_pages -> gbase_map), which
  holds the address to a 0x4000 boundary and maps one 0x4000 unit; the size is round
  checked to 0x4000 (0x638295..0x6382b9, otherwise EINVAL); the mode word is only
  compared against 2 (an extra engine pass). The declared field is therefore 0, and
  the field the old policy named (8) is the caller's SIZE -- replacing it was exactly
  the deterministic EINVAL the live runs measured.
* 0xC0184404 keeps its own layout from the same dispatcher ({ u16, u64, u64 }); its
  fields are not proven, so its declaration is left as it was.
* `data_max` is the largest payload the experiment may have placed there; it is
  the same bound the historical call geometry used (16384 for the submit family,
  65536 for the trigger), never larger than PS4RF_IOCTL_MAX_DATA.
* the status read takes no pointer field: it fills its 260 byte response from the
  driver, so it is declared with PS4RF_IOCTL_NO_PTR_FIELD.
*/
#ifndef PS4RF_IOCTL_POLICY_DATA_H
#define PS4RF_IOCTL_POLICY_DATA_H

#include "ps4rf_ioctl.h"

/* ps4rf_ioctl_rule: command, blob_len, out_len, mode_present, mode, ptr_field, data_max.
 * The device and the rule set are inline (pointer free: the payload is entered without a dynamic
 * loader, so the whole policy must carry no relocation). */
static const ps4rf_ioctl_policy PS4RF_IOCTL_POLICY = {
  "/dev/pup_update0", 3u,
  {
    { 0xC0184401u, 24u, 0u,   0u, 0u, 0u,                       0x4000u },
    { 0xC010440Au, 24u, 260u, 0u, 0u, PS4RF_IOCTL_NO_PTR_FIELD, 0u },
    { 0xC0184404u, 24u, 0u,   1u, 1u, 8u,                       0x10000u },
  }
};

#endif /* PS4RF_IOCTL_POLICY_DATA_H */
