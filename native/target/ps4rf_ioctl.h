/* ps4rf_ioctl.h -- generic bounded ioctl invoke (W17).

The provider knows nothing about device specific payload layouts. It offers
exactly: a device from the policy, a command from the allowlist, a fixed
maximum argument size, open / ioctl / close, and the rc / errno / output back.
Device specific layout lives in the experiment layer, never here.
*/
#ifndef PS4RF_IOCTL_H
#define PS4RF_IOCTL_H

#include <stdint.h>

#define PS4RF_IOCTL_MAX_BLOB 64u
#define PS4RF_IOCTL_MAX_OUT 0x1000u
/* W17F: the largest write payload the provider ever places in its own transfer buffer.
 * It is not a request side address and not a request side allocation: the buffer is a
 * compile-time object of the provider, and only its CONTENT is bounded by this value. */
#define PS4RF_IOCTL_MAX_DATA 0x10000u

typedef struct {
  /* W17F: no device pointer per rule. The device is policy level and stored as an inline array,
   * so neither the rule table nor the policy can carry a relocation (the payload is entered
   * without a dynamic loader; the build gate requires zero relocations). */
  uint32_t command;        /* allowlisted command number */
  uint32_t blob_len;       /* exact argument size this command takes */
  uint32_t out_len;        /* response bytes, 0 when the command returns none */
  uint32_t mode_present;   /* 1 when the command carries a mode word */
  uint32_t mode;           /* the only accepted mode value */
  /* W17F: byte offset of the pointer field inside the argument block, or
   * PS4RF_IOCTL_NO_PTR_FIELD when the command takes no user pointer. When a field is
   * declared the provider REPLACES it with the address of its own transfer buffer: the
   * caller never supplies an address, and the device never sees one from the wire. */
  uint32_t ptr_field;
  uint32_t data_max;       /* upper bound of the write payload for this command */
} ps4rf_ioctl_rule;

#define PS4RF_IOCTL_NO_PTR_FIELD 0xFFFFFFFFu

/* W17F: the provider-owned transfer buffer holds the argument block at offset 0 and the write
 * payload at PS4RF_IOCTL_DATA_OFFSET. One object, two regions, no per-request allocation.
 *
 * W18 submit ABI (proven from the FW13.52 image, see the policy data): the value the device
 * receives in the argument block's pointer field is this buffer plus PS4RF_IOCTL_DATA_OFFSET, and
 * the driver's mapping path (gpuvm.c map: extractCpuAddrUser -> vm_fault_quick_hold_pages ->
 * gbase_map) holds the cpuaddr to a 0x4000 boundary and maps exactly one 0x4000 unit -- so the
 * payload region starts on that boundary, the object itself is aligned to it, and the mapped
 * 0x4000 bytes are exactly the staged payload. */
/* The argument block sits at the front, the payload region behind it, aligned at run time to
 * PS4RF_IOCTL_ALIGN -- the driver holds the address it is given to that boundary (gpuvm map:
 * cpuaddr alignment), and one 0x4000 unit of it is mapped. Aligning at run time keeps the object
 * exactly PS4RF_IOCTL_XFER_BYTES bytes: the payload region starts at the first boundary behind the
 * block, and a request whose data would not fit behind that boundary is refused. */
#define PS4RF_IOCTL_DATA_OFFSET PS4RF_IOCTL_MAX_BLOB
#define PS4RF_IOCTL_BLOCK_OFFSET 0u
#define PS4RF_IOCTL_XFER_BYTES (PS4RF_IOCTL_MAX_DATA + PS4RF_IOCTL_MAX_BLOB)
#define PS4RF_IOCTL_ALIGN 0x4000u
#define PS4RF_IOCTL_ALIGNED __attribute__((aligned(PS4RF_IOCTL_ALIGN)))

#define PS4RF_IOCTL_DEVICE_MAX 32u
#define PS4RF_IOCTL_MAX_RULES 4u

typedef struct {
  /* W17F: fully inline and pointer free -- device as a character array, rules as a fixed
   * array. A pointer member would place the policy in .data.rel.ro and force a RELATIVE
   * relocation into the artefact (which is entered without a dynamic loader). */
  char device[PS4RF_IOCTL_DEVICE_MAX];
  uint32_t count;
  ps4rf_ioctl_rule rules[PS4RF_IOCTL_MAX_RULES];
} ps4rf_ioctl_policy;

typedef struct {
  void *(*open)(void *ctx, const char *device, uint32_t flags);
  /* `data` is the provider-owned argument block (already staged and pointer-patched when the
   * rule declares a field); `*out_len` enters as the capacity from the policy and leaves as the
   * number of response bytes the device returned. `data_len` is the block size. */
  int (*ioctl)(void *ctx, void *fd, uint32_t command, uint8_t *data,
               uint32_t data_len, uint8_t *out, uint32_t *out_len, int32_t *err_out);
  void (*close)(void *ctx, void *fd);
  /* W17F: the provider-owned transfer buffer. `len` is the number of bytes the caller
   * needs (argument block and write payload region); NULL means the platform cannot supply
   * one and the request is refused before the device is opened. The address never crosses
   * the wire. */
  uint8_t *(*transfer)(void *ctx, uint32_t len);
} ps4rf_ioctl_ops;

enum {
  PS4RF_IOCTL_OK = 0u,
  PS4RF_IOCTL_REFUSED_DEVICE = 1u,
  PS4RF_IOCTL_REFUSED_COMMAND = 2u,
  PS4RF_IOCTL_REFUSED_BLOB = 3u,
  PS4RF_IOCTL_REFUSED_MODE = 4u,
  PS4RF_IOCTL_REFUSED_OPEN = 5u,
  PS4RF_IOCTL_REFUSED_IOCTL = 6u
};

typedef struct {
  uint32_t verdict;      /* PS4RF_IOCTL_* */
  uint32_t command;
  uint32_t out_len;
  int32_t rc;            /* the command's return value */
  int32_t err;           /* errno reported by the platform layer */
  uint8_t out[PS4RF_IOCTL_MAX_OUT];
} ps4rf_ioctl_result;

int ps4rf_ioctl_policy_check(const ps4rf_ioctl_policy *policy, const char *device,
                             uint32_t command, uint32_t blob_len,
                             const uint32_t *mode, const ps4rf_ioctl_rule **rule_out);
int ps4rf_ioctl_invoke(void *ctx, const ps4rf_ioctl_policy *policy,
                       const ps4rf_ioctl_ops *ops, const char *device,
                       uint32_t command, const uint8_t *blob, uint32_t blob_len,
                       const uint32_t *mode, ps4rf_ioctl_result *out);
const char *ps4rf_ioctl_verdict_name(uint32_t verdict);

/* W17F: place `data` (data_len bytes, <= the rule's data_max) in the provider's own transfer
 * buffer, write that buffer's payload address into the rule's declared pointer field of the
 * argument block, and return the block the device call must use. The caller never supplies an
 * address: a field present in the request block is overwritten, never used. Returns NULL when the
 * platform has no transfer buffer, when the rule declares no field, or on any bound violation. */
uint8_t *ps4rf_ioctl_stage(void *ctx, const ps4rf_ioctl_ops *ops, const ps4rf_ioctl_rule *rule,
                           const uint8_t *blob, uint32_t blob_len,
                           const uint8_t *data, uint32_t data_len, int *patched);

#endif /* PS4RF_IOCTL_H */
