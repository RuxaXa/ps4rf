/* ps4rf_ioctl.c -- generic bounded ioctl invoke (W17). */
#include "ps4rf_ioctl.h"

#include <string.h>

static int same_device(const char *a, const char *b) {
  if (a == 0 || b == 0) return 0;
  size_t i = 0;
  for (; a[i] != 0 && b[i] != 0; i++) if (a[i] != b[i]) return 0;
  return a[i] == 0 && b[i] == 0;
}

int ps4rf_ioctl_policy_check(const ps4rf_ioctl_policy *policy, const char *device,
                             uint32_t command, uint32_t blob_len,
                             const uint32_t *mode, const ps4rf_ioctl_rule **rule_out) {
  if (rule_out) *rule_out = 0;
  if (policy == 0 || policy->count == 0 || policy->count > PS4RF_IOCTL_MAX_RULES) {
    return (int)PS4RF_IOCTL_REFUSED_DEVICE;
  }
  if (!same_device(policy->device, device)) return (int)PS4RF_IOCTL_REFUSED_DEVICE;
  for (uint32_t i = 0; i < policy->count; i++) {
    const ps4rf_ioctl_rule *r = &policy->rules[i];
    if (r->command != command) continue;
    if (blob_len != r->blob_len || r->blob_len > PS4RF_IOCTL_MAX_BLOB) return (int)PS4RF_IOCTL_REFUSED_BLOB;
    if (r->out_len > PS4RF_IOCTL_MAX_OUT) return (int)PS4RF_IOCTL_REFUSED_BLOB;
    if (r->data_max > PS4RF_IOCTL_MAX_DATA) return (int)PS4RF_IOCTL_REFUSED_BLOB;
    if (r->ptr_field != PS4RF_IOCTL_NO_PTR_FIELD && r->ptr_field + 8u > r->blob_len) {
      return (int)PS4RF_IOCTL_REFUSED_BLOB;   /* the declared field must live in the block */
    }
    if (r->mode_present) {
      if (mode == 0 || *mode != r->mode) return (int)PS4RF_IOCTL_REFUSED_MODE;
    } else if (mode != 0) {
      return (int)PS4RF_IOCTL_REFUSED_MODE;
    }
    if (rule_out) *rule_out = r;
    return (int)PS4RF_IOCTL_OK;
  }
  return (int)PS4RF_IOCTL_REFUSED_COMMAND;
}

/* W17F: the argument block the device call uses. The block and the write payload live in ONE
 * provider-owned buffer; the device receives the address of the block, and the block's declared
 * pointer field receives the address of the payload region. No address ever comes from the
 * request -- a field present in the request block is overwritten, never used.
 *
 * W18 submit ABI: for 0xC0184401 the declared field is the block's FIRST u64 (the kernel reads it
 * as the cpuaddr it pins and maps), the second u64 is the request size the handler rounds to
 * 0x4000, and the u32 at 0x10 is the mode word. The staging therefore writes exactly eight bytes
 * at the declared offset and leaves every other byte of the request block -- size, mode and
 * padding included -- as the caller sent it. */
uint8_t *ps4rf_ioctl_stage(void *ctx, const ps4rf_ioctl_ops *ops, const ps4rf_ioctl_rule *rule,
                           const uint8_t *blob, uint32_t blob_len,
                           const uint8_t *data, uint32_t data_len, int *patched) {
  uint8_t *buf;
  if (patched) *patched = 0;
  if (ops == 0 || ops->transfer == 0 || rule == 0) return 0;
  if (blob == 0 || blob_len == 0 || blob_len > PS4RF_IOCTL_MAX_BLOB) return 0;
  if (data_len > rule->data_max) return 0;
  if (rule->ptr_field == PS4RF_IOCTL_NO_PTR_FIELD) {
    /* no declared field: a write payload has nowhere to go, so the request is refused rather
     * than silently dropped (and a request without payload has no reason to be staged) */
    return 0;
  }
  if (rule->ptr_field + 8u > blob_len) return 0;
  buf = ops->transfer(ctx, (uint32_t)PS4RF_IOCTL_XFER_BYTES);
  if (buf == 0) return 0;
  /* the payload region is aligned at run time: the driver holds the address it is handed to a
   * 0x4000 boundary (gpuvm map: cpuaddr alignment) and maps one unit of it, while the object
   * itself stays PS4RF_IOCTL_XFER_BYTES bytes. A request whose data would not fit behind that
   * boundary is refused rather than staged half-way. */
  {
    uintptr_t region = ((uintptr_t)buf + (uintptr_t)PS4RF_IOCTL_DATA_OFFSET
                        + (uintptr_t)(PS4RF_IOCTL_ALIGN - 1u))
                       & ~(uintptr_t)(PS4RF_IOCTL_ALIGN - 1u);
    if (region + (uintptr_t)data_len > (uintptr_t)buf + (uintptr_t)PS4RF_IOCTL_XFER_BYTES) {
      return 0;
    }
    memcpy(buf + PS4RF_IOCTL_BLOCK_OFFSET, blob, blob_len);
    if (data_len != 0u) memcpy((uint8_t *)region, data, data_len);
    for (uint32_t i = 0; i < 8u; i++) {
      buf[PS4RF_IOCTL_BLOCK_OFFSET + rule->ptr_field + i] =
          (uint8_t)(((uint64_t)region >> (8u * i)) & 0xffu);
    }
  }
  if (patched) *patched = 1;
  return buf + PS4RF_IOCTL_BLOCK_OFFSET;
}

int ps4rf_ioctl_invoke(void *ctx, const ps4rf_ioctl_policy *policy,
                       const ps4rf_ioctl_ops *ops, const char *device,
                       uint32_t command, const uint8_t *blob, uint32_t blob_len,
                       const uint32_t *mode, ps4rf_ioctl_result *out) {
  if (ops == 0 || out == 0 || ops->open == 0 || ops->ioctl == 0 || ops->close == 0) return -1;
  memset(out, 0, sizeof(*out));
  out->command = command;
  const ps4rf_ioctl_rule *rule = 0;
  int verdict = ps4rf_ioctl_policy_check(policy, device, command, blob_len, mode, &rule);
  if (verdict != (int)PS4RF_IOCTL_OK) { out->verdict = (uint32_t)verdict; return 0; }
  void *fd = ops->open(ctx, policy->device, 0x0002u /* O_RDWR */);
  if (fd == 0) { out->verdict = PS4RF_IOCTL_REFUSED_OPEN; return 0; }
  uint32_t got = rule->out_len;
  int32_t err = 0;
  /* W17F: `blob` is the buffer the device call uses -- the provider-owned transfer block when a
   * pointer field is declared (staged and patched by ps4rf_ioctl_stage), the request block
   * otherwise. The response bytes come back through `out`. */
  int rc = ops->ioctl(ctx, fd, command, (uint8_t *)blob, blob_len, out->out, &got, &err);
  ops->close(ctx, fd);
  out->rc = (int32_t)rc;
  out->err = err;
  out->out_len = got > PS4RF_IOCTL_MAX_OUT ? PS4RF_IOCTL_MAX_OUT : got;
  if (rc != 0) {
    /* performed, and the device said no: the rc/errno are the finding, not a provider refusal */
    out->verdict = PS4RF_IOCTL_REFUSED_IOCTL;
    return 0;
  }
  out->verdict = PS4RF_IOCTL_OK;
  return 0;
}

const char *ps4rf_ioctl_verdict_name(uint32_t verdict) {
  switch (verdict) {
    case PS4RF_IOCTL_OK: return "OK";
    case PS4RF_IOCTL_REFUSED_DEVICE: return "REFUSED_DEVICE";
    case PS4RF_IOCTL_REFUSED_COMMAND: return "REFUSED_COMMAND";
    case PS4RF_IOCTL_REFUSED_BLOB: return "REFUSED_BLOB";
    case PS4RF_IOCTL_REFUSED_MODE: return "REFUSED_MODE";
    case PS4RF_IOCTL_REFUSED_OPEN: return "REFUSED_OPEN";
    case PS4RF_IOCTL_REFUSED_IOCTL: return "REFUSED_IOCTL";
    default: return "UNKNOWN";
  }
}
