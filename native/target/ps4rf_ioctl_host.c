/* PS4RF W17 -- host-build stand-in for the console ioctl platform layer.
 *
 * A host has no /dev/pup_update0 and no business touching a device, so this layer is honestly
 * incapable: there is no descriptor, no call and no transfer buffer, which means every
 * ioctl.invoke request is refused (REFUSED_OPEN) instead of being answered with an invented
 * result -- the fail-closed path the offline end-to-end run exercises.
 *
 * The definitions are WEAK on purpose: the dev-host rehearsal link
 * (tests/harness/ps4rf_recipe_sim.c) defines ps4rf_ioctl_target_ops() strongly and replays a
 * recorded device trace through the same production provider. That object is never part of a
 * console artefact.
 */
#include "ps4rf_ioctl.h"

static void *host_open(void *ctx, const char *device, uint32_t flags) {
  (void)ctx;
  (void)device;
  (void)flags;
  return 0;                       /* no descriptor without a device */
}

static int host_call(void *ctx, void *fd, uint32_t command, uint8_t *data,
                     uint32_t data_len, uint8_t *out, uint32_t *out_len,
                     int32_t *err_out) {
  (void)ctx;
  (void)fd;
  (void)command;
  (void)data;
  (void)data_len;
  (void)out;
  (void)out_len;
  if (err_out != 0) *err_out = 0;
  return -1;                      /* never reached: open() already refused */
}

static void host_close(void *ctx, void *fd) {
  (void)ctx;
  (void)fd;
}

static uint8_t *host_transfer(void *ctx, uint32_t len) {
  (void)ctx;
  (void)len;
  return 0;                       /* no buffer, so no pointer field can be staged */
}

/* W17F: the ops table is built once, at runtime, into .bss. A `static const` struct of function
 * pointers would live in .data.rel.ro and force R_X86_64_RELATIVE relocations into the artefact,
 * which is entered without a dynamic loader. */
static ps4rf_ioctl_ops g_ops;
static int g_ops_ready;

__attribute__((weak)) const ps4rf_ioctl_ops *ps4rf_ioctl_target_ops(void) {
  if (!g_ops_ready) {
  g_ops.open = host_open;
  g_ops.ioctl = host_call;
  g_ops.close = host_close;
  g_ops.transfer = host_transfer;
    g_ops_ready = 1;
  }
  return &g_ops;
}
