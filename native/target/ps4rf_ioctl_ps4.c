/* PS4RF W17 -- console platform layer for the bounded ioctl invoke.
 *
 * Exactly three libPS4 entry points: open() / ioctl() / close(), plus __error() for errno. The
 * device path comes from the compile-time policy, the command from the allowlist, the argument
 * block and the write payload from ONE provider-owned buffer that is never larger than
 * PS4RF_IOCTL_XFER_BYTES. Nothing here allocates: the buffer is a compile-time object, so the
 * address the device receives is deterministic and belongs to the payload.
 *
 * The host build links ps4rf_ioctl_host.c instead: no device, no fd, open() fails and the request
 * is refused before any call -- the fail-closed stand-in. The dev-host rehearsal links
 * tests/harness/ps4rf_recipe_sim.c, which replays a recorded device trace.
 */
#include "ps4rf_ioctl.h"

#include "ps4rf_libc.h"

/* libPS4 (kernel.h / file.h): compiled-in syscall wrappers plus the errno pointer table. */
extern int open(const char *path, int flags, int mode);
extern int close(int fd);
extern int ioctl(int fd, unsigned long com, void *data);
extern int *(*__error)(void);

/* the provider-owned transfer block: argument block at offset 0, write payload at
 * PS4RF_IOCTL_DATA_OFFSET. One object per payload, no per-request allocation. */
static uint8_t g_transfer[PS4RF_IOCTL_XFER_BYTES];

static void *ps4_open(void *ctx, const char *device, uint32_t flags) {
  int fd;
  (void)ctx;
  if (device == 0) return 0;
  fd = open(device, (int)flags, 0);
  if (fd < 0) return 0;
  /* fd 0 must not collide with the NULL "no descriptor" value of the ops contract */
  return (void *)(uintptr_t)((uint32_t)fd + 1u);
}

static int ps4_call(void *ctx, void *fd, uint32_t command, uint8_t *data,
                    uint32_t data_len, uint8_t *out, uint32_t *out_len,
                    int32_t *err_out) {
  int raw = (int)(uintptr_t)fd - 1;
  uint32_t want = out_len != 0 ? *out_len : 0u;
  int rc;
  (void)ctx;
  (void)data_len;
  if (out_len != 0) *out_len = 0u;
  rc = ioctl(raw, (unsigned long)command, (void *)data);
  if (err_out != 0) *err_out = rc < 0 ? (int32_t)(__error != 0 ? *__error() : 0) : 0;
  if (rc >= 0 && out != 0 && want != 0u) {
    /* the driver's copyout lands in the same buffer the request was copied in from */
    uint32_t n = want > PS4RF_IOCTL_MAX_OUT ? PS4RF_IOCTL_MAX_OUT : want;
    memcpy(out, data, n);
    *out_len = n;
  }
  return rc;
}

static void ps4_close(void *ctx, void *fd) {
  (void)ctx;
  if (fd == 0) return;
  close((int)(uintptr_t)fd - 1);
}

static uint8_t *ps4_transfer(void *ctx, uint32_t len) {
  (void)ctx;
  if (len > (uint32_t)sizeof g_transfer) return 0;
  return g_transfer;
}

/* W17F: the ops table is built once, at runtime, into .bss. A `static const` struct of function
 * pointers would live in .data.rel.ro and force R_X86_64_RELATIVE relocations into the artefact,
 * which is entered without a dynamic loader. */
static ps4rf_ioctl_ops g_ops;
static int g_ops_ready;

const ps4rf_ioctl_ops *ps4rf_ioctl_target_ops(void) {
  if (!g_ops_ready) {
  g_ops.open = ps4_open;
  g_ops.ioctl = ps4_call;
  g_ops.close = ps4_close;
  g_ops.transfer = ps4_transfer;
    g_ops_ready = 1;
  }
  return &g_ops;
}
