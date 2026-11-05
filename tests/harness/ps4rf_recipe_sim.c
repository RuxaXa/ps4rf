/* PS4RF W17 -- the offline rehearsal stand-in for the two platform seams.

This object replaces ps4rf_recipe_host.c (the fail-closed host stand-ins) and
ps4rf_ioctl_host.c (the host platform layer) in a *dev-host rehearsal* build. It defines the same
symbols strongly, so the production providers and the production dispatch run unchanged on top of
it: kernel.snapshot.recipe walks the real table through the real privileged-callback protocol, and
ioctl.invoke stages its own transfer block and enters the real provider.

What it is NOT: a simulation of a console. It replays a *tape* (PS4RF_RPC_TAPE) recorded from the
experiment layer's own simulated console -- the same model the oracle classification was derived
on. Every recorded read must be asked for with exactly the VA and length it was recorded with, in
the recorded order; every device call must arrive with the recorded command and block. Any
divergence aborts the process: a rehearsal that answers a question nobody asked is worthless.

Checks the tape player makes and reports by aborting or by refusing:

  * the read leaf is only ever entered from inside a recorded read, and the bytes it hands out are
    the recorded ones in the recorded order (a walk that composed a different VA is caught);
  * the device call receives the provider's OWN transfer buffer as its argument block (not the
    request block) and the block's declared pointer field holds a fresh, non-zero value that is not
    what the caller sent -- i.e. the address the device sees cannot come from the wire;
  * every command in the tape is answered exactly once, in order.
*/
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "ps4rf_ioctl.h"

/* NOTE: ps4rf_recipe_target.h is deliberately NOT included here. Its declaration of
 * ps4rf_recipe_k_read8 carries __attribute__((weak)) -- the payload's fallback leaf -- and an
 * attribute inherited from a declaration would make this file's definition weak too, so the
 * linker would keep the payload's `mov (%rdi),%al` dereference and the rehearsal would read real
 * memory instead of the tape. This definition is strong on purpose: strong beats weak regardless
 * of link order, which is exactly what the rehearsal needs. */

#define SIM_MAX_READS 256u
#define SIM_MAX_IOCTLS 32u
#define SIM_MAX_REGION 0x1000u

typedef struct {
  uint64_t va;
  uint32_t len;
  uint8_t data[SIM_MAX_REGION];
} sim_read;

typedef struct {
  uint32_t command;
  uint32_t blob_len;
  int32_t ptr_field;          /* -1 = the command declares no pointer field */
  int32_t rc;
  int32_t err;
  uint32_t out_len;
  uint8_t out[SIM_MAX_REGION];
  uint8_t blob[PS4RF_IOCTL_MAX_BLOB];
  uint8_t sent_field[8];      /* what the recorded request carried at the pointer field */
} sim_ioctl;

static sim_read g_reads[SIM_MAX_READS];
static uint32_t g_read_count;
static uint32_t g_read_index;
static sim_ioctl g_ioctls[SIM_MAX_IOCTLS];
static uint32_t g_ioctl_count;
static uint32_t g_ioctl_index;
static uint64_t g_kbase;
static char g_scenario[64];
static uint32_t g_leaf_index;
static int g_in_read;
static uint8_t g_transfer[PS4RF_IOCTL_XFER_BYTES] PS4RF_IOCTL_ALIGNED;
static int g_ops_ready;
static ps4rf_ioctl_ops g_ops;
/* the kernel hands the payload a wrapper whose first field is not the payload's business; the
 * rehearsal points it at a real object so a payload that read it would read defined bytes */
static uint8_t g_wrapper_field0;

static void sim_fail(const char *why) {
  fprintf(stderr, "rehearsal tape: %s (scenario %s, read %u/%u, ioctl %u/%u)\n", why,
          g_scenario[0] ? g_scenario : "?", g_read_index, g_read_count, g_ioctl_index,
          g_ioctl_count);
  exit(3);
}

static int hexval(int c) {
  if (c >= '0' && c <= '9') return c - '0';
  if (c >= 'a' && c <= 'f') return c - 'a' + 10;
  if (c >= 'A' && c <= 'F') return c - 'A' + 10;
  return -1;
}

static uint32_t decode_hex(const char *text, uint8_t *out, uint32_t cap) {
  uint32_t n = 0;
  size_t i;
  size_t len = strlen(text);
  if (len % 2u != 0u) sim_fail("odd hex field");
  for (i = 0; i < len; i += 2u) {
    int hi = hexval((unsigned char)text[i]);
    int lo = hexval((unsigned char)text[i + 1u]);
    if (hi < 0 || lo < 0) sim_fail("bad hex field");
    if (n >= cap) sim_fail("hex field larger than the recorded bound");
    out[n++] = (uint8_t)((hi << 4) | lo);
  }
  return n;
}

static void sim_load(const char *path) {
  FILE *f = fopen(path, "r");
  char line[8192];
  if (f == NULL) sim_fail("tape cannot be opened");
  while (fgets(line, sizeof line, f) != NULL) {
    char *nl = strchr(line, '\n');
    if (nl != NULL) *nl = '\0';
    if (line[0] == '\0' || line[0] == '#') continue;
    if (strncmp(line, "scenario ", 9u) == 0) {
      snprintf(g_scenario, sizeof g_scenario, "%s", line + 9);
      continue;
    }
    if (strncmp(line, "kbase ", 6u) == 0) {
      g_kbase = strtoull(line + 6, NULL, 16);
      continue;
    }
    if (strncmp(line, "read ", 5u) == 0) {
      char *va_text = line + 5;
      char *sp = strchr(va_text, ' ');
      if (sp == NULL || g_read_count >= SIM_MAX_READS) sim_fail("read line malformed");
      *sp = '\0';
      g_reads[g_read_count].va = strtoull(va_text, NULL, 16);
      g_reads[g_read_count].len = decode_hex(sp + 1, g_reads[g_read_count].data, SIM_MAX_REGION);
      if (g_reads[g_read_count].len == 0u) sim_fail("recorded read is empty");
      g_read_count++;
      continue;
    }
    if (strncmp(line, "ioctl ", 6u) == 0) {
      char *fields[6];
      uint32_t nf = 0;
      char *p = line + 6;
      while (nf < 6u && p != NULL) {
        fields[nf++] = p;
        p = strchr(p, ' ');
        if (p != NULL) *p++ = '\0';
      }
      if (nf != 6u || g_ioctl_count >= SIM_MAX_IOCTLS) sim_fail("ioctl line malformed");
      sim_ioctl *rec = &g_ioctls[g_ioctl_count];
      memset(rec, 0, sizeof *rec);
      rec->command = (uint32_t)strtoul(fields[0], NULL, 16);
      rec->blob_len = decode_hex(fields[1], rec->blob, PS4RF_IOCTL_MAX_BLOB);
      rec->ptr_field = strcmp(fields[2], "none") == 0 ? -1 : (int32_t)strtol(fields[2], NULL, 10);
      rec->rc = (int32_t)strtol(fields[3], NULL, 10);
      rec->err = (int32_t)strtol(fields[4], NULL, 10);
      rec->out_len = (strcmp(fields[5], "-") == 0) ? 0u
                                                   : decode_hex(fields[5], rec->out, SIM_MAX_REGION);
      if (rec->ptr_field >= 0 && (uint32_t)(rec->ptr_field + 8) <= rec->blob_len) {
        memcpy(rec->sent_field, rec->blob + rec->ptr_field, 8u);
      }
      g_ioctl_count++;
      continue;
    }
  }
  fclose(f);
  if (g_read_count == 0u) sim_fail("tape carries no read");
}

__attribute__((constructor)) static void sim_init(void) {
  const char *path = getenv("PS4RF_RPC_TAPE");
  if (path == NULL) sim_fail("PS4RF_RPC_TAPE is not set");
  sim_load(path);
}

/* ------------------------------------------------------------------ the kernel side of the seam */

uint64_t get_kernel_base(void) {
  return g_kbase;
}

__attribute__((noinline)) uint8_t ps4rf_recipe_k_read8(uint64_t va) {
  const sim_read *rec;
  if (!g_in_read) sim_fail("the read leaf was entered outside a recorded read");
  if (g_read_index >= g_read_count) sim_fail("the walk asked for more reads than were recorded");
  rec = &g_reads[g_read_index];
  if (g_leaf_index >= rec->len) sim_fail("the read leaf ran past the recorded length");
  if (rec->va + g_leaf_index != va) sim_fail("the read leaf VA does not match the recorded VA");
  return rec->data[g_leaf_index++];
}

int kexec(void *func, void *user_arg) {
  /* the console ABI the payload compiles against: the kernel wraps the caller's pointer in
   * { void *syscall_handler; void *info } and enters the payload with a pointer to that wrapper,
   * so the payload's second argument is the wrapper and its own block sits in field 2 */
  struct sim_wrapper {
    void *syscall_handler;
    void *info;
  } wrapper;
  int rc;
  if (g_read_index >= g_read_count) sim_fail("a privileged transition without a recorded read");
  if (g_leaf_index != 0u) sim_fail("the read leaf state was not left clean by the last read");
  wrapper.syscall_handler = (void *)&g_wrapper_field0;
  wrapper.info = user_arg;
  g_in_read = 1;
  rc = ((int (*)(void *, void *))func)((void *)0, (void *)&wrapper);
  g_in_read = 0;
  if (rc != 0) sim_fail("the callback refused a read that the console answered");
  if (g_leaf_index != g_reads[g_read_index].len) sim_fail("the read copied a different length");
  g_leaf_index = 0u;
  g_read_index++;
  return 0;
}

/* ---------------------------------------------------------------- the userland device seam */

static void *sim_open(void *ctx, const char *device, uint32_t flags) {
  (void)ctx;
  (void)flags;
  if (device == NULL || device[0] == '\0') sim_fail("open without a device path");
  return (void *)(uintptr_t)1u;
}

static int sim_call(void *ctx, void *fd, uint32_t command, uint8_t *data, uint32_t data_len,
                    uint8_t *out, uint32_t *out_len, int32_t *err_out) {
  sim_ioctl *rec;
  uint32_t want;
  (void)ctx;
  (void)fd;
  if (g_ioctl_index >= g_ioctl_count) sim_fail("a device call without a recorded call");
  rec = &g_ioctls[g_ioctl_index];
  if (command != rec->command) sim_fail("the device call command does not match the tape");
  if (data_len != rec->blob_len) sim_fail("the argument block size does not match the tape");
  if (data != g_transfer + PS4RF_IOCTL_BLOCK_OFFSET)
    sim_fail("the device was handed a block that is not the provider's "
                                   "own transfer buffer");
  if (rec->ptr_field >= 0) {
    uint64_t seen = 0ull;
    uint32_t i;
    for (i = 0u; i < 8u; i++) {
      seen |= (uint64_t)data[rec->ptr_field + i] << (8u * i);
    }
    if (seen == 0ull) sim_fail("the pointer field the device sees is zero: the provider did not "
                               "stage its own transfer buffer");
    {
      uint64_t sent = 0ull;
      for (i = 0u; i < 8u; i++) sent |= (uint64_t)rec->sent_field[i] << (8u * i);
      if (sent != 0ull && seen == sent) {
        sim_fail("the pointer field the device sees is the value the caller sent: the address "
                 "reached the device from the wire");
      }
    }
    /* W18: the provider stages ONLY the declared field -- every other byte of the block (the
       request size at 0x08, the mode word at 0x10 and the padding) must be the caller's */
    for (i = 0u; i < rec->blob_len; i++) {
      if (i >= (uint32_t)rec->ptr_field && i < (uint32_t)rec->ptr_field + 8u) continue;
      if (data[i] != rec->blob[i]) {
        sim_fail("the staged block changed a byte outside the declared pointer field");
      }
    }
  } else {
    uint32_t i;
    for (i = 0u; i < rec->blob_len; i++) {
      if (data[i] != rec->blob[i]) sim_fail("the argument block differs from the recorded one");
    }
  }
  want = out_len != NULL ? *out_len : 0u;
  if (out != NULL && out_len != NULL) {
    uint32_t n = rec->out_len < want ? rec->out_len : want;
    memcpy(out, rec->out, n);
    *out_len = n;
  }
  if (err_out != NULL) *err_out = rec->err;
  g_ioctl_index++;
  return (int)rec->rc;
}

static void sim_close(void *ctx, void *fd) {
  (void)ctx;
  (void)fd;
}

static uint8_t *sim_transfer(void *ctx, uint32_t len) {
  (void)ctx;
  if (len > (uint32_t)sizeof g_transfer) return NULL;
  return g_transfer;
}

const ps4rf_ioctl_ops *ps4rf_ioctl_target_ops(void) {
  if (!g_ops_ready) {
    g_ops.open = sim_open;
    g_ops.ioctl = sim_call;
    g_ops.close = sim_close;
    g_ops.transfer = sim_transfer;
    g_ops_ready = 1;
  }
  return &g_ops;
}

/* the rehearsal's own reporting hook: how many tape records were consumed */
uint32_t ps4rf_rehearsal_reads_used(void) { return g_read_index; }
uint32_t ps4rf_rehearsal_reads_total(void) { return g_read_count; }
uint32_t ps4rf_rehearsal_ioctls_used(void) { return g_ioctl_index; }
uint32_t ps4rf_rehearsal_ioctls_total(void) { return g_ioctl_count; }
