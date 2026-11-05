/* PS4RF W16 (option B) offline harness for the binding-window step.
 *
 * Links the *production* module (native/target/ps4rf_kread.c) and replaces only its leaf operations
 * and the two SDK entry points, exactly like tests/harness/kread_offline.c:
 *
 *   ps4rf_kread_k_readmsr -> returns the synthetic LSTAR (never executes a real rdmsr)
 *   ps4rf_kread_k_read8   -> serves the synthetic kernel image, counts every byte read
 *   kexec()               -> simulates the console syscall-11 dispatch and calls the payload
 *   get_kernel_base()     -> returns the synthetic kernel base
 *
 * Everything in between is the code that runs on the console: the row check against the compiled
 * table, the step's own one-shot re-arm and spend, the single ordered read, the copy-out record and
 * the monotonic lifetime cursor.
 *
 * What this proves, per window: the step reads the row the generated header published under that
 * slot (compiled indices 9..13 of the current table), offset 0, exactly 16 bytes, and reports those
 * bytes plus their sha256; a session re-arm between steps never resets the cursor (so no window can
 * be read twice); after the fifth window the set reports SET_COMPLETE and no further privileged
 * transition happens. The host re-derives the expected bytes independently from the registry
 * (tests/test_kread_identity_offline.py) -- the payload makes no match claim.
 *
 * Dispatch ABI: the console builds { void *syscall_handler; payload } and passes a pointer to that
 * wrapper; the caller's block sits in the SECOND field (offset 8). The harness reproduces exactly
 * that shape and points the first field at a harness-owned buffer -- the console's field 0 is
 * kernel memory, so a wrong-ABI callback would be writing into it.
 *
 * Output: one JSON object; exit 0 only when every check passed.
 * Build and run: tests/test_kread_identity_offline.py. Offline only: no network, no console, no rdmsr.
 */

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "ps4rf_kread.h"
#include "ps4rf_kread_regions.h"
#include "sha256.h"

#define SIM_KBASE 0xffffffff998f4000ull
#define SIM_LSTAR (SIM_KBASE + 0x1c0ull)
#define SIM_SIZE 0x700000u               /* covers every binding window rva + 16 */
#define WINDOW_COUNT PS4RF_KREAD_BINDING_WINDOW_COUNT
#define PROBLEM_MAX 16

static uint8_t g_sim[SIM_SIZE];
static uint64_t g_lstar = SIM_LSTAR;
static int g_kexec_calls;
static int g_dispatch_calls;
static int g_bytes_read;
static int g_problems;
static const char *g_problem_text[PROBLEM_MAX];

static uint8_t sim_byte(uint32_t rva) {
  return (uint8_t)((rva * 2654435761u) >> 24);
}

static void problem(const char *text) {
  if (g_problems < PROBLEM_MAX) g_problem_text[g_problems] = text;
  g_problems++;
}

/* ------------------------------------------------------------------ leaf replacements */

uint64_t ps4rf_kread_k_readmsr(uint32_t reg) {
  if (reg != 0xC0000082u) {
    problem("the step read an unexpected MSR");
    return 0ull;
  }
  return g_lstar;
}

uint8_t ps4rf_kread_k_read8(uint64_t base, uint32_t rva) {
  g_bytes_read++;
  if (base != SIM_KBASE || rva >= SIM_SIZE) {
    problem("read outside the simulated kernel");
    return 0u;
  }
  return g_sim[rva];
}

uint64_t get_kernel_base(void) { return SIM_KBASE; }

int kexec(void *func, void *user_arg) {
  struct kernel_abi {
    void *syscall_handler;
    ps4rf_kread_info *info;
  } wrapper;
  int (*entry)(void *, struct ps4rf_kread_args *);

  g_kexec_calls++;
  wrapper.syscall_handler = (void *)g_sim;      /* harness-owned: a wrong-ABI callback writes here */
  wrapper.info = (ps4rf_kread_info *)user_arg;
  entry = (int (*)(void *, struct ps4rf_kread_args *))func;
  g_dispatch_calls++;
  return entry(0, (struct ps4rf_kread_args *)&wrapper);
}

/* ------------------------------------------------------------------ the run */

static const uint32_t g_expected_index[WINDOW_COUNT] = {
#ifdef PS4RF_KREAD_IDENTITY_MUTANT_WRONG_SLOT
  /* COUNTER-PROOF BUILD (never used by the real suite): the first slot is declared to be row 0,
   * i.e. a different window than the generated header publishes. The run must FAIL, which is what
   * proves the slot check above is not vacuous -- the module reads what the table says, and the
   * harness compares it against what the table should say. */
  0u,
#else
  PS4RF_KREAD_BINDING_WINDOW_0,
#endif
  PS4RF_KREAD_BINDING_WINDOW_1, PS4RF_KREAD_BINDING_WINDOW_2,
  PS4RF_KREAD_BINDING_WINDOW_3, PS4RF_KREAD_BINDING_WINDOW_4,
};

static void hex_bytes(const uint8_t *data, uint32_t len, char *out) {
  static const char digits[] = "0123456789abcdef";
  uint32_t i;
  for (i = 0u; i < len; i++) {
    out[2u * i] = digits[(data[i] >> 4) & 0xfu];
    out[2u * i + 1u] = digits[data[i] & 0xfu];
  }
  out[2u * len] = '\0';
}

int main(void) {
  ps4rf_kread_info info;
  ps4rf_kread_identity_record rec;
  char hexbuf[2u * PS4RF_KREAD_IDENTITY_LEN + 1u];
  uint32_t slot;
  int status;
  int i;

  for (uint32_t b = 0u; b < SIM_SIZE; b++) g_sim[b] = sim_byte(b);

  printf("{\"suite\":\"w16_identity_offline\",\"window_count\":%u,\"windows\":[",
         (unsigned)WINDOW_COUNT);
  for (slot = 0u; slot < WINDOW_COUNT; slot++) {
    const ps4rf_kread_region *row;
    uint32_t rva;
    uint8_t sha[32];

    memset(&rec, 0, sizeof(rec));
    ps4rf_kread_session_begin(&info);            /* the agent's re-arm: must not reset the cursor */
    status = ps4rf_kread_identity_next(&info, &rec);

    if (status != PS4RF_KREAD_IDENTITY_OK) problem("a step did not report OK");
    if (rec.index != g_expected_index[slot]) problem("a step read a row other than its own slot");
    if (rec.copied_len != PS4RF_KREAD_IDENTITY_LEN) problem("a step did not copy exactly 16 bytes");
    if (rec.status != PS4RF_KREAD_IDENTITY_OK) problem("the record status is not OK");
    if (rec.sha256_status != PS4RF_KREAD_SHA_MEASURED) problem("the sha256 of the window was not measured");
    if (rec.index < PS4RF_KREAD_REGION_COUNT &&
        rec.resolved_rva != (uint64_t)PS4RF_KREAD_REGIONS[rec.index].rva) {
      problem("the resolved rva echo differs from the compiled row");
    }
    row = &PS4RF_KREAD_REGIONS[rec.index];
    rva = row->rva;
    for (uint32_t k = 0u; k < PS4RF_KREAD_IDENTITY_LEN; k++) {
      if (rec.bytes[k] != sim_byte(rva + k)) problem("a window byte differs from the image");
    }
    ps4rf_sha256(rec.bytes, (size_t)PS4RF_KREAD_IDENTITY_LEN, sha);
    for (uint32_t k = 0u; k < 32u; k++) {
      if (rec.sha256[k] != sha[k]) problem("the recorded sha256 is not the digest of the bytes");
    }
    hex_bytes(rec.bytes, PS4RF_KREAD_IDENTITY_LEN, hexbuf);
    printf("%s{\"slot\":%u,\"index\":%u,\"status_name\":\"%s\",\"copied_len\":%u,\"bytes_hex\":\"%s\"}",
           slot == 0u ? "" : ",", (unsigned)slot, (unsigned)rec.index,
           ps4rf_kread_identity_status_name(status), (unsigned)rec.copied_len, hexbuf);
  }
  printf("],");

  /* the exhausted set: the next call must report SET_COMPLETE and must not transition at all */
  {
    int before = g_kexec_calls;
    memset(&rec, 0, sizeof(rec));
    ps4rf_kread_session_begin(&info);
    status = ps4rf_kread_identity_next(&info, &rec);
    if (status != PS4RF_KREAD_IDENTITY_DONE) problem("the exhausted set did not report SET_COMPLETE");
    if (g_kexec_calls != before) problem("a privileged transition happened after the set was exhausted");
    printf("\"exhausted\":{\"status_name\":\"%s\",\"kexec_delta\":%d,\"kexec_calls\":%d},"
           "\"row_check_stays_out\":%s,"
           "\"cursor\":%u,\"kexec_calls\":%d,\"dispatch_calls\":%d,\"bytes_read\":%d,"
           "\"problems\":%d,\"problem_text\":[",
           ps4rf_kread_identity_status_name(status), g_kexec_calls - before, g_kexec_calls,
           g_kexec_calls == (int)WINDOW_COUNT ? "true" : "false",
           (unsigned)ps4rf_kread_identity_cursor(), g_kexec_calls, g_dispatch_calls, g_bytes_read,
           g_problems);
  }
  for (i = 0; i < (g_problems < PROBLEM_MAX ? g_problems : PROBLEM_MAX); i++) {
    printf("%s\"%s\"", i == 0 ? "" : ",", g_problem_text[i]);
  }
  printf("]}\n");
  return g_problems == 0 ? 0 : 1;
}
