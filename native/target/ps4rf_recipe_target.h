/* PS4RF W17 -- the recipe read seam (console user/kernel section split).

The bounded recipe provider (ps4rf_recipe.c) reads through an injected callback.
This file supplies that callback for a build that has a kernel:

  kernel section : ps4rf_recipe_kpayload  -- ONE leaf that copies `len` bytes from
                   the runtime VA it is handed into the payload's own transfer
                   block. It holds no MSR access, calls nothing and writes no
                   kernel memory; the VA arrives from the user section after the
                   recipe guard (canonical, aligned root, bounded length) admitted
                   it, and the leaf re-checks the range before the first byte.
  user section   : ps4rf_recipe_read_run -- one kexec transition per DECLARED
                   recipe cell (at most PS4RF_RECIPE_MAX_ENTRIES per request, no
                   retry: a failed transition fails that cell, it is never repeated)
                   plus ps4rf_recipe_target_kbase.

The host never supplies an address: the request names a recipe of the generated
table; every VA is composed from the table's RVA and the SDK kernel base, or from
a pointer value read out of kernel memory by a previous cell of the same recipe.
*/
#ifndef PS4RF_RECIPE_TARGET_H
#define PS4RF_RECIPE_TARGET_H

#include <stdint.h>

#include "ps4rf_recipe.h"

#define PS4RF_RECIPE_XFER_MAGIC_IN 0x52465231u              /* "1RFR" caller marker      */
#define PS4RF_RECIPE_XFER_MAGIC_OUT 0x52465232u             /* "2RFR" callback marker    */
#define PS4RF_RECIPE_XFER_GUARD 0x5053345246525231ull       /* "PS4RFR1" block end canary */

/* transfer block status (kernel section + user section verdicts) */
#define PS4RF_RECIPE_XFER_OK 0u
#define PS4RF_RECIPE_XFER_MAGIC 1u           /* block not authenticated: nothing written  */
#define PS4RF_RECIPE_XFER_LEN 2u             /* len 0 or above PS4RF_RECIPE_MAX_ENTRY_LEN */
#define PS4RF_RECIPE_XFER_ADDRESS 3u         /* VA not canonical / not in the kernel half */
#define PS4RF_RECIPE_XFER_KEXEC 4u           /* the privileged transition failed          */
#define PS4RF_RECIPE_XFER_RESULT 5u          /* callback marker / guard / count mismatch  */
#define PS4RF_RECIPE_XFER_KBASE 6u           /* the platform has no kernel base           */
#define PS4RF_RECIPE_XFER_BUDGET 7u          /* more transitions than the compile-time cap */

/* One bounded read. The user section fills everything up to `guard`; the kernel
 * leaf fills `copied`, `cb_status` and `bytes`, then sets the guard. */
typedef struct {
  uint32_t magic_in;
  uint32_t len;
  uint32_t cb_status;
  uint32_t copied;
  uint64_t va;
  uint64_t guard;
  uint8_t bytes[PS4RF_RECIPE_MAX_ENTRY_LEN];
} ps4rf_recipe_xfer;

/* the SDK hands the payload a wrapper whose second field is the caller's block */
typedef struct {
  void *syscall_handler;
  ps4rf_recipe_xfer *info;
} ps4rf_recipe_args;

typedef struct {
  uint64_t kbase;
  uint32_t transitions;
  uint32_t max_transitions;
} ps4rf_recipe_target_ctx;

/* kernel section (one entry point, leaf only) */
int ps4rf_recipe_kpayload(void *td, ps4rf_recipe_args *args);

/* the weak leaf the offline harness replaces to drive the production callback
 * against a synthetic image; a console artefact uses this definition */
__attribute__((weak, noinline)) uint8_t ps4rf_recipe_k_read8(uint64_t va);

/* user section */
uint64_t ps4rf_recipe_target_kbase(void);
void ps4rf_recipe_target_ctx_init(ps4rf_recipe_target_ctx *ctx);
/* The read callback the walk uses, obtained as a VALUE: in this build (-fPIC) taking the address
 * of a cross-file global routes it through the GOT, and a GOT entry is a dynamic relocation in an
 * artefact that has no dynamic loader. The callback itself stays file local. */
ps4rf_recipe_read_fn ps4rf_recipe_target_read_fn(void);
const char *ps4rf_recipe_xfer_status_name(uint32_t status);

#endif /* PS4RF_RECIPE_TARGET_H */
