/* ps4rf_recipe_target.c -- the recipe read seam for a build that has a kernel (W17).

Rules this file keeps (see ps4rf_recipe_target.h):

  * exactly ONE privileged entry point, ps4rf_recipe_kpayload, reached through the
    SDK's kexec() from ONE call site in the user section (ps4rf_recipe_target_read).
  * one transition per DECLARED recipe cell: the recipe table is compile-time data
    (generated), its count is bounded by PS4RF_RECIPE_MAX_ENTRIES, and the transfer
    context refuses more transitions than that bound. A failed transition fails the
    cell; it is NEVER retried.
  * no MSR access, no syscall, no wrmsr, no CR access, no indirect call and no
    allocation in the kernel section: the base comes from the platform, the VA from
    the recipe guard.
  * read-only: the leaf writes only into the payload's own transfer block.
*/
#include "ps4rf_recipe_target.h"

#include "ps4rf_libc.h"

/* The platform's two kernel entry points. On the console both come from libPS4
 * (kexec() makes the privileged transition, get_kernel_base() returns the
 * LSTAR-derived image base). A host build links honest stand-ins
 * (ps4rf_recipe_host.c) or the offline simulator (tests/harness/ps4rf_recipe_sim.c). */
extern int kexec(void *func, void *user_arg);
extern uint64_t get_kernel_base(void);

/* ------------------------------------------------------------------ kernel section */

/* The one leaf. Every check the user section already made is repeated here, because
 * the leaf is what runs with the kernel's privileges: canonical range, length bound,
 * no wraparound. It copies exactly `len` bytes into the payload's own block and
 * touches nothing else -- not even a status word of anything it does not own. */
int ps4rf_recipe_kpayload(void *td, ps4rf_recipe_args *args)
{
    ps4rf_recipe_xfer *x;
    uint32_t i;

    (void)td;
    if (args == 0) return -1;
    x = args->info;                     /* wrapper field 2: never field 1 */
    if (x == 0) return -1;
    if (x->magic_in != PS4RF_RECIPE_XFER_MAGIC_IN) return -1;   /* writes nothing */
    x->guard = 0ull;
    x->cb_status = PS4RF_RECIPE_XFER_OK;
    x->copied = 0u;

    if (x->len == 0u || x->len > PS4RF_RECIPE_MAX_ENTRY_LEN) {
        x->cb_status = PS4RF_RECIPE_XFER_LEN;
        return 0;
    }
    if (x->va < PS4RF_RECIPE_KVA_LO) {
        x->cb_status = PS4RF_RECIPE_XFER_ADDRESS;
        return 0;
    }
    if (x->va > (PS4RF_RECIPE_KVA_HI - (uint64_t)x->len)) {      /* checked, no wrap */
        x->cb_status = PS4RF_RECIPE_XFER_ADDRESS;
        return 0;
    }
    for (i = 0u; i < x->len; i++) {
        x->bytes[i] = ps4rf_recipe_k_read8(x->va + (uint64_t)i);
    }
    x->copied = x->len;
    x->guard = PS4RF_RECIPE_XFER_GUARD;
    return 0;
}

__attribute__((weak, noinline)) uint8_t ps4rf_recipe_k_read8(uint64_t va)
{
    return *(volatile uint8_t *)va;
}

/* -------------------------------------------------------------------- user section */

uint64_t ps4rf_recipe_target_kbase(void)
{
    return get_kernel_base();
}

void ps4rf_recipe_target_ctx_init(ps4rf_recipe_target_ctx *ctx)
{
    if (ctx == 0) return;
    ctx->kbase = 0ull;
    ctx->transitions = 0u;
    ctx->max_transitions = PS4RF_RECIPE_MAX_ENTRIES;
}

/* The injected read callback the provider walks with: ONE transition, bounded and
 * never retried. A refused or failed transition reports `len` bytes short, which the
 * provider turns into a refused cell carrying the status name. */
static ps4rf_recipe_xfer g_xfer;

static int ps4rf_recipe_read_run(void *vctx, uint64_t va, uint32_t len,
                       uint8_t *out, uint32_t *out_len)
{
    ps4rf_recipe_target_ctx *ctx = vctx;
    uint32_t i;
    int rc;

    if (out_len != 0) *out_len = 0u;
    if (out == 0 || out_len == 0) return -1;
    if (len == 0u || len > PS4RF_RECIPE_MAX_ENTRY_LEN) return -1;
    if (ctx != 0 && ctx->transitions >= ctx->max_transitions) return -1;

    g_xfer.magic_in = PS4RF_RECIPE_XFER_MAGIC_IN;
    g_xfer.len = len;
    g_xfer.cb_status = PS4RF_RECIPE_XFER_OK;
    g_xfer.copied = 0u;
    g_xfer.va = va;
    g_xfer.guard = 0ull;

    if (ctx != 0) ctx->transitions++;
    rc = kexec((void *)&ps4rf_recipe_kpayload, (void *)&g_xfer);
    if (rc != 0) return -1;                                    /* no retry, ever */
    if (g_xfer.guard != PS4RF_RECIPE_XFER_GUARD) return -1;      /* callback did not run */
    if (g_xfer.cb_status != PS4RF_RECIPE_XFER_OK) return -1;
    if (g_xfer.copied != len) return -1;
    for (i = 0u; i < len; i++) out[i] = g_xfer.bytes[i];
    *out_len = len;
    return 0;
}

ps4rf_recipe_read_fn ps4rf_recipe_target_read_fn(void)
{
    return ps4rf_recipe_read_run;
}

const char *ps4rf_recipe_xfer_status_name(uint32_t status)
{
    switch (status) {
      case PS4RF_RECIPE_XFER_OK: return "OK";
      case PS4RF_RECIPE_XFER_MAGIC: return "MAGIC";
      case PS4RF_RECIPE_XFER_LEN: return "LEN";
      case PS4RF_RECIPE_XFER_ADDRESS: return "ADDRESS";
      case PS4RF_RECIPE_XFER_KEXEC: return "KEXEC";
      case PS4RF_RECIPE_XFER_RESULT: return "RESULT";
      case PS4RF_RECIPE_XFER_KBASE: return "KBASE";
      case PS4RF_RECIPE_XFER_BUDGET: return "BUDGET";
      default: return "UNKNOWN";
    }
}
