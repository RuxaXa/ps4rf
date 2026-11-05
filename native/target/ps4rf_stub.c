/* PS4RF P4/W8 target agent -- stub provider implementation (see ps4rf_stub.h). */
#include "ps4rf_stub.h"

#include "ps4rf_platform.h"
#include "ps4rf_agent.h"

#ifndef PS4RF_TARGET_PS4
#include <stdlib.h>
#endif

#if defined(PS4RF_TARGET_KREAD)
#include "ps4rf_kread.h"
#endif

#if defined(PS4RF_TARGET_RECIPE)
#include "ps4rf_recipe.h"
#include "ps4rf_recipe_data.h"          /* the generated recipe table (names + entries) */
#include "ps4rf_recipe_target.h"        /* the read seam of this build                  */
#include "sha256.h"
#endif

#if defined(PS4RF_TARGET_IOCTL)
#include "ps4rf_ioctl.h"
#include "ps4rf_ioctl_policy_data.h"    /* the generated command policy                 */
/* the platform layer of this build: libPS4 on the console, the fail-closed host stand-in
 * otherwise, the recorded-trace rehearsal object in a dev-host rehearsal */
const ps4rf_ioctl_ops *ps4rf_ioctl_target_ops(void);
#endif

/* W14 §15: the only value the `capability` argument of `session.shutdown` may carry. It is a
 * constant of the wire contract, not a table lookup: the operation is capability-*free* (the frozen
 * registry binds no capability to it, and capability-bearing operations are never wired on the
 * target), so the value the caller declares is pinned here, in one place. */
#define PS4RF_SESSION_SHUTDOWN_CAPABILITY "session.admin"

/* W14 §5 test stand-in -- host builds only. It makes the stub provider take a fixed time per
 * operation so a test can close the transport *while* a request is being handled: only then is a
 * "pending request" a real thing to observe. Timing only -- no result, no state, no ordering
 * changes, and the console build cannot have it because there is no environment there. */
#ifndef PS4RF_TARGET_PS4
static void stub_host_delay(void)
{
    const char *ms = getenv("PS4RF_HOST_STUB_SLOW_MS");
    unsigned long v = 0ul;
    if (ms == NULL) return;
    while (*ms >= '0' && *ms <= '9') {
        v = v * 10ul + (unsigned long)(*ms - '0');
        if (v > 5000ul) return;             /* a stand-in, not a hang */
        ms++;
    }
    if (v == 0ul) return;
    ps4rf_platform_get()->sleep_us((unsigned)(v * 1000ul));
}
#endif
static int arg_int(const jval *args, const char *name, long long *out)
{
    const jval *v = jval_get(args, name);
    if (v == NULL || jval_kind(v) != JVAL_INT) return 0;
    *out = (long long)jval_int(v);
    return 1;
}

static const char *arg_str(const jval *args, const char *name)
{
    const jval *v = jval_get(args, name);
    if (v == NULL || jval_kind(v) != JVAL_STRING) return NULL;
    return jval_string(v, NULL);
}

static jval *held_refs_array(const ps4rf_rt *rt)
{
    jval *arr = jval_new_array();
    unsigned i;
    if (arr == NULL) return NULL;
    for (i = 0u; i < PS4RF_RES_MAX; i++) {
        const ps4rf_res_slot *slot = &rt->res.slots[i];
        if (slot->used) {
            if (jval_arr_add(arr, jval_new_string(slot->id)) != 0) {
                jval_free(arr);
                return NULL;
            }
        }
    }
    return arr;
}

static const char *res_error(unsigned st, const char **detail)
{
    switch (st) {
    case PS4RF_RES_LIMIT:
        *detail = "resource limit reached (held slots or allocation size)";
        return "RESOURCE_LIMIT";
    case PS4RF_RES_DESTROYED:
        *detail = "object was destroyed";
        return "RESOURCE_DESTROYED";
    case PS4RF_RES_STATE:
        *detail = "resource in wrong state for this operation";
        return "RESOURCE_STATE_INVALID";
    case PS4RF_RES_INVALID:
    default:
        *detail = "argument or resource reference is invalid";
        return "ARGUMENT_INVALID";
    }
}

static const char *op_ping(const jval *args, jval **result, const char **detail)
{
    long long seq;
    jval *obj = jval_new_object();
    (void)detail;
    if (obj == NULL) return "INTERNAL_ERROR";
    if (jval_obj_set(obj, "pong", jval_new_bool(1)) != 0) {
        jval_free(obj);
        return "INTERNAL_ERROR";
    }
    if (arg_int(args, "seq", &seq)) {
        if (jval_obj_set(obj, "seq", jval_new_int(seq)) != 0) {
            jval_free(obj);
            return "INTERNAL_ERROR";
        }
    }
    *result = obj;
    return NULL;
}

static const char *op_session_status(ps4rf_rt *rt, jval **result, const char **detail)
{
    jval *obj = jval_new_object();
    (void)detail;
    if (obj == NULL) return "INTERNAL_ERROR";
    if (jval_obj_set(obj, "session_state", jval_new_string(rt->state)) != 0 ||
        jval_obj_set(obj, "mutating_allowed", jval_new_bool(strcmp(rt->state, PS4RF_STATE_ACTIVE) == 0)) != 0 ||
        jval_obj_set(obj, "held_resources", held_refs_array(rt)) != 0 ||
        /* W15R3 (owner D5 fix): the lifetime's boot-binding outcome, as announced by the session
         * that was open when it was measured -- the measurement runs in this session's checkpoint,
         * after the dial, so this is where the result is readable. `boot_detail` names the
         * measurement's own failure status; the digest of boot_sec/boot_usec stays a host-side
         * derivation (W11 rule). */
        jval_obj_set(obj, "boot_status",
                     jval_new_string(rt->boot_status != NULL ? rt->boot_status : "UNRESOLVED")) != 0 ||
        jval_obj_set(obj, "boot_detail",
                     jval_new_string(rt->boot_detail != NULL ? rt->boot_detail : "")) != 0 ||
        jval_obj_set(obj, "boot_sec", jval_new_int((int64_t)rt->boot_sec)) != 0 ||
        jval_obj_set(obj, "boot_usec", jval_new_int((int64_t)rt->boot_usec)) != 0 ||
        /* Track A (W16 option B): this session's fixed window step. The payload read ONE window
         * itself -- first the binding fingerprints, then the observation windows -- and reports the
         * row index (a compile-time constant of the generated table), the bytes as lowercase hex and
         * its own sha256 of the copied range. An empty `window_kind` means this session read nothing
         * (the binding's own session, or the sets are spent): the host can tell "nothing read" from
         * "read" and never mistakes an observation for an identity. */
        jval_obj_set(obj, "window_kind",
                     jval_new_string(rt->window_kind != NULL ? rt->window_kind : "")) != 0 ||
        jval_obj_set(obj, "window_status",
                     jval_new_string(rt->window_status != NULL ? rt->window_status : "")) != 0 ||
        jval_obj_set(obj, "window_index", jval_new_int((int64_t)rt->window_index)) != 0 ||
        jval_obj_set(obj, "window_len", jval_new_int((int64_t)rt->window_len)) != 0 ||
        jval_obj_set(obj, "window_cursor", jval_new_int((int64_t)rt->window_cursor)) != 0 ||
        jval_obj_set(obj, "window_count", jval_new_int((int64_t)rt->window_count)) != 0 ||
        jval_obj_set(obj, "window_hex",
                     jval_new_string(rt->window_hex != NULL ? rt->window_hex : "")) != 0 ||
        jval_obj_set(obj, "window_sha256",
                     jval_new_string(rt->window_sha256 != NULL ? rt->window_sha256 : "")) != 0) {
        jval_free(obj);
        return "INTERNAL_ERROR";
    }
    *result = obj;
    return NULL;
}

static const char *op_telemetry_read(ps4rf_rt *rt, jval **result, const char **detail)
{
    jval *obj = jval_new_object();
    (void)detail;
    if (obj == NULL) return "INTERNAL_ERROR";
    if (jval_obj_set(obj, "session_state", jval_new_string(rt->state)) != 0 ||
        jval_obj_set(obj, "inflight", jval_new_int((int64_t)rt->inflight)) != 0 ||
        jval_obj_set(obj, "held_resources", held_refs_array(rt)) != 0) {
        jval_free(obj);
        return "INTERNAL_ERROR";
    }
    *result = obj;
    return NULL;
}

static const char *op_memory_alloc(ps4rf_rt *rt, const jval *args, jval **result, const char **detail)
{
    long long size = 0;
    long long align = 0;
    char ref[PS4RF_REF_LEN];
    jval *obj;
    ps4rf_res_status st;

    if (!arg_int(args, "size", &size)) { *detail = "size is required"; return "ARGUMENT_INVALID"; }
    if (size < 1) { *detail = "size must be >= 1"; return "ARGUMENT_INVALID"; }
    if (size > (long long)PS4RF_STUB_MAX_ALLOC) { *detail = "size above the target allocation limit"; return "RESOURCE_LIMIT"; }
    if (arg_int(args, "alignment", &align) && (align < 1 || (align & (align - 1)) != 0)) {
        *detail = "alignment must be a power of two";
        return "ARGUMENT_INVALID";
    }
    if (ps4rf_res_live(&rt->res) >= PS4RF_STUB_MAX_HELD) {
        *detail = "too many held resources";
        return "RESOURCE_LIMIT";
    }
    st = ps4rf_res_alloc(&rt->res, (size_t)size, align > 0 ? (size_t)align : 8u, ref);
    if (st != PS4RF_RES_OK) return res_error(st, detail);
    obj = jval_new_object();
    if (obj == NULL || jval_obj_set(obj, "ref", jval_new_string(ref)) != 0) {
        jval_free(obj);
        return "INTERNAL_ERROR";
    }
    *result = obj;
    return NULL;
}

static const char *op_memory_free(ps4rf_rt *rt, const jval *args, jval **result, const char **detail)
{
    const char *ref = arg_str(args, "ref");
    char freed[PS4RF_REF_LEN];
    jval *obj;
    ps4rf_res_status st;
    if (ref == NULL) { *detail = "ref is required"; return "ARGUMENT_INVALID"; }
    st = ps4rf_res_free(&rt->res, ref, freed);
    if (st != PS4RF_RES_OK) return res_error(st, detail);
    obj = jval_new_object();
    if (obj == NULL || jval_obj_set(obj, "freed", jval_new_string(freed)) != 0) {
        jval_free(obj);
        return "INTERNAL_ERROR";
    }
    *result = obj;
    return NULL;
}

static const char *op_create(ps4rf_rt *rt, const jval *args, int barrier, jval **result, const char **detail)
{
    long long parties = 0;
    char ref[PS4RF_REF_LEN];
    jval *obj;
    ps4rf_res_status st;

    if (!arg_int(args, "parties", &parties)) { *detail = "parties is required"; return "ARGUMENT_INVALID"; }
    if (parties < 1) { *detail = "parties must be >= 1"; return "ARGUMENT_INVALID"; }
    if (ps4rf_res_live(&rt->res) >= PS4RF_STUB_MAX_HELD) { *detail = "too many held resources"; return "RESOURCE_LIMIT"; }
    st = ps4rf_res_create(&rt->res, (unsigned)parties, barrier, ref);
    if (st != PS4RF_RES_OK) return res_error(st, detail);
    obj = jval_new_object();
    if (obj == NULL || jval_obj_set(obj, barrier ? "barrier" : "gate", jval_new_string(ref)) != 0) {
        jval_free(obj);
        return "INTERNAL_ERROR";
    }
    *result = obj;
    return NULL;
}

static const char *op_arrive(ps4rf_rt *rt, const jval *args, jval **result, const char **detail)
{
    const char *ref = arg_str(args, "gate");
    unsigned participants = 0u;
    ps4rf_res_status st;
    jval *obj;
    if (ref == NULL) { *detail = "gate is required"; return "ARGUMENT_INVALID"; }
    st = ps4rf_res_arrive(&rt->res, ref, &participants);
    if (st != PS4RF_RES_OK) return res_error(st, detail);
    obj = jval_new_object();
    if (obj == NULL || jval_obj_set(obj, "registered", jval_new_bool(1)) != 0 ||
        jval_obj_set(obj, "participants", jval_new_int((int64_t)participants)) != 0) {
        jval_free(obj);
        return "INTERNAL_ERROR";
    }
    *result = obj;
    return NULL;
}

static const char *wait_result(ps4rf_rt *rt, const char *ref, const jval *args,
                               int arrive_first, jval **result, const char **detail)
{
    long long timeout = (long long)PS4RF_STUB_DEFAULT_WAIT_MS;
    int released = 0;
    ps4rf_res_status st;
    jval *obj;

    if (ref == NULL) { *detail = "gate/barrier is required"; return "ARGUMENT_INVALID"; }
    if (arg_int(args, "timeout_ms", &timeout)) {
        if (timeout < 0) { *detail = "timeout_ms must not be negative"; return "ARGUMENT_INVALID"; }
    }
    if (arrive_first) {
        unsigned participants = 0u;
        st = ps4rf_res_arrive(&rt->res, ref, &participants);
        if (st != PS4RF_RES_OK) return res_error(st, detail);
    }
    st = ps4rf_res_wait(&rt->res, ref, (unsigned)timeout, &released);
    if (st != PS4RF_RES_OK) return res_error(st, detail);
    obj = jval_new_object();
    if (obj == NULL || jval_obj_set(obj, "released", jval_new_bool(released ? 1 : 0)) != 0) {
        jval_free(obj);
        return "INTERNAL_ERROR";
    }
    *result = obj;
    return NULL;
}

static const char *op_gate_status(ps4rf_rt *rt, const jval *args, jval **result, const char **detail)
{
    const char *ref = arg_str(args, "gate");
    unsigned participants = 0u;
    int released = 0, destroyed = 0;
    ps4rf_res_status st;
    jval *obj;
    if (ref == NULL) { *detail = "gate is required"; return "ARGUMENT_INVALID"; }
    st = ps4rf_res_status_of(&rt->res, ref, &participants, &released, &destroyed);
    if (st != PS4RF_RES_OK) return res_error(st, detail);
    obj = jval_new_object();
    if (obj == NULL || jval_obj_set(obj, "participants", jval_new_int((int64_t)participants)) != 0 ||
        jval_obj_set(obj, "released", jval_new_bool(released ? 1 : 0)) != 0 ||
        jval_obj_set(obj, "destroyed", jval_new_bool(destroyed ? 1 : 0)) != 0) {
        jval_free(obj);
        return "INTERNAL_ERROR";
    }
    *result = obj;
    return NULL;
}

static const char *op_release(ps4rf_rt *rt, const jval *args, const char *arg_name,
                              jval **result, const char **detail)
{
    const char *ref = arg_str(args, arg_name);
    int released = 0;
    ps4rf_res_status st;
    jval *obj;
    if (ref == NULL) { *detail = "gate/barrier is required"; return "ARGUMENT_INVALID"; }
    st = ps4rf_res_release(&rt->res, ref, &released);
    if (st != PS4RF_RES_OK) return res_error(st, detail);
    obj = jval_new_object();
    if (obj == NULL || jval_obj_set(obj, "released", jval_new_bool(released ? 1 : 0)) != 0) {
        jval_free(obj);
        return "INTERNAL_ERROR";
    }
    *result = obj;
    return NULL;
}

static const char *op_destroy(ps4rf_rt *rt, const jval *args, const char *arg_name,
                              jval **result, const char **detail)
{
    const char *ref = arg_str(args, arg_name);
    int destroyed = 0;
    ps4rf_res_status st;
    jval *obj;
    if (ref == NULL) { *detail = "gate/barrier is required"; return "ARGUMENT_INVALID"; }
    st = ps4rf_res_destroy(&rt->res, ref, &destroyed);
    if (st != PS4RF_RES_OK) return res_error(st, detail);
    obj = jval_new_object();
    if (obj == NULL || jval_obj_set(obj, "destroyed", jval_new_bool(destroyed ? 1 : 0)) != 0) {
        jval_free(obj);
        return "INTERNAL_ERROR";
    }
    *result = obj;
    return NULL;
}

#ifdef PS4RF_TARGET_KREAD
/* W14 (resident ps4rfd): the bounded kernel.read provider. This is the ONLY productive read
 * path: the request arrives as an authenticated RPC, the router validates its arguments against
 * the generated catalog and enters exactly one provider handler here. The session loop of the
 * agent holds no read state, no parse and no call site (the build gate proves that), and this
 * provider is the only caller of ps4rf_kread_run() in the whole target tree.
 *
 * The request carries three integers -- region_index, offset, length -- and nothing else. No
 * address, no rva, no pointer and no size of any address space is read from the request: the
 * region comes from the compile-time table, the address is composed inside the single kernel
 * callback as kbase + region RVA + offset, and the length is capped at PS4RF_KREAD_MAX_LEN.
 * The one shot is per session: ps4rf_stub_session_begin() re-arms it exactly once per session,
 * never from a request, so a session performs at most one privileged transition. */
static ps4rf_kread_info g_kread;

void ps4rf_stub_session_begin(void)
{
    ps4rf_kread_session_begin(&g_kread);
}

static const char *op_kernel_read(ps4rf_rt *rt, const jval *args, jval **result,
                                  const char **detail)
{
    long long index = -1, offset = -1, length = -1;
    int run_status;
    jval *record;
    const jval *hex;

    if (!arg_int(args, "region_index", &index) || !arg_int(args, "offset", &offset) ||
        !arg_int(args, "length", &length) || index < 0 || offset < 0 || length < 0 ||
        index > 0xFFFFFFFFll || offset > 0xFFFFFFFFll || length > 0xFFFFFFFFll) {
        *detail = "kernel.read: the three bounded integers could not be read in full";
        return "ARGUMENT_INVALID";
    }

    /* W15R3 (owner D5 fix): the privileged gate. The lifetime's boot binding is measured once,
     * inside the first session that is already handshaken (daemon_boot_measure) -- a lifetime that
     * could not measure it (unresolved, kexec error, callback error, malformed result) keeps its
     * control plane but has no privileged read: the request is refused here, before the module is
     * entered, before any kexec and before any event is built. Only a build that carries the boot
     * binding enforces this (the bare provider builds have no binding to check). */
#ifdef PS4RF_TARGET_BOOTBIND
    if (!ps4rf_kread_boot_established()) {
        ps4rf_trace_marker("B10 research refused boot binding unresolved");
        *detail = "kernel.read: the lifetime has no established boot binding (the measurement ran "
                  "once per lifetime, inside the first session; a lifetime that could not measure "
                  "it refuses the privileged read)";
        return "BOOT_BINDING_UNRESOLVED";
    }
    ps4rf_trace_marker("B10 research ready");
#endif

    run_status = ps4rf_kread_run(&g_kread, (uint32_t)index, (uint32_t)offset, (uint32_t)length);
    record = ps4rf_kread_event(&g_kread, run_status, rt->build_id, rt->context);
    if (record == NULL) {
        *detail = "kernel.read: the read record could not be built";
        return "INTERNAL_ERROR";
    }
    /* The declared result field is the measured byte string; the verdict of the run lives in the
     * same record (status / run_status_name / callback_executed). A reader must check the verdict
     * and must not treat the presence of a result as a successful read. */
    hex = jval_get(record, "bytes_hex");
    if (hex == NULL || jval_obj_set(record, "data",
                                    jval_new_string(jval_string(hex, NULL))) != 0) {
        jval_free(record);
        *detail = "kernel.read: the declared result field could not be set";
        return "INTERNAL_ERROR";
    }
    *detail = ps4rf_kread_run_status_name(run_status);
    *result = record;
    return NULL;
}
#else
void ps4rf_stub_session_begin(void)
{
    /* no privileged provider in this build: nothing to re-arm (a kernel.read request falls
     * through to the deferred default below, exactly as before W14) */
}
#endif /* PS4RF_TARGET_KREAD */

/* W17F -- the two generic research primitives, wired to their providers.

 * kernel.snapshot.recipe -> ps4rf_recipe_run()
 * ioctl.invoke           -> ps4rf_ioctl_invoke()
 *
 * Both handlers are experiment-free: they know the generated tables (recipes, command policy)
 * and the two providers, and nothing about a specific window, marker, device layout or
 * experiment. There is no address in either request and no way to reach a raw kernel call: the
 * recipe names a compile-time entry list and the ioctl names an allowlisted command, and the
 * only pointer the device ever sees is the provider's own transfer buffer.
 */

#if defined(PS4RF_TARGET_RECIPE)
/* One block for all cells: at most PS4RF_RECIPE_MAX_ENTRIES entries of at most
 * PS4RF_RECIPE_MAX_ENTRY_LEN bytes each. Compile-time sized, never allocated per request. */
#define PS4RF_RECIPE_BLOCK_BYTES (PS4RF_RECIPE_MAX_ENTRIES * PS4RF_RECIPE_MAX_ENTRY_LEN)
/* the positional index slots the recipe vocabulary declares (bitmap word, PT slot) */
#define PS4RF_RECIPE_INDEX_SLOTS 2u

static uint8_t g_recipe_block[PS4RF_RECIPE_BLOCK_BYTES];
static ps4rf_recipe_target_ctx g_recipe_ctx;
static ps4rf_recipe_result g_recipe_result;
/* one reusable hex buffer: jval_new_string copies what it is given, so a single buffer serves
 * every cell without a per-request allocation (the largest cell is 4096 bytes) */
static char g_recipe_hex[2u * PS4RF_RECIPE_MAX_ENTRY_LEN + 1u];

static void hex_lower(char *dst, const uint8_t *src, uint32_t n)
{
    static const char digits[] = "0123456789abcdef";
    uint32_t i;
    for (i = 0u; i < n; i++) {
        dst[2u * i] = digits[(src[i] >> 4) & 0x0fu];
        dst[2u * i + 1u] = digits[src[i] & 0x0fu];
    }
    dst[2u * n] = '\0';
}

static const ps4rf_recipe_index *recipe_lookup(const char *name)
{
    uint32_t i;
    if (name == NULL) return NULL;
    for (i = 0u; i < (uint32_t)PS4RF_RECIPE_TABLE_COUNT; i++) {
        const ps4rf_recipe_index *r = &PS4RF_RECIPE_INDEX_TABLE[i];
        if (strcmp(r->name, name) == 0) return r;
    }
    return NULL;
}

static const char *op_kernel_snapshot_recipe(ps4rf_rt *rt, const jval *args, jval **result_out,
                                            const char **detail_out)
{
    const char *ref = arg_str(args, "recipe_ref");
    const ps4rf_recipe_index *recipe;
    const ps4rf_recipe_entry *entries;
    uint32_t entry_count;
    const jval *arr;
    uint32_t indices[PS4RF_RECIPE_INDEX_SLOTS];
    uint32_t index_count = 0u;
    uint64_t kbase;
    jval *cells;
    uint32_t i;
    int rc;
    uint8_t digest[32];
    char sha_hex[65];
    (void)rt;

    if (ref == NULL) {
        *detail_out = "kernel.snapshot.recipe: recipe_ref must be a string";
        return "ARGUMENT_INVALID";
    }
    recipe = recipe_lookup(ref);
    if (recipe == NULL) {
        /* the admissible names are the generated table, never an address and never a free form
         * selector: an unknown reference reads nothing (no transition is made) */
        *detail_out = "kernel.snapshot.recipe: recipe_ref names no recipe of the generated table";
        return "ARGUMENT_INVALID";
    }
    entries = &PS4RF_RECIPE_ENTRIES[recipe->first];
    entry_count = recipe->count;
    arr = jval_get(args, "indices");
    if (arr != NULL) {
        if (jval_kind(arr) != JVAL_ARRAY) {
            *detail_out = "kernel.snapshot.recipe: indices must be an array of bounded integers";
            return "ARGUMENT_INVALID";
        }
        if (jval_count(arr) > (size_t)PS4RF_RECIPE_INDEX_SLOTS) {
            *detail_out = "kernel.snapshot.recipe: too many indices for the declared index slots";
            return "ARGUMENT_INVALID";
        }
        for (i = 0u; i < (uint32_t)jval_count(arr); i++) {
            const jval *e = jval_at(arr, (size_t)i);
            int64_t v;
            if (e == NULL || jval_kind(e) != JVAL_INT) {
                *detail_out = "kernel.snapshot.recipe: every index must be an integer";
                return "ARGUMENT_INVALID";
            }
            v = jval_int(e);
            if (v < 0 || v > (int64_t)PS4RF_RECIPE_MAX_INDEX) {
                *detail_out = "kernel.snapshot.recipe: an index is outside the declared bound";
                return "ARGUMENT_INVALID";
            }
            indices[index_count++] = (uint32_t)v;
        }
    }
    if (ps4rf_recipe_validate(entries, entry_count) != 0) {
        *detail_out = "kernel.snapshot.recipe: the generated recipe table does not validate "
                      "(build fault, nothing was read)";
        return "INTERNAL_ERROR";
    }
    /* W15R3 parity with the bounded read: a lifetime without an established boot binding serves
     * no privileged read. Only a build that carries the binding enforces it. */
#ifdef PS4RF_TARGET_BOOTBIND
    if (!ps4rf_kread_boot_established()) {
        ps4rf_trace_marker("B10 research refused boot binding unresolved");
        *detail_out = "kernel.snapshot.recipe: the lifetime has no established boot binding "
                      "(the measurement ran once per lifetime, inside the first session)";
        return "BOOT_BINDING_UNRESOLVED";
    }
#endif
    kbase = ps4rf_recipe_target_kbase();
    if (kbase == 0ull) {
        ps4rf_trace_marker("B10 research refused no kernel base");
        *detail_out = "kernel.snapshot.recipe: the platform reported no kernel base; "
                      "nothing was read";
        return "INTERNAL_ERROR";
    }
    ps4rf_recipe_target_ctx_init(&g_recipe_ctx);
    g_recipe_ctx.kbase = kbase;
    rc = ps4rf_recipe_run(entries, entry_count, kbase, indices, index_count, g_recipe_block,
                          (uint32_t)sizeof g_recipe_block, ps4rf_recipe_target_read_fn(),
                          &g_recipe_ctx, &g_recipe_result);
    if (rc != 0) {
        *detail_out = "kernel.snapshot.recipe: the run was refused before the first entry";
        return "INTERNAL_ERROR";
    }
    cells = jval_new_array();
    if (cells == NULL) {
        *detail_out = "kernel.snapshot.recipe: the cell list could not be built";
        return "INTERNAL_ERROR";
    }
    for (i = 0u; i < g_recipe_result.entries && i < (uint32_t)PS4RF_RECIPE_MAX_ENTRIES; i++) {
        const ps4rf_recipe_cell *c = &g_recipe_result.cells[i];
        const ps4rf_recipe_entry *e = &entries[i];
        jval *cell = jval_new_object();
        char *hex = g_recipe_hex;
        uint32_t len = c->status == PS4RF_RECIPE_OK ? c->length : 0u;
        if (cell == NULL) { jval_free(cells); *detail_out = "kernel.snapshot.recipe: cell alloc"; return "INTERNAL_ERROR"; }
        if (len != 0u) hex_lower(hex, c->data, len);
        if (jval_obj_set(cell, "name", jval_new_string(e->name)) != 0 ||
            jval_obj_set(cell, "status", jval_new_int((int64_t)c->status)) != 0 ||
            jval_obj_set(cell, "status_name",
                         jval_new_string(ps4rf_recipe_status_name(c->status))) != 0 ||
            jval_obj_set(cell, "why", jval_new_int((int64_t)c->why)) != 0 ||
            jval_obj_set(cell, "why_name", jval_new_string(ps4rf_recipe_why_name(c->why))) != 0 ||
            jval_obj_set(cell, "length", jval_new_int((int64_t)len)) != 0 ||
            jval_obj_set(cell, "addr", jval_new_int((int64_t)c->addr)) != 0 ||
            jval_obj_set(cell, "root_value", jval_new_int((int64_t)c->root_value)) != 0 ||
            jval_obj_set(cell, "attach",
                         jval_new_int((e->type == PS4RF_RECIPE_TYPE_FOLLOW_ONCE &&
                                       (e->flags & PS4RF_RECIPE_FLAG_ATTACH_GATE) &&
                                       c->status == PS4RF_RECIPE_OK) ? 1 : 0)) != 0 ||
            jval_obj_set(cell, "data", jval_new_string(len != 0u ? hex : "")) != 0) {
            jval_free(cell);
            jval_free(cells);
            *detail_out = "kernel.snapshot.recipe: the cell record could not be set";
            return "INTERNAL_ERROR";
        }
        if (jval_arr_add(cells, cell) != 0) {
            jval_free(cells);
            *detail_out = "kernel.snapshot.recipe: the cell list could not be extended";
            return "INTERNAL_ERROR";
        }
    }
    /* the digest covers exactly the payload the cells carry, in cell order: the host can
     * recompute it from the response alone */
    ps4rf_sha256(g_recipe_block, (size_t)g_recipe_result.total_bytes, digest);
    hex_lower(sha_hex, digest, 32u);
    *result_out = jval_new_object();
    if (*result_out == NULL ||
        jval_obj_set(*result_out, "cells", cells) != 0 ||
        jval_obj_set(*result_out, "sha256", jval_new_string(sha_hex)) != 0) {
        jval_free(cells);
        *result_out = NULL;
        *detail_out = "kernel.snapshot.recipe: the result could not be assembled";
        return "INTERNAL_ERROR";
    }
    *detail_out = "recipe served";
    return NULL;
}
#endif /* PS4RF_TARGET_RECIPE */

#if defined(PS4RF_TARGET_IOCTL)
static uint8_t g_ioctl_blob[PS4RF_IOCTL_MAX_BLOB];
static uint8_t g_ioctl_data[PS4RF_IOCTL_MAX_DATA];
static ps4rf_ioctl_result g_ioctl_result;
/* one reusable hex buffer (jval_new_string copies): the largest response the policy admits */
static char g_ioctl_hex[2u * PS4RF_IOCTL_MAX_OUT + 1u];

static int hex_nib(int c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

static int hex_decode(const char *text, uint8_t *out, uint32_t cap, uint32_t *len_out)
{
    size_t n, i;
    *len_out = 0u;
    if (text == NULL) return 0;
    n = strlen(text);
    if ((n % 2u) != 0u || n / 2u > (size_t)cap) return -1;
    for (i = 0u; i < n; i += 2u) {
        int hi = hex_nib((unsigned char)text[i]);
        int lo = hex_nib((unsigned char)text[i + 1u]);
        if (hi < 0 || lo < 0) return -1;
        out[i / 2u] = (uint8_t)((hi << 4) | lo);
    }
    *len_out = (uint32_t)(n / 2u);
    return 0;
}

static const char *op_ioctl_invoke(ps4rf_rt *rt, const jval *args, jval **result_out,
                                   const char **detail_out)
{
    long long command = -1, mode = -1;
    const char *blob_text = arg_str(args, "blob");
    const char *data_text = arg_str(args, "data");
    const jval *mode_val = jval_get(args, "mode");
    uint32_t blob_len = 0u, data_len = 0u;
    const ps4rf_ioctl_rule *rule = NULL;
    const ps4rf_ioctl_ops *ops = ps4rf_ioctl_target_ops();
    uint8_t *staged;
    int patched = 0;
    uint32_t mode_present = 0u, mode_word = 0u;
    char *out_hex;
    (void)rt;

    if (!arg_int(args, "command", &command) || command < 0 || command > 0xFFFFFFFFll) {
        *detail_out = "ioctl.invoke: command must be a 32 bit unsigned integer";
        return "ARGUMENT_INVALID";
    }
    if (blob_text == NULL) {
        *detail_out = "ioctl.invoke: the argument block (blob) must be a hex string";
        return "ARGUMENT_INVALID";
    }
    if (hex_decode(blob_text, g_ioctl_blob, (uint32_t)PS4RF_IOCTL_MAX_BLOB, &blob_len) != 0) {
        *detail_out = "ioctl.invoke: the argument block is not valid hex of a size the policy admits";
        return "ARGUMENT_INVALID";
    }
    if (mode_val != NULL) {
        if (jval_kind(mode_val) != JVAL_INT) {
            *detail_out = "ioctl.invoke: mode must be an integer when present";
            return "ARGUMENT_INVALID";
        }
        mode = jval_int(mode_val);
        if (mode < 0 || mode > 0xFFFFFFFFll) {
            *detail_out = "ioctl.invoke: mode is outside the 32 bit range";
            return "ARGUMENT_INVALID";
        }
        mode_present = 1u;
        mode_word = (uint32_t)mode;
    }
    if (ps4rf_ioctl_policy_check(&PS4RF_IOCTL_POLICY, PS4RF_IOCTL_POLICY.device,
                                 (uint32_t)command, blob_len,
                                 mode_present ? &mode_word : NULL, &rule) !=
        (int)PS4RF_IOCTL_OK) {
        *detail_out = "ioctl.invoke: the command policy refuses this device/command/block/mode "
                      "combination (the allowlist is compile-time)";
        return "ARGUMENT_INVALID";
    }
    if (ops == NULL) {
        *detail_out = "ioctl.invoke: this build has no ioctl platform layer";
        return "INTERNAL_ERROR";
    }
    if (data_text != NULL && rule->ptr_field == PS4RF_IOCTL_NO_PTR_FIELD) {
        *detail_out = "ioctl.invoke: this command declares no pointer field, so a write payload "
                      "has nowhere to go";
        return "ARGUMENT_INVALID";
    }
    if (rule->ptr_field != PS4RF_IOCTL_NO_PTR_FIELD) {
        if (data_text != NULL &&
            hex_decode(data_text, g_ioctl_data, (uint32_t)PS4RF_IOCTL_MAX_DATA, &data_len) != 0) {
            *detail_out = "ioctl.invoke: the write payload is not valid hex of a bounded size";
            return "ARGUMENT_INVALID";
        }
        /* the provider's own buffer, its own address, the request's bytes: the caller never
         * names an address and the field in the request block is always overwritten */
        staged = ps4rf_ioctl_stage(NULL, ops, rule, g_ioctl_blob, blob_len,
                                   data_len != 0u ? g_ioctl_data : NULL, data_len, &patched);
        if (staged == NULL) {
            *detail_out = "ioctl.invoke: no transfer buffer is available for this command";
            return "INTERNAL_ERROR";
        }
        blob_text = NULL;   /* the staged block replaces the request block below */
    } else {
        staged = g_ioctl_blob;
    }
    if (ps4rf_ioctl_invoke(NULL, &PS4RF_IOCTL_POLICY, ops, PS4RF_IOCTL_POLICY.device,
                           (uint32_t)command, staged, blob_len,
                           mode_present ? &mode_word : NULL, &g_ioctl_result) != 0) {
        *detail_out = "ioctl.invoke: the provider could not be entered";
        return "INTERNAL_ERROR";
    }
    if (g_ioctl_result.verdict == PS4RF_IOCTL_REFUSED_OPEN) {
        *detail_out = "ioctl.invoke: the device could not be opened (no call was made)";
        return "INTERNAL_ERROR";
    }
    /* exactly one open / ioctl / close happened above; the rc and the errno are the device's
     * answer, and the verdict is recorded in the detail so a reader can tell a refusal from a
     * performed call */
    out_hex = g_ioctl_hex;
    hex_lower(out_hex, g_ioctl_result.out, g_ioctl_result.out_len);
    *result_out = jval_new_object();
    if (*result_out == NULL ||
        jval_obj_set(*result_out, "rc", jval_new_int((int64_t)g_ioctl_result.rc)) != 0 ||
        jval_obj_set(*result_out, "errno", jval_new_int((int64_t)g_ioctl_result.err)) != 0 ||
        jval_obj_set(*result_out, "output", jval_new_string(out_hex)) != 0) {
        *result_out = NULL;
        *detail_out = "ioctl.invoke: the result could not be assembled";
        return "INTERNAL_ERROR";
    }
    *detail_out = ps4rf_ioctl_verdict_name(g_ioctl_result.verdict);
    return NULL;
}
#endif /* PS4RF_TARGET_IOCTL */

/* W14 §15 -- the authenticated admin shutdown.
 *
 * Authentication is the session: only a request inside an AEAD-authenticated session reaches this
 * point, and the operation is never served on a bare connection (a connection that does not
 * complete the frozen handshake never becomes a request). Authorization is the catalogue: the
 * request must name the capability this operation is bound to (`row->capability`), and `session.admin`
 * is the only value the wire contract admits.
 *
 * The handler *requests* the end, it does not perform one: it sets a flag, the session loop ends the
 * session with the ADMIN_SHUTDOWN bye and the daemon ends the lifetime. That keeps one exit path.
 * It changes no kernel state, triggers no reboot, reaches no loader and installs no persistence --
 * the only thing it touches is the resident agent's own lifetime.
 *
 * Recovery: the catalogue marks the operation recovery_safe, so a boot in recovery serves it. That is
 * the policy: a controller that has to stop an agent whose boot is in recovery must be able to. */
static const char *op_session_shutdown(ps4rf_rt *rt, const ps4rf_op_row *row, const jval *args,
                                       jval **result_out, const char **detail_out)
{
    const jval *claim = jval_get(args, "capability");
    const char *value = (claim != NULL && jval_kind(claim) == JVAL_STRING)
                            ? jval_string(claim, NULL) : NULL;
    jval *obj;
    (void)detail_out;

    if (!ps4rf_agent_is_resident()) {
        *detail_out = "not served outside the resident mode";
        return "OPERATION_DEFERRED";
    }
    if (rt->state == NULL || strcmp(rt->state, PS4RF_STATE_CLOSED) == 0) {
        *detail_out = "the session is not live";
        return "OPERATION_DEFERRED";
    }
    if (value == NULL || strcmp(value, PS4RF_SESSION_SHUTDOWN_CAPABILITY) != 0) {
        *detail_out = "session.admin is required";
        return "CAPABILITY_REQUIRED";
    }
    obj = jval_new_object();
    if (obj == NULL || jval_obj_set(obj, "status", jval_new_string("ACCEPTED")) != 0) {
        if (obj != NULL) jval_free(obj);
        *detail_out = "internal error";
        return "INTERNAL_ERROR";
    }
    rt->admin_shutdown = 1;
    *result_out = obj;
    return NULL;
}

const char *ps4rf_stub_invoke(ps4rf_rt *rt, const ps4rf_op_row *row, const jval *args,
                              jval **result_out, const char **detail_out)
{
    const char *name = row->name;
    *result_out = NULL;
    *detail_out = "internal error";

#ifndef PS4RF_TARGET_PS4
    stub_host_delay();                       /* §5 test stand-in (host builds only) */
#endif

#if defined(PS4RF_TARGET_KREAD)
    if (strcmp(name, "kernel.read") == 0) return op_kernel_read(rt, args, result_out, detail_out);
#endif
#if defined(PS4RF_TARGET_RECIPE)
    if (strcmp(name, "kernel.snapshot.recipe") == 0) {
        return op_kernel_snapshot_recipe(rt, args, result_out, detail_out);
    }
#endif
#if defined(PS4RF_TARGET_IOCTL)
    if (strcmp(name, "ioctl.invoke") == 0) return op_ioctl_invoke(rt, args, result_out, detail_out);
#endif
    if (strcmp(name, "session.ping") == 0) return op_ping(args, result_out, detail_out);
    if (strcmp(name, "session.shutdown") == 0) {
        return op_session_shutdown(rt, row, args, result_out, detail_out);
    }
    if (strcmp(name, "session.status") == 0) return op_session_status(rt, result_out, detail_out);
    if (strcmp(name, "telemetry.read") == 0) return op_telemetry_read(rt, result_out, detail_out);
    if (strcmp(name, "memory.alloc") == 0) return op_memory_alloc(rt, args, result_out, detail_out);
    if (strcmp(name, "memory.free") == 0) return op_memory_free(rt, args, result_out, detail_out);
    if (strcmp(name, "sync.gate.create") == 0) return op_create(rt, args, 0, result_out, detail_out);
    if (strcmp(name, "sync.barrier.create") == 0) return op_create(rt, args, 1, result_out, detail_out);
    if (strcmp(name, "sync.gate.arrive") == 0) return op_arrive(rt, args, result_out, detail_out);
    if (strcmp(name, "sync.gate.wait") == 0)
        return wait_result(rt, arg_str(args, "gate"), args, 0, result_out, detail_out);
    if (strcmp(name, "sync.barrier.wait") == 0)
        return wait_result(rt, arg_str(args, "barrier"), args, 1, result_out, detail_out);
    if (strcmp(name, "sync.gate.status") == 0) return op_gate_status(rt, args, result_out, detail_out);
    if (strcmp(name, "sync.gate.release") == 0) return op_release(rt, args, "gate", result_out, detail_out);
    if (strcmp(name, "sync.barrier.release") == 0) return op_release(rt, args, "barrier", result_out, detail_out);
    if (strcmp(name, "sync.gate.destroy") == 0) return op_destroy(rt, args, "gate", result_out, detail_out);
    if (strcmp(name, "sync.barrier.destroy") == 0) return op_destroy(rt, args, "barrier", result_out, detail_out);

    /* The router only calls the provider for wired routes; reaching this line means the
     * table and the provider disagree -- refuse instead of guessing. */
    *detail_out = "operation is not implemented by the native stub provider";
    return "OPERATION_DEFERRED";
}
