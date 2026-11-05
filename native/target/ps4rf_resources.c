/* PS4RF P4/W8 target agent -- resources implementation (see ps4rf_resources.h). */
#include "ps4rf_resources.h"

#include "ps4rf_platform.h"
#include "sha256.h"

#define PS4RF_ALIGN_UP(v, a) (((v) + ((a) - 1u)) & ~((size_t)(a) - 1u))

static const char *kind_name(unsigned char kind)
{
    switch (kind) {
    case PS4RF_RES_MEM: return "mem";
    case PS4RF_RES_GATE: return "gate";
    case PS4RF_RES_BARRIER: return "barrier";
    default: return NULL;
    }
}

static void hex16_upper(const uint8_t *raw, char *out)
{
    static const char digits[] = "0123456789ABCDEF";
    unsigned i;
    for (i = 0u; i < 8u; i++) {
        out[i * 2u] = digits[(raw[i] >> 4) & 0x0fu];
        out[i * 2u + 1u] = digits[raw[i] & 0x0fu];
    }
    out[16] = '\0';
}

static void make_ref(const ps4rf_res *res, unsigned char kind, unsigned counter, char out[PS4RF_REF_LEN])
{
    char seed[96];
    uint8_t digest[32];
    const char *name = kind_name(kind);
    unsigned n = 0u;
    const char *p = res->session_id;
    char number[16];
    unsigned i = 0u;

    /* seed = session_id | kind | counter (decimal, no separators that could collide) */
    while (*p != '\0' && n < sizeof(seed) - 32u) seed[n++] = *p++;
    seed[n++] = '|';
    if (name != NULL) {
        const char *q = name;   /* the kind name is reused for the ref prefix below */
        while (*q != '\0' && n < sizeof(seed) - 32u) seed[n++] = *q++;
    }
    seed[n++] = '|';
    if (counter == 0u) {
        number[i++] = '0';
    } else {
        unsigned v = counter;
        char rev[16];
        unsigned r = 0u;
        while (v > 0u && r < sizeof(rev)) {
            rev[r++] = (char)('0' + (v % 10u));
            v /= 10u;
        }
        while (r > 0u) number[i++] = rev[--r];
    }
    for (unsigned k = 0u; k < i && n < sizeof(seed); k++) seed[n++] = number[k];

    ps4rf_sha256(seed, (size_t)n, digest);
    out[0] = '\0';
    if (name != NULL) {
        unsigned k = 0u;
        while (name[k] != '\0' && k < 8u) {
            out[k] = name[k];
            k++;
        }
        out[k] = ':';
        hex16_upper(digest, out + k + 1u);
    }
}

void ps4rf_res_init(ps4rf_res *res, const char *session_id)
{
    unsigned i;
    if (res == NULL) return;
    for (i = 0u; i < PS4RF_RES_MAX; i++) {
        res->slots[i].id[0] = '\0';
        res->slots[i].kind = PS4RF_RES_NONE;
        res->slots[i].used = 0u;
        res->slots[i].ptr = NULL;
        res->slots[i].size = 0u;
        res->slots[i].destroyed = 0u;
        res->slots[i].released = 0u;
        res->slots[i].parties = 0u;
        res->slots[i].participants = 0u;
        res->slots[i].lane_count = 0u;
    }
    res->session_id[0] = '\0';
    if (session_id != NULL) {
        unsigned n = 0u;
        while (session_id[n] != '\0' && n + 1u < sizeof(res->session_id)) {
            res->session_id[n] = session_id[n];
            n++;
        }
        res->session_id[n] = '\0';
    }
    res->counter = 0u;
    res->live = 0u;
    res->peak_live = 0u;
    res->alloc_calls = 0u;
    res->free_calls = 0u;
    res->refusals = 0u;
}

static ps4rf_res_slot *slot_new(ps4rf_res *res, unsigned char kind, char out[PS4RF_REF_LEN])
{
    unsigned i;
    for (i = 0u; i < PS4RF_RES_MAX; i++) {
        ps4rf_res_slot *slot = &res->slots[i];
        if (!slot->used) {
            slot->used = 1u;
            slot->kind = kind;
            slot->destroyed = 0u;
            slot->released = 0u;
            slot->participants = 0u;
            slot->lane_count = 0u;
            slot->ptr = NULL;
            slot->size = 0u;
            res->counter++;
            make_ref(res, kind, res->counter, slot->id);
            res->live++;
            if (res->live > res->peak_live) res->peak_live = res->live;
            if (out != NULL) {
                unsigned n = 0u;
                while (slot->id[n] != '\0' && n + 1u < PS4RF_REF_LEN) {
                    out[n] = slot->id[n];
                    n++;
                }
                out[n] = '\0';
            }
            return slot;
        }
    }
    return NULL;
}

/* Bounded, case sensitive ref lookup. The pattern is enforced before the lookup, so a
 * malformed ref is an ARGUMENT_INVALID and never a silent miss. */
static int ref_pattern_ok(const char *ref)
{
    unsigned i = 0u;
    unsigned colon = 0u;
    if (ref == NULL) return 0;
    if (!((ref[0] >= 'a' && ref[0] <= 'z'))) return 0;
    for (i = 0u; ref[i] != '\0'; i++) {
        char c = ref[i];
        if (c == ':') {
            if (colon != 0u || i == 0u) return 0;
            colon = i;
            continue;
        }
        if (colon == 0u) {
            if (!((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '_')) return 0;
        } else {
            if (!((c >= '0' && c <= '9') || (c >= 'A' && c <= 'F'))) return 0;
        }
    }
    if (colon == 0u) return 0;
    if (i - colon - 1u != 16u) return 0;   /* exactly 16 hex digits */
    return 1;
}

static ps4rf_res_slot *slot_find(ps4rf_res *res, const char *ref, unsigned char kind)
{
    unsigned i;
    if (!ref_pattern_ok(ref)) return NULL;
    for (i = 0u; i < PS4RF_RES_MAX; i++) {
        ps4rf_res_slot *slot = &res->slots[i];
        unsigned k = 0u;
        if (!slot->used || slot->kind != kind) continue;
        while (slot->id[k] != '\0' && ref[k] != '\0' && slot->id[k] == ref[k]) k++;
        if (slot->id[k] == '\0' && ref[k] == '\0') return slot;
    }
    return NULL;
}

static ps4rf_res_status kind_any(ps4rf_res *res, const char *ref, ps4rf_res_slot **out, unsigned char *kind)
{
    unsigned char kinds[3];
    unsigned i;
    kinds[0] = PS4RF_RES_MEM;
    kinds[1] = PS4RF_RES_GATE;
    kinds[2] = PS4RF_RES_BARRIER;
    for (i = 0u; i < 3u; i++) {
        ps4rf_res_slot *slot = slot_find(res, ref, kinds[i]);
        if (slot != NULL) {
            if (slot->destroyed) return PS4RF_RES_DESTROYED;
            *out = slot;
            *kind = kinds[i];
            return PS4RF_RES_OK;
        }
    }
    if (!ref_pattern_ok(ref)) return PS4RF_RES_INVALID;
    return PS4RF_RES_STATE;   /* well formed but unknown (or already destroyed and reaped) */
}

ps4rf_res_status ps4rf_res_alloc(ps4rf_res *res, size_t size, size_t align, char out[PS4RF_REF_LEN])
{
    ps4rf_res_slot *slot;
    void *ptr;
    res->alloc_calls++;
    if (size == 0u || size > 1048576u) { res->refusals++; return PS4RF_RES_LIMIT; }
    if (align == 0u) align = 8u;
    if ((align & (align - 1u)) != 0u) { res->refusals++; return PS4RF_RES_INVALID; }
    ptr = malloc(size);
    if (ptr == NULL) { res->refusals++; return PS4RF_RES_LIMIT; }
    memset(ptr, 0, size);
    slot = slot_new(res, PS4RF_RES_MEM, out);
    if (slot == NULL) {
        free(ptr);
        res->refusals++;
        return PS4RF_RES_LIMIT;
    }
    slot->ptr = ptr;
    slot->size = size;
    return PS4RF_RES_OK;
}

ps4rf_res_status ps4rf_res_free(ps4rf_res *res, const char *ref, char out_freed[PS4RF_REF_LEN])
{
    ps4rf_res_slot *slot = NULL;
    unsigned char kind = 0u;
    ps4rf_res_status st = kind_any(res, ref, &slot, &kind);
    if (st != PS4RF_RES_OK) { res->refusals++; return st; }
    if (kind != PS4RF_RES_MEM || slot->ptr == NULL) { res->refusals++; return PS4RF_RES_STATE; }
    free(slot->ptr);
    slot->ptr = NULL;
    slot->size = 0u;
    slot->used = 0u;
    res->free_calls++;
    res->live--;
    if (out_freed != NULL) {
        unsigned n = 0u;
        while (slot->id[n] != '\0' && n + 1u < PS4RF_REF_LEN) {
            out_freed[n] = slot->id[n];
            n++;
        }
        out_freed[n] = '\0';
    }
    return PS4RF_RES_OK;
}

/* W14 §2: the session's teardown. Everything the session held is released here, in one place, and
 * the set must be attributable to a session. A gate/barrier is marked destroyed (a waiter on a dead
 * session must never read "released"), memory is freed, the slot is cleared. */
ps4rf_res_status ps4rf_res_teardown(ps4rf_res *res, unsigned *reaped)
{
    unsigned i;
    unsigned freed = 0u;
    int unbound;

    if (res == NULL) return PS4RF_RES_INVALID;
    unbound = (res->session_id[0] == '\0');
    for (i = 0u; i < PS4RF_RES_MAX; i++) {
        ps4rf_res_slot *slot = &res->slots[i];
        if (slot->used == 0u) continue;
        if (slot->kind == PS4RF_RES_NONE) { res->refusals++; return PS4RF_RES_STATE; }
        if (unbound) { res->refusals++; return PS4RF_RES_STATE; }
        if (slot->kind == PS4RF_RES_MEM) {
            if (slot->ptr != NULL) free(slot->ptr);
            slot->ptr = NULL;
            slot->size = 0u;
        } else {
            slot->destroyed = 1u;               /* never "released" for a waiter */
            slot->released = 0u;
            slot->lane_count = 0u;
            slot->participants = 0u;
        }
        memset(slot->id, 0, sizeof(slot->id));
        slot->kind = PS4RF_RES_NONE;
        slot->used = 0u;
        freed++;
    }
    if (freed > 0u) res->free_calls += freed;
    if (res->live >= freed) res->live -= freed;
    else res->live = 0u;
    if (reaped != NULL) *reaped = freed;
    if (res->live != 0u) { res->refusals++; return PS4RF_RES_STATE; }
    return PS4RF_RES_OK;
}

ps4rf_res_status ps4rf_res_create(ps4rf_res *res, unsigned parties, int barrier, char out[PS4RF_REF_LEN])
{
    ps4rf_res_slot *slot;
    if (parties == 0u || parties > PS4RF_RES_LANE_MAX) { res->refusals++; return PS4RF_RES_INVALID; }
    slot = slot_new(res, barrier ? PS4RF_RES_BARRIER : PS4RF_RES_GATE, out);
    if (slot == NULL) { res->refusals++; return PS4RF_RES_LIMIT; }
    slot->parties = parties;
    slot->released = 0u;
    return PS4RF_RES_OK;
}

ps4rf_res_status ps4rf_res_arrive(ps4rf_res *res, const char *ref, unsigned *participants)
{
    ps4rf_res_slot *slot = NULL;
    unsigned char kind = 0u;
    unsigned lane;
    ps4rf_res_status st = kind_any(res, ref, &slot, &kind);
    if (st != PS4RF_RES_OK) { res->refusals++; return st; }
    if (kind != PS4RF_RES_GATE && kind != PS4RF_RES_BARRIER) { res->refusals++; return PS4RF_RES_STATE; }
    if (slot->lane_count >= PS4RF_RES_LANE_MAX) { res->refusals++; return PS4RF_RES_LIMIT; }
    lane = slot->lane_count + 1u;
    slot->lanes[slot->lane_count++] = lane;
    slot->participants = slot->lane_count;
    if (kind == PS4RF_RES_BARRIER && slot->participants >= slot->parties) slot->released = 1u;
    if (participants != NULL) *participants = slot->participants;
    return PS4RF_RES_OK;
}

ps4rf_res_status ps4rf_res_wait(ps4rf_res *res, const char *ref, unsigned timeout_ms, int *released)
{
    ps4rf_res_slot *slot = NULL;
    unsigned char kind = 0u;
    uint64_t deadline;
    ps4rf_res_status st = kind_any(res, ref, &slot, &kind);
    if (st != PS4RF_RES_OK) { res->refusals++; return st; }
    if (kind != PS4RF_RES_GATE && kind != PS4RF_RES_BARRIER) { res->refusals++; return PS4RF_RES_STATE; }
    if (slot->released) {
        if (released != NULL) *released = 1;
        return PS4RF_RES_OK;
    }
    /* The agent is single threaded: a lane that waits is bounded by the request timeout
     * and returns "released = false" (frozen GateWaitResult.TIMEOUT) instead of blocking
     * the session. */
    deadline = ps4rf_platform_get()->now_us() + (uint64_t)timeout_ms * 1000ull;
    while (ps4rf_platform_get()->now_us() < deadline) {
        ps4rf_platform_get()->sleep_us(1000u);
        if (slot->released) {
            if (released != NULL) *released = 1;
            return PS4RF_RES_OK;
        }
        if (slot->destroyed) { res->refusals++; return PS4RF_RES_DESTROYED; }
    }
    if (released != NULL) *released = slot->released ? 1 : 0;
    return PS4RF_RES_OK;
}

ps4rf_res_status ps4rf_res_release(ps4rf_res *res, const char *ref, int *released)
{
    ps4rf_res_slot *slot = NULL;
    unsigned char kind = 0u;
    ps4rf_res_status st = kind_any(res, ref, &slot, &kind);
    if (st != PS4RF_RES_OK) { res->refusals++; return st; }
    if (kind != PS4RF_RES_GATE && kind != PS4RF_RES_BARRIER) { res->refusals++; return PS4RF_RES_STATE; }
    slot->released = 1u;
    if (released != NULL) *released = 1;
    return PS4RF_RES_OK;
}

ps4rf_res_status ps4rf_res_status_of(ps4rf_res *res, const char *ref, unsigned *participants,
                                     int *released, int *destroyed)
{
    ps4rf_res_slot *slot = NULL;
    unsigned char kind = 0u;
    ps4rf_res_status st = kind_any(res, ref, &slot, &kind);
    if (st != PS4RF_RES_OK) { res->refusals++; return st; }
    if (kind != PS4RF_RES_GATE && kind != PS4RF_RES_BARRIER) { res->refusals++; return PS4RF_RES_STATE; }
    if (participants != NULL) *participants = slot->participants;
    if (released != NULL) *released = slot->released ? 1 : 0;
    if (destroyed != NULL) *destroyed = slot->destroyed ? 1 : 0;
    return PS4RF_RES_OK;
}

ps4rf_res_status ps4rf_res_destroy(ps4rf_res *res, const char *ref, int *destroyed)
{
    ps4rf_res_slot *slot = NULL;
    unsigned char kind = 0u;
    ps4rf_res_status st = kind_any(res, ref, &slot, &kind);
    if (st != PS4RF_RES_OK) { res->refusals++; return st; }
    if (kind != PS4RF_RES_GATE && kind != PS4RF_RES_BARRIER) { res->refusals++; return PS4RF_RES_STATE; }
    slot->destroyed = 1u;
    slot->used = 0u;
    res->live--;
    if (destroyed != NULL) *destroyed = 1;
    return PS4RF_RES_OK;
}

const char *ps4rf_res_cleanup_state(const ps4rf_res *res)
{
    if (res->live > 0u) return PS4RF_CLEANUP_PENDING;
    return PS4RF_CLEANUP_COMPLETE;
}

unsigned ps4rf_res_live(const ps4rf_res *res)
{
    return res->live;
}

void ps4rf_res_held_list(const ps4rf_res *res, char *out, size_t cap)
{
    unsigned i;
    size_t n = 0u;
    if (out == NULL || cap == 0u) return;
    out[0] = '\0';
    for (i = 0u; i < PS4RF_RES_MAX; i++) {
        const ps4rf_res_slot *slot = &res->slots[i];
        const char *p;
        if (!slot->used) continue;
        p = slot->id;
        while (*p != '\0' && n + 2u < cap) out[n++] = *p++;
        if (n + 2u < cap) out[n++] = ',';
    }
    if (n > 0u && out[n - 1u] == ',') n--;
    out[n] = '\0';
}
