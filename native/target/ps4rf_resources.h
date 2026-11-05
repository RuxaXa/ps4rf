/* PS4RF P4/W8 target agent -- resources (memory, sync gates, barriers).
 *
 * The native counterpart of the frozen host manager (core/resources/manager.py) plus the
 * frozen sync objects (core/sync/gate.py). Same vocabulary, same failure modes:
 *
 *   * refs are `<kind>:<16 uppercase hex>` (frozen pattern `^[a-z][a-z0-9_]*:[0-9A-F]{16}$`)
 *   * a gate is released only by `release`; a barrier releases itself when the expected
 *     number of participants arrived
 *   * a duplicate lane is refused (`RESOURCE_STATE_INVALID`), a destroyed object is
 *     refused (`RESOURCE_DESTROYED`), and a wait timout returns `released = false`
 *   * every held object is visible in the status snapshot, so "no leak" is observable
 *
 * Ref derivation: sha256(session_id | kind | counter) truncated to 8 bytes, uppercase
 * hex. The host manager derives its refs from its own entropy source; the target uses
 * the session id, which is negotiated per session, so refs are unique per session and
 * reproducible in the evidence.
 */
#ifndef PS4RF_RESOURCES_H
#define PS4RF_RESOURCES_H

#include <stddef.h>
#include <stdint.h>

#include "ps4rf_libc.h"

#define PS4RF_RES_MAX 24u
#define PS4RF_RES_LANE_MAX 8u
#define PS4RF_REF_LEN 24u          /* "barrier:" + 16 hex + NUL */
#define PS4RF_CLEANUP_PENDING "PENDING"
#define PS4RF_CLEANUP_COMPLETE "COMPLETE"
#define PS4RF_CLEANUP_PARTIAL "PARTIAL"

typedef enum {
    PS4RF_RES_NONE = 0,
    PS4RF_RES_MEM = 1,
    PS4RF_RES_GATE = 2,
    PS4RF_RES_BARRIER = 3
} ps4rf_res_kind;

typedef enum {
    PS4RF_RES_OK = 0,
    PS4RF_RES_INVALID = 1,          /* ARGUMENT_INVALID / RESOURCE_STATE_INVALID */
    PS4RF_RES_LIMIT = 2,            /* RESOURCE_LIMIT */
    PS4RF_RES_DESTROYED = 3,        /* RESOURCE_DESTROYED */
    PS4RF_RES_STATE = 4             /* RESOURCE_STATE_INVALID (duplicate lane, wrong kind) */
} ps4rf_res_status;

typedef struct {
    char id[PS4RF_REF_LEN];
    unsigned char kind;
    unsigned char used;
    unsigned char destroyed;
    /* memory */
    size_t size;
    void *ptr;
    /* gate / barrier */
    unsigned char released;
    unsigned parties;
    unsigned participants;
    unsigned lanes[PS4RF_RES_LANE_MAX];
    unsigned lane_count;
} ps4rf_res_slot;

typedef struct {
    char session_id[64];
    ps4rf_res_slot slots[PS4RF_RES_MAX];
    unsigned counter;
    unsigned live;                  /* number of live (held) objects */
    unsigned peak_live;
    unsigned alloc_calls;
    unsigned free_calls;
    unsigned refusals;
} ps4rf_res;

void ps4rf_res_init(ps4rf_res *res, const char *session_id);

ps4rf_res_status ps4rf_res_alloc(ps4rf_res *res, size_t size, size_t align, char out[PS4RF_REF_LEN]);
ps4rf_res_status ps4rf_res_free(ps4rf_res *res, const char *ref, char out_freed[PS4RF_REF_LEN]);
ps4rf_res_status ps4rf_res_create(ps4rf_res *res, unsigned parties, int barrier, char out[PS4RF_REF_LEN]);
ps4rf_res_status ps4rf_res_arrive(ps4rf_res *res, const char *ref, unsigned *participants);
ps4rf_res_status ps4rf_res_wait(ps4rf_res *res, const char *ref, unsigned timeout_ms, int *released);
ps4rf_res_status ps4rf_res_release(ps4rf_res *res, const char *ref, int *released);
ps4rf_res_status ps4rf_res_status_of(ps4rf_res *res, const char *ref, unsigned *participants,
                                     int *released, int *destroyed);
ps4rf_res_status ps4rf_res_destroy(ps4rf_res *res, const char *ref, int *destroyed);

/* W14 §2/§10 -- session teardown. Reaps every live object of THIS session's resource set in one
 * place, so a session that ends (however it ends) hands the set back empty. The set must be bound
 * to a session: a teardown on a set without a session id is refused instead of destroying objects
 * nobody can attribute -- destroying them would consume state the caller cannot prove it owns.
 *
 * Returns OK with *reaped = number of objects released; STATE when the set is unbound or left
 * inconsistent (nothing of the offending slot is touched); the set is as clean as it could be made.
 * Deterministic and allocation-free apart from freeing the session's own memory blocks. */
ps4rf_res_status ps4rf_res_teardown(ps4rf_res *res, unsigned *reaped);

/* "PENDING" while objects are held, "COMPLETE" when everything is released again,
 * "PARTIAL" when objects remain after a close attempt (never reported as COMPLETE). */
const char *ps4rf_res_cleanup_state(const ps4rf_res *res);
unsigned ps4rf_res_live(const ps4rf_res *res);
/* Fills a JSON-ish comma separated list of held refs into out (bounded, always NUL). */
void ps4rf_res_held_list(const ps4rf_res *res, char *out, size_t cap);

#endif /* PS4RF_RESOURCES_H */
