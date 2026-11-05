/* PS4RF P4/W8 target agent -- runtime state shared by router, stub provider and session. */
#ifndef PS4RF_RUNTIME_H
#define PS4RF_RUNTIME_H

#include <stddef.h>
#include <stdint.h>

#include "ps4rf_evidence.h"
#include "ps4rf_libc.h"
#include "ps4rf_optable_data.h"
#include "ps4rf_resources.h"
#include "ps4rf_telemetry.h"

/* Frozen session states (core/session/states.py). */
#define PS4RF_STATE_NEW "NEW"
#define PS4RF_STATE_HANDSHAKE "HANDSHAKE"
#define PS4RF_STATE_ACTIVE "ACTIVE"
#define PS4RF_STATE_CLEANUP "CLEANUP"
#define PS4RF_STATE_RECOVERY_REQUIRED "RECOVERY_REQUIRED"
#define PS4RF_STATE_CLOSED "CLOSED"

typedef struct {
    ps4rf_res res;
    ps4rf_ev ev;
    ps4rf_telemetry tel;

    char session_id[64];
    char request_prefix[24];
    const char *state;              /* frozen session state string */
    int recovery_required;
    unsigned inflight;
    unsigned inflight_max_seen;
    unsigned requests_served;

    const char *provider_id;
    char build_id[80];
    char context[64];

    unsigned protocol_version;
    unsigned max_frame_bytes;
    unsigned lifetime_s;
    unsigned idle_s;

    /* W15R3 (owner D5 fix): the lifetime's boot-binding outcome, published by the resident daemon
     * into the *live* session. The measurement runs in this session's checkpoint -- after the dial
     * and the handshake -- so the first session is where the result has to be readable: the
     * resident loop's next platform call (the redial) is not a channel the host can rely on. The
     * digest stays a host-side derivation; these are the raw inputs and the measured status. */
    const char *boot_status;    /* "MEASURED" | "UNRESOLVED" (daemon-owned, per lifetime) */
    const char *boot_detail;    /* the measurement's own status name when it did not measure */
    long long boot_sec;
    long long boot_usec;

    /* Track A (W16 option B, observation half): this session's fixed window step -- the ONE
     * binding/observation window the daemon read for this session. Every pointer is daemon-owned
     * and lives for the whole lifetime; the session only points at it. The bytes arrive as hex and
     * as the payload's own sha256 of the copied range (the host re-derives both, and never treats
     * an observation as an identity). `window_kind` is "" when the sets are exhausted or the
     * lifetime has no established binding, so the host can tell "nothing read" from "read". */
    const char *window_kind;    /* "" | "BINDING" | "OBSERVATION" */
    const char *window_status;  /* the step's own status name ("" when no step ran) */
    const char *window_hex;     /* the window's bytes, lowercase hex ("" when nothing was read) */
    const char *window_sha256;  /* sha256 of the copied range, hex ("" when not measured) */
    unsigned window_index;      /* the compiled table row the step read (0 when none) */
    unsigned window_len;        /* bytes the step read into the report */
    unsigned window_cursor;     /* fixed window steps spent in this lifetime */
    unsigned window_count;      /* size of the whole fixed window set */

    /* W14 §5 -- transport loss. A response that never reached the peer is unfinished business the
     * boot cannot resolve itself *when the work it answers was mutating*: the target does not know
     * what the host saw. `last_op_mutating` is the router's verdict on the request it just handled. */
    /* W14 §15: an authenticated admin shutdown was accepted in this session. The provider sets it,
     * the session loop ends the session with the ADMIN_SHUTDOWN bye and the daemon ends the
     * lifetime -- the provider itself never ends anything. Session state: never carried over. */
    int admin_shutdown;          /* set by the provider only when it *accepted* the request */

    unsigned undelivered_responses;
    unsigned undelivered_mutations;
    int last_op_mutating;

    /* W14 §2/§10 -- the session teardown result. `cleanup_reaped` counts the objects the session
     * teardown released, `cleanup_status` is 0 (PS4RF_RES_OK) when the set was handed back empty
     * and attributable, non-zero when the teardown refused. Session state: never carried over. */
    unsigned cleanup_reaped;
    int cleanup_status;
} ps4rf_rt;

void ps4rf_rt_init(ps4rf_rt *rt, const char *session_id, const char *build_id,
                   const char *context, const char *provider_id);

#endif /* PS4RF_RUNTIME_H */
