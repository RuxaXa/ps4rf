/* PS4RF W14 -- resident daemon (ps4rfd): lifecycle, session acceptance and agent exit.
 *
 * What this module is
 * -------------------
 * The resident counterpart of the single-shot target agent. It owns the §2 lifecycle
 *
 *     BOOTSTRAP -> RESIDENT_IDLE -> SESSION_ACTIVE -> SESSION_CLEANUP -> RESIDENT_IDLE -> ...
 *
 * and nothing else. It has no wire path of its own, no operation dispatch and no second
 * provider entry: every session is driven by the frozen `ps4rf_agent_run` (handshake, READY,
 * REQUEST/RESPONSE loop) and every operation still reaches the dispatcher through the router.
 *
 * Transport (§12, §13)
 * --------------------
 * Sessions are accepted over the *existing dial-out transport*: the daemon dials the
 * configured research endpoint with `net_connect`, so a controller that has its listener open
 * *is* the session attempt. There is no listener, no port and no health probe on the agent
 * side -- the loader port is never named, opened or probed by the agent after bootstrap (§12:
 * the research transport is the only channel a session uses).
 *
 *   * a dial that cannot connect is "no controller offering right now": recorded
 *     (`dial_misses`), never fatal -- a resident agent must survive a missing controller,
 *   * a dial during RESIDENT_IDLE is a session attempt and is decided by
 *     `ps4rf_daemon_accept()`, the single acceptance gate,
 *   * a further connection attempt that reaches the agent while a session is ACTIVE is
 *     refused with the SESSION_BUSY notice **on that connection** (§13: at most one active
 *     research session). The session itself continues untouched; at most one such refusal is
 *     made per session, because after the session the next attempt must be served again.
 *
 * The refusal notice is emitted before any handshake, so it cannot be authenticated and
 * therefore carries **no authority**: it is a busy notice (a reason for the closed
 * connection), never a protocol frame, never a state change, and the host validator
 * (`tools/hostctl/resident.py`) treats it as information only.
 *
 * Exit conditions (§3)
 * --------------------
 * The agent ends for exactly four reasons, and for nothing else:
 *
 *   ADMIN_SHUTDOWN            -- the authenticated admin shutdown (§15; the producer arrives
 *                                with that wave: this module defines the vocabulary only)
 *   PROTOCOL_CORRUPTION       -- a fatal protocol failure: framing, direction, AEAD, canonical
 *                                parse, a failed HELLO/handshake, a replayed session id
 *   RECOVERY_REQUIRED_UNSAFE  -- RECOVERY_REQUIRED with an unsafe agent state (a live object,
 *                                an in-flight request, a recording violation or a cleanup that
 *                                is not COMPLETE). A RECOVERY_REQUIRED with a *sound* state
 *                                keeps the agent resident and sets the boot-wide recovery flag
 *                                (§11: never reset automatically, only recovery-safe
 *                                status/telemetry afterwards)
 *   INTERNAL_INTEGRITY_FAILURE-- the agent's own invariants or fixed steps failed (bootstrap
 *                                could not establish the boot inputs, the cached boot inputs
 *                                changed under a running daemon, the session left resources
 *                                behind, the fixed privileged step did not complete)
 *
 * Everything else -- a lost transport, a closed connection, a refused operation -- is
 * session-scoped and leaves the agent resident. The stop reason of a *run* (driver budget
 * reached, no controller offering) is reported separately and is not an exit condition.
 */
#ifndef PS4RF_DAEMON_H
#define PS4RF_DAEMON_H

#include <stddef.h>
#include <stdint.h>

#include "ps4rf_runtime.h"
#include "ps4rf_kread.h"   /* the fixed steps' record types + the region table's window defines */

/* ------------------------------------------------------------------ §2 lifecycle states */
#define PS4RF_DAEMON_STATE_BOOTSTRAP       "BOOTSTRAP"
#define PS4RF_DAEMON_STATE_RESIDENT_IDLE   "RESIDENT_IDLE"
#define PS4RF_DAEMON_STATE_SESSION_ACTIVE  "SESSION_ACTIVE"
#define PS4RF_DAEMON_STATE_SESSION_CLEANUP "SESSION_CLEANUP"
#define PS4RF_DAEMON_STATE_EXITED          "EXITED"

/* -------------------------------------------------- §3 the only four agent exit conditions */
#define PS4RF_DAEMON_EXIT_NONE      "NONE"
#define PS4RF_DAEMON_EXIT_ADMIN     "ADMIN_SHUTDOWN"
#define PS4RF_DAEMON_EXIT_PROTOCOL  "PROTOCOL_CORRUPTION"
#define PS4RF_DAEMON_EXIT_RECOVERY  "RECOVERY_REQUIRED_UNSAFE"
#define PS4RF_DAEMON_EXIT_INTEGRITY "INTERNAL_INTEGRITY_FAILURE"

/* ------------------- how the *run* ended (driver vocabulary, not an agent exit condition) */
#define PS4RF_DAEMON_STOP_BUDGET    "DRIVER_BUDGET"
#define PS4RF_DAEMON_STOP_EXIT      "EXIT_CONDITION"
#define PS4RF_DAEMON_STOP_BOOTSTRAP "BOOTSTRAP_FAILED"
#define PS4RF_DAEMON_STOP_NODIAL    "NO_CONTROLLER"

/* ------------------------------------------------ §13 SESSION_BUSY refusal (pre-session) */
#define PS4RF_DAEMON_BUSY_MSG     "SESSION_BUSY"
#define PS4RF_DAEMON_BUSY_VERSION "ps4rfd-daemon-w14"
#define PS4RF_DAEMON_BUSY_MAX     512u

/* bounded registry of session ids served in this run (reuse detection, §4/§17) */
/* §4/§17 -- the session-id registry is a *bounded ring*: it must not grow with the run length
 * (the stress requirement), so it remembers the most recent ids and counts the total. The primary
 * guarantee is the host's: a session id is `SES-<128-bit nonce hex>` and is never reused. This
 * registry is the backstop that catches a replay inside the window; the window is reported. */
#define PS4RF_DAEMON_SESSION_IDS 64u

/* §18: the capacity a caller must offer for the report. The evidence is bounded by construction --
 * 64 session ids plus 8 session records plus the scalars -- so the requirement is a constant, not a
 * guess. A caller that offers less gets nothing back (the builder fails closed instead of
 * truncating evidence). */
#define PS4RF_DAEMON_REPORT_MAX 16384u

/* §6 -- the dial-out backoff is bounded on both ends: a missing controller may cost time but never
 * a busy loop, and never an unbounded wait. */
#define PS4RF_DAEMON_BACKOFF_MIN_US 50000u    /* 50 ms floor, even if the config asks for 0 */
#define PS4RF_DAEMON_BACKOFF_MAX_US 30000000u /* 30 s cap, even if the config asks for more */
/* The floor wins over a smaller cap: a cap misconfigured below the floor would otherwise reintroduce
 * the busy loop the floor exists to prevent. */

typedef enum {
    PS4RF_DAEMON_ACCEPT = 0,        /* the attempt becomes a session */
    PS4RF_DAEMON_SESSION_BUSY = 1   /* §13: refused with the busy notice, agent stays resident */
} ps4rf_daemon_decision;

typedef struct {
    const char *label;
    const char *context;
    const char *provider_id;
    const char *build_id;
    const uint8_t *psk;                /* borrowed; never copied into a report or a notice */
    const char *host;                  /* the controller's research endpoint (dial-out) */
    unsigned port;
    unsigned dial_attempts;            /* per dial attempt (the platform retries internally) */
    unsigned lifetime_s;
    unsigned idle_s;
    unsigned max_sessions;             /* driver budget; 0 = unbounded (console behaviour) */
    unsigned idle_rounds;              /* idle dial rounds before the run ends; 0 = unbounded */
    unsigned idle_pause_us;            /* §6 backoff base (the first pause after a dial miss) */
    unsigned backoff_max_us;           /* §6 backoff cap; 0 = PS4RF_DAEMON_BACKOFF_MAX_US */
    int      initial_recovery;         /* §11: this boot comes up in the recovery state */
    int      refuse_while_busy;        /* §13: refuse a further attempt during a session */
} ps4rf_daemon_config;

/* §18/W14B -- the two evidence levels.
 *
 * *Lifetime*: the boot facts, the agent build, when the lifetime started, how often the boot-wide
 * recovery flag was raised and what raised it, and the final exit reason. It is identified by
 * `lifetime_id`, which every session record below belongs to -- a session record is only ever
 * meaningful together with the lifetime that produced it.
 *
 * *Session*: the id the host chose, the identity the agent announced for it, what the session did
 * (requests answered, provider entries, refusals), what it held, how it ended and in what cleanup
 * state. The transcript stays a *host-side* derivation (the target computes no transcript digest --
 * the same rule that keeps the boot-id derivation off the console); the record binds the session by
 * the id the host chose and the identity the agent announced, which is what the host needs to pair
 * the two sides.
 *
 * The list is *bounded*: the most recent PS4RF_DAEMON_SESSION_RECORDS sessions are kept and
 * `session_records_total` counts all of them, so evidence never grows with the run length. */
#define PS4RF_DAEMON_SESSION_RECORDS 8u

typedef struct {
    char session_id[64];
    char bye[24];                      /* the frozen BYE reason of this session */
    char cleanup_state[16];
    unsigned held_after_cleanup;
    unsigned reaped;
    unsigned requests;                 /* requests the session answered */
    unsigned provider_entries;
    unsigned deferred;
    unsigned invalid;
    unsigned violations;
    int recovery_at_start;             /* the boot-wide flag when this session opened */
    int boot_recheck_ok;               /* the per-session boot/profile re-check of §5 */
} ps4rf_daemon_session_record;

typedef struct {
    char state[24];
    char stop[24];
    char exit_reason[32];
    char exit_detail[96];
    unsigned attempts;                 /* session attempts dialed in this run (driver budget) */
    unsigned sessions_served;
    unsigned sessions_failed;
    unsigned busy_refusals;
    unsigned dial_misses;              /* consecutive dial misses (drives the §6 backoff) */
    unsigned dial_misses_total;        /* dial misses over the whole run (evidence) */
    unsigned dial_backoff_us;          /* the pause the §6 backoff used last */
    unsigned recovery_transitions;     /* §11: times the boot-wide flag was raised */
    char recovery_source[24];          /* what raised it: "BOOT" | "SESSION" | "NONE" */
    unsigned bootstrap_failures;
    unsigned transitions;
    int recovery_required;             /* boot-wide (§11), never reset automatically */
    unsigned cleanup_reaped;           /* objects released by the last session's teardown */
    unsigned held_after_cleanup;       /* live objects left after that teardown (0 = clean) */
    unsigned cleanup_refusals;         /* sessions whose teardown could not hand the set back */
    char cleanup_state[16];            /* "COMPLETE" | "PENDING" after the last session */
    unsigned undelivered_responses;    /* answers that never reached the peer (whole run) */
    unsigned undelivered_mutations;    /* mutating answers the host never saw (whole run) */
    char boot_inputs[16];              /* "MEASURED" | "UNRESOLVED" */
    long long boot_sec;                /* raw inputs; the digest stays a host-side derivation */
    long long boot_usec;
    unsigned session_id_count;
    char session_ids[PS4RF_DAEMON_SESSION_IDS][64];
    char last_bye[24];
    char lifetime_id[80];              /* identifies the lifetime every session record belongs to */
    long long lifetime_start_sec;
    unsigned session_records_total;    /* sessions recorded over the whole run (may exceed the list) */
    unsigned session_record_count;     /* entries in `session_records`, oldest first */
    ps4rf_daemon_session_record session_records[PS4RF_DAEMON_SESSION_RECORDS];
} ps4rf_daemon_report;

typedef struct {
    ps4rf_daemon_config cfg;
    ps4rf_daemon_report rep;
    const char *state;
    int active;                        /* a session is in flight (never more than one) */
    int busy_refused_this_session;
    int boot_cached;
    int boot_measured;                 /* W15R3: the lifetime's one measurement was attempted */
    int dial_marked;                   /* W15R3: the B03 breadcrumb was emitted (first dial) */
    int session_marked;                /* W15R3: the B07 breadcrumb was emitted for this session */
    int session_id_checked;            /* the current session's id was inspected once */
    int session_id_replayed;           /* ... and it had been served before (replay) */
    int recovery_required;             /* boot-wide recovery flag raised during this run */
    const ps4rf_rt *rt_current;        /* the running session's runtime (checkpoint input) */
    long long boot_sec;
    long long boot_usec;
    char boot_detail[40];              /* W15R3: the measurement's status name when it failed */
    /* Track A: the lifetime's fixed window step. `window_marked` is per session (the step runs at
     * most once per session); the report fields below are per session as well and are re-filled by
     * that step -- the session.status response of the session the step ran in carries them. The
     * two record blocks are the step's own scratch: the outcome is copied into the report fields
     * before the next step can clear the block, exactly as the boot step does it. */
    int window_marked;                 /* the window step of this session was decided */
    char window_kind[16];              /* "" | "BINDING" | "OBSERVATION" */
    char window_status[24];            /* the step's own status name ("" when no step ran) */
    char window_hex[2u * PS4RF_KREAD_OBS_MAX_LEN + 1u];   /* the window's bytes, lowercase hex */
    char window_sha256[65];            /* sha256 of the copied range, hex ("" when not measured) */
    unsigned window_index;
    unsigned window_len;
    unsigned window_cursor;
    unsigned window_count;
    ps4rf_kread_identity_record window_identity;            /* scratch: binding-window outcome */
    ps4rf_kread_observation_record window_observation;      /* scratch: observation outcome */
    char seen[PS4RF_DAEMON_SESSION_IDS][64];
    unsigned seen_count;
    unsigned seen_head;
} ps4rf_daemon;

void ps4rf_daemon_init(ps4rf_daemon *d, const ps4rf_daemon_config *cfg);

/* The current lifecycle state (a PS4RF_DAEMON_STATE_* constant). */
const char *ps4rf_daemon_state(const ps4rf_daemon *d);

/* §2 BOOTSTRAP, once per boot: establishes the boot inputs / profile cache. 0 = ok,
 * -1 = fail closed (the run must end with INTERNAL_INTEGRITY_FAILURE / BOOTSTRAP_FAILED). */
int ps4rf_daemon_bootstrap(ps4rf_daemon *d);

/* §5: the cached boot inputs are re-read before every session. 0 = unchanged (or nothing
 * cached), -1 = the cache no longer describes this boot (reason into `detail`). */
int ps4rf_daemon_boot_recheck(ps4rf_daemon *d, char *detail, size_t detail_cap);

/* §13 the single session acceptance gate. ACCEPT only in RESIDENT_IDLE with no active
 * session; SESSION_BUSY in every other state (it is what a further connection while a
 * session is active is answered with, and what the mid-session refusal path consults). */
ps4rf_daemon_decision ps4rf_daemon_accept(const ps4rf_daemon *d);

/* The SESSION_BUSY notice as canonical JSON. Returns the length written (0 = not built).
 * Unauthenticated by construction (there is no session yet) and therefore authority-free. */
size_t ps4rf_daemon_busy_notice(const ps4rf_daemon *d, char *out, size_t cap);

/* The resident run. Returns 0 when the run ended on the driver budget / no controller
 * offering, 1 when it ended on an exit condition. The report carries the details. */
int ps4rf_daemon_run(ps4rf_daemon *d);

/* The recorded exit reason ("NONE" while the agent is resident), for a driver that has to tell a
 * clean shutdown apart from a fault when it maps the run to a process exit code. */
const char *ps4rf_daemon_exit_reason(const ps4rf_daemon *d);

/* W14 §5/§11 -- the one decision that turns a finished session into a boot state: does this boot
 * have to be considered in recovery? True when the session broke a protocol obligation, raised the
 * flag itself, left work in flight, lost the answer to a mutating operation, or could not hand its
 * resource set back empty. A plain lost transport is not in that list. */
int ps4rf_daemon_session_recovery_required(const ps4rf_rt *rt, const char *cleanup);

/* The run report as canonical JSON (no key material, no host input). */
size_t ps4rf_daemon_report_json(const ps4rf_daemon *d, char *out, size_t cap);

#endif /* PS4RF_DAEMON_H */
