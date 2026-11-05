/* PS4RF W14 -- the resident daemon's state machine, against the production module.
 *
 * A white-box harness: it links the *production* ps4rf_daemon.c (plus the frozen dispatch modules
 * and the honest host platform stand-ins) and asks the questions a state machine must answer
 * before any socket is involved:
 *
 *   * the lifecycle vocabulary is the frozen one (BOOTSTRAP/RESIDENT_IDLE/SESSION_ACTIVE/
 *     SESSION_CLEANUP),
 *   * the acceptance gate accepts in RESIDENT_IDLE and refuses in every other state -- including
 *     the mid-session case (§13) where a further connection must see SESSION_BUSY,
 *   * the refusal notice is valid canonical JSON with exactly the documented field set and no
 *     session-bound material (it is unauthenticated, so it must carry no authority),
 *   * the run report is valid canonical JSON from the frozen vocabulary.
 *
 * Everything socket-level (per-session listeners, the refusal on a real second connection, the
 * four exit conditions) is driven end to end in tests/test_w14_daemon.py.
 */
#include <stdio.h>
#include <string.h>

#include "ps4rf_daemon.h"
#include "ps4rf_platform.h"

static const char *decision_name(ps4rf_daemon_decision d)
{
    return d == PS4RF_DAEMON_ACCEPT ? "ACCEPT" : "SESSION_BUSY";
}

/* W14 §2/§5/§9/§11 -- the two decisions the daemon makes about a finished session, exercised
 * directly on the production code: what must be reaped, and what makes a boot "in recovery".
 * These are unit-level questions (a socket cannot produce every combination). */
static const char *recovery_rule_cases(void)
{
    static char out[512];
    ps4rf_rt rt;
    unsigned reaped = 0u;
    char ref[PS4RF_REF_LEN];
    int clean, violations, undelivered, leftover, refused_teardown, null_rt, pending;
    const char *state;

    ps4rf_res foreign;
    char foreign_ref[PS4RF_REF_LEN];
    ps4rf_res_status own_status;
    ps4rf_res_status foreign_status;
    unsigned foreign_freed = 0u;
    unsigned live_after;
    unsigned foreign_live_after;

    memset(&rt, 0, sizeof(rt));
    ps4rf_rt_init(&rt, "SES-harness", "harness-build", "harness", "ps4rfd-native-stub");

    /* a clean session must not park the boot in recovery */
    clean = ps4rf_daemon_session_recovery_required(&rt, PS4RF_CLEANUP_COMPLETE);
    null_rt = ps4rf_daemon_session_recovery_required(NULL, PS4RF_CLEANUP_COMPLETE);

    rt.ev.violations = 1u;
    violations = ps4rf_daemon_session_recovery_required(&rt, PS4RF_CLEANUP_COMPLETE);
    rt.ev.violations = 0u;

    rt.undelivered_mutations = 1u;
    undelivered = ps4rf_daemon_session_recovery_required(&rt, PS4RF_CLEANUP_COMPLETE);
    rt.undelivered_mutations = 0u;

    /* one object the session forgets: the cleanup state says PENDING and the rule agrees */
    (void)ps4rf_res_create(&rt.res, 1u, 0, ref);
    state = ps4rf_res_cleanup_state(&rt.res);
    leftover = ps4rf_daemon_session_recovery_required(&rt, state);
    pending = ps4rf_daemon_session_recovery_required(&rt, PS4RF_CLEANUP_COMPLETE);

    rt.cleanup_status = 1;                               /* the teardown refused */
    refused_teardown = ps4rf_daemon_session_recovery_required(&rt, PS4RF_CLEANUP_COMPLETE);
    rt.cleanup_status = 0;

    /* the teardown hands this session's set back empty ... */
    own_status = ps4rf_res_teardown(&rt.res, &reaped);
    live_after = ps4rf_res_live(&rt.res);
    /* ... and refuses to touch a set it cannot attribute to a session */
    ps4rf_res_init(&foreign, NULL);
    (void)ps4rf_res_create(&foreign, 1u, 0, foreign_ref);
    foreign_status = ps4rf_res_teardown(&foreign, &foreign_freed);
    foreign_live_after = ps4rf_res_live(&foreign);

    snprintf(out, sizeof(out),
             "{\"clean\":%d,\"violations\":%d,\"undelivered\":%d,\"leftover\":%d,"
             "\"pending_cleanup\":%d,\"refused_teardown\":%d,\"null_rt\":%d,"
             "\"teardown_status\":%d,\"teardown_reaped\":%u,\"live_after\":%u,"
             "\"foreign_status\":%d,\"foreign_freed\":%u,\"foreign_live_after\":%u}",
             clean, violations, undelivered, leftover, pending, refused_teardown, null_rt,
             (int)own_status, reaped, live_after, (int)foreign_status, foreign_freed,
             foreign_live_after);
    return out;
}

int main(void)
{
    ps4rf_daemon_config cfg;
    ps4rf_daemon d;
    char notice_idle[PS4RF_DAEMON_BUSY_MAX + 1u];
    char notice_active[PS4RF_DAEMON_BUSY_MAX + 1u];
    char report[PS4RF_DAEMON_REPORT_MAX];
    size_t n_idle = 0u;
    size_t n_active = 0u;
    size_t n_report;
    int bootstrap_rc;
    int run_rc;
    const char *accept_bootstrap;
    const char *accept_idle;
    const char *accept_active;
    const char *accept_cleanup;
    const char *accept_after_active;

    memset(&cfg, 0, sizeof(cfg));
    cfg.label = "harness-daemon";
    cfg.context = "harness";
    cfg.provider_id = "ps4rfd-native-stub";
    cfg.build_id = "harness-build";
    cfg.host = "127.0.0.1";
    cfg.port = 9;                  /* nothing listens there: the honest "no controller" case */
    cfg.dial_attempts = 1u;
    cfg.lifetime_s = 5u;
    cfg.idle_s = 5u;
    cfg.max_sessions = 0u;         /* the run ends on the idle rounds, not on a session budget */
    cfg.idle_rounds = 1u;
    cfg.idle_pause_us = 0u;
    cfg.refuse_while_busy = 1;

    ps4rf_daemon_init(&d, &cfg);

    /* 1. the gate refuses outside RESIDENT_IDLE (BOOTSTRAP is not a serving state) */
    accept_bootstrap = decision_name(ps4rf_daemon_accept(&d));

    /* 2. §2 BOOTSTRAP, once per boot */
    bootstrap_rc = ps4rf_daemon_bootstrap(&d);

    /* 3. the gate accepts in RESIDENT_IDLE */
    d.state = PS4RF_DAEMON_STATE_RESIDENT_IDLE;
    accept_idle = decision_name(ps4rf_daemon_accept(&d));
    n_idle = ps4rf_daemon_busy_notice(&d, notice_idle, PS4RF_DAEMON_BUSY_MAX);

    /* 4. §13: a session is active -> a further connection sees SESSION_BUSY. The active flag and
     *    the state must agree; neither one alone may open the gate. */
    d.active = 1;
    d.state = PS4RF_DAEMON_STATE_SESSION_ACTIVE;
    accept_active = decision_name(ps4rf_daemon_accept(&d));
    n_active = ps4rf_daemon_busy_notice(&d, notice_active, PS4RF_DAEMON_BUSY_MAX);

    /* 5. the cleanup state is not a serving state either */
    d.state = PS4RF_DAEMON_STATE_SESSION_CLEANUP;
    accept_cleanup = decision_name(ps4rf_daemon_accept(&d));

    /* 6. the flag alone (state back to idle, session still active) stays a refusal */
    d.state = PS4RF_DAEMON_STATE_RESIDENT_IDLE;
    accept_after_active = decision_name(ps4rf_daemon_accept(&d));

    /* 7. a full run: bootstrap, no controller, driver-budget/idle end (no exit condition) */
    ps4rf_daemon_init(&d, &cfg);
    run_rc = ps4rf_daemon_run(&d);
    n_report = ps4rf_daemon_report_json(&d, report, sizeof(report));

    printf("{\"accept_bootstrap\":\"%s\",\"accept_idle\":\"%s\",\"accept_active\":\"%s\","
           "\"accept_cleanup\":\"%s\",\"accept_after_active\":\"%s\","
           "\"bootstrap_rc\":%d,\"boot_inputs\":\"%s\","
           "\"notice_idle_len\":%u,\"notice_idle\":%s,\"notice_active_len\":%u,"
           "\"notice_active\":%s,\"run_rc\":%d,\"report_len\":%u,\"report\":%s,"
           "\"state_vocabulary\":[\"%s\",\"%s\",\"%s\",\"%s\",\"%s\"],"
           "\"exit_vocabulary\":[\"%s\",\"%s\",\"%s\",\"%s\",\"%s\"],"
           "\"stop_vocabulary\":[\"%s\",\"%s\",\"%s\",\"%s\"],\"busy_msg\":\"%s\","
           "\"recovery_rule\":%s}\n",
           accept_bootstrap, accept_idle, accept_active, accept_cleanup, accept_after_active,
           bootstrap_rc, d.rep.boot_inputs,
           (unsigned)n_idle, n_idle > 0u ? notice_idle : "null",
           (unsigned)n_active, n_active > 0u ? notice_active : "null",
           run_rc, (unsigned)n_report, n_report > 0u ? report : "null",
           PS4RF_DAEMON_STATE_BOOTSTRAP, PS4RF_DAEMON_STATE_RESIDENT_IDLE,
           PS4RF_DAEMON_STATE_SESSION_ACTIVE, PS4RF_DAEMON_STATE_SESSION_CLEANUP,
           PS4RF_DAEMON_STATE_EXITED,
           PS4RF_DAEMON_EXIT_NONE, PS4RF_DAEMON_EXIT_ADMIN, PS4RF_DAEMON_EXIT_PROTOCOL,
           PS4RF_DAEMON_EXIT_RECOVERY, PS4RF_DAEMON_EXIT_INTEGRITY,
           PS4RF_DAEMON_STOP_BUDGET, PS4RF_DAEMON_STOP_EXIT, PS4RF_DAEMON_STOP_BOOTSTRAP,
           PS4RF_DAEMON_STOP_NODIAL,
           PS4RF_DAEMON_BUSY_MSG,
           recovery_rule_cases());
    return 0;
}
