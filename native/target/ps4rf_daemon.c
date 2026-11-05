/* PS4RF W14 -- resident daemon (ps4rfd). See ps4rf_daemon.h for the contract. */
#include "ps4rf_daemon.h"

#include "jcs.h"
#include "ps4rf_agent.h"
#include "ps4rf_platform.h"
#include "ps4rf_protocol.h"
#include "ps4rf_resources.h"
#include "ps4rf_runtime.h"

#ifdef PS4RF_TARGET_BOOTID
#include "ps4rf_boot.h"
#endif

/* W15R2: the lifetime boot binding. The resident build declares BOOTBIND together with the
 * bounded kernel.read provider: the bootstrap then measures the boot instant exactly once per
 * agent lifetime through that provider's single callback, over the compiled `boottime` row (the
 * userland route is not a boot-binding source on this firmware -- W11.1 live). The result block
 * is file-scope state of this module and is never exposed, never a request field. */
#ifdef PS4RF_TARGET_BOOTBIND
#include "ps4rf_kread.h"
static ps4rf_kread_info g_boot_binding_info;

/* Track A: the fixed window step's own result block -- one per step, never shared with the boot
 * measurement, so a window outcome can never overwrite the binding's report. */
static ps4rf_kread_info g_window_info;
#endif

/* ------------------------------------------------------------------------ small helpers */

/* No strcmp/strncmp here on purpose: the console build links against libPS4's libc surface,
 * and this module keeps its external surface to what the agent modules already use. */
static int d_eq(const char *a, const char *b)
{
    size_t i = 0u;
    if (a == NULL || b == NULL) return 0;
    while (a[i] != '\0' && b[i] != '\0') {
        if (a[i] != b[i]) return 0;
        i++;
    }
    return a[i] == b[i];
}

static int d_ne(const char *a, const char *b)
{
    return d_eq(a, b) ? 0 : 1;
}

static void d_copy(char *dst, size_t cap, const char *src)
{
    size_t i = 0u;
    if (dst == NULL || cap == 0u) return;
    if (src == NULL) {
        dst[0] = '\0';
        return;
    }
    while (src[i] != '\0' && i + 1u < cap) {
        dst[i] = src[i];
        i++;
    }
    dst[i] = '\0';
}

/* §18: append without snprintf (the daemon module keeps the libPS4 libc surface out of its way). */
static size_t d_append(char *out, size_t cap, size_t at, const char *text)
{
    size_t i = 0u;
    if (out == NULL || cap == 0u) return at;
    while (text != NULL && text[i] != '\0' && at + 1u < cap) out[at++] = text[i++];
    if (at < cap) out[at] = '\0';
    return at;
}

static size_t d_append_u64(char *out, size_t cap, size_t at, unsigned long long value)
{
    char digits[24];
    size_t n = 0u;
    if (out == NULL || cap == 0u) return at;
    if (value == 0ull) {
        digits[n++] = '0';
    }
    while (value > 0ull && n < sizeof(digits)) {
        digits[n++] = (char)('0' + (int)(value % 10ull));
        value /= 10ull;
    }
    while (n > 0u && at + 1u < cap) out[at++] = digits[--n];
    if (at < cap) out[at] = '\0';
    return at;
}

static void d_set_state(ps4rf_daemon *d, const char *state)
{
    d->state = state;
    d_copy(d->rep.state, sizeof(d->rep.state), state);
    d->rep.transitions++;
}

/* 0 when the run continues, 1 when the agent ends (the caller owns the exit code). */
static int daemon_finish(ps4rf_daemon *d, const char *exit_reason, const char *detail)
{
    if (exit_reason == NULL || d_eq(exit_reason, PS4RF_DAEMON_EXIT_NONE)) return 0;
    d_copy(d->rep.exit_reason, sizeof(d->rep.exit_reason), exit_reason);
    d_copy(d->rep.exit_detail, sizeof(d->rep.exit_detail), detail != NULL ? detail : "");
    d_copy(d->rep.stop, sizeof(d->rep.stop), PS4RF_DAEMON_STOP_EXIT);
    d_set_state(d, PS4RF_DAEMON_STATE_EXITED);
    return 1;
}

/* ------------------------------------------------------------------ session-id registry */

static int daemon_session_id_seen(const ps4rf_daemon *d, const char *session_id)
{
    unsigned i;
    for (i = 0u; i < d->seen_count; i++) {
        if (d_eq(d->seen[i], session_id)) return 1;
    }
    return 0;
}

static void daemon_session_id_record(ps4rf_daemon *d, const char *session_id)
{
    d_copy(d->seen[d->seen_head], sizeof(d->seen[0]), session_id);
    d->seen_head = (d->seen_head + 1u) % PS4RF_DAEMON_SESSION_IDS;
    if (d->seen_count < PS4RF_DAEMON_SESSION_IDS) d->seen_count++;
    if (d->rep.session_id_count < PS4RF_DAEMON_SESSION_IDS) {
        d_copy(d->rep.session_ids[d->rep.session_id_count], sizeof(d->rep.session_ids[0]),
               session_id);
        d->rep.session_id_count++;
    }
}

/* §18: one record per session that actually became one, appended in order and bounded. A session
 * record says what the session was, what it did, what it held and how it ended -- the second half of
 * the two-level evidence the report carries; `lifetime_id` says which lifetime produced it. */
static void daemon_session_record_add(ps4rf_daemon *d, const ps4rf_rt *rt, const char *bye,
                                      int boot_recheck_ok)
{
    ps4rf_daemon_session_record *rec;
    unsigned index;

    if (rt == NULL || rt->session_id[0] == '\0') return;      /* an attempt, not a session */
    if (d->rep.session_record_count >= PS4RF_DAEMON_SESSION_RECORDS) {
        /* the list is bounded: drop the oldest record, keep the newest ones */
        size_t keep = sizeof(d->rep.session_records[0]) * (PS4RF_DAEMON_SESSION_RECORDS - 1u);
        memmove(&d->rep.session_records[0], &d->rep.session_records[1], keep);
        index = PS4RF_DAEMON_SESSION_RECORDS - 1u;
    } else {
        index = d->rep.session_record_count;
        d->rep.session_record_count++;
    }
    rec = &d->rep.session_records[index];
    memset(rec, 0, sizeof(*rec));
    d_copy(rec->session_id, sizeof(rec->session_id), rt->session_id);
    d_copy(rec->bye, sizeof(rec->bye), (bye != NULL) ? bye : "");
    d_copy(rec->cleanup_state, sizeof(rec->cleanup_state),
           ps4rf_res_cleanup_state(&rt->res));
    rec->held_after_cleanup = ps4rf_res_live(&rt->res);
    rec->reaped = rt->cleanup_reaped;
    rec->requests = ps4rf_ev_count(&rt->ev);
    rec->provider_entries = rt->ev.provider_entries_total;
    rec->deferred = rt->ev.deferred_total;
    rec->invalid = rt->ev.invalid_total;
    rec->violations = rt->ev.violations;
    rec->recovery_at_start = rt->recovery_required ? 1 : 0;
    rec->boot_recheck_ok = boot_recheck_ok ? 1 : 0;
    d->rep.session_records_total++;
}

/* ------------------------------------------------------------------- transport (dial out) */

static int daemon_dial(ps4rf_daemon *d, unsigned attempts)
{
    const ps4rf_platform *pf = ps4rf_platform_get();
    if (d->cfg.host == NULL || d->cfg.port == 0u || pf->net_connect == NULL) return -1;
    return pf->net_connect(d->cfg.host, d->cfg.port, (int)(attempts == 0u ? 1u : attempts));
}

/* §6: bounded reconnect. `base` is the configured first pause, doubled per consecutive miss and
 * clamped to the configured cap; both ends have hard floors/ceilings so a misconfiguration cannot
 * produce a busy loop (0 us) or an unbounded wait. A missing controller is *not* an integrity
 * event: it touches neither the boot inputs, nor the recovery flag, nor any capability state. */
static unsigned daemon_backoff_us(const ps4rf_daemon *d)
{
    unsigned base = (d->cfg.idle_pause_us > 0u) ? d->cfg.idle_pause_us : PS4RF_DAEMON_BACKOFF_MIN_US;
    unsigned cap = (d->cfg.backoff_max_us > 0u) ? d->cfg.backoff_max_us
                                                : PS4RF_DAEMON_BACKOFF_MAX_US;
    unsigned shift = (d->rep.dial_misses > 0u) ? (d->rep.dial_misses - 1u) : 0u;
    unsigned long long pause;
    if (cap < PS4RF_DAEMON_BACKOFF_MIN_US) cap = PS4RF_DAEMON_BACKOFF_MIN_US;
    if (shift > 20u) shift = 20u;                  /* bounded shift: no overflow, no UB */
    pause = (unsigned long long)base << shift;
    if (pause > (unsigned long long)cap) pause = (unsigned long long)cap;
    if (pause < (unsigned long long)PS4RF_DAEMON_BACKOFF_MIN_US) {
        pause = (unsigned long long)PS4RF_DAEMON_BACKOFF_MIN_US;
    }
    return (unsigned)pause;
}

static int daemon_write_all(int fd, const char *buf, size_t len)
{
    const ps4rf_platform *pf = ps4rf_platform_get();
    size_t off = 0u;
    while (off < len) {
        int rc = pf->net_send(fd, buf + off, len - off);
        if (rc > 0) {
            off += (size_t)rc;
            continue;
        }
        if (rc == -1) {
            if (pf->sleep_us != NULL) pf->sleep_us(1000u);
            continue;
        }
        return -1;
    }
    return 0;
}

/* §13: the busy notice goes on the *connection that was refused*, before any handshake. It is
 * unauthenticated (there is no session) and therefore carries no authority -- it exists so a
 * controller learns why the connection closed instead of seeing a silent close. */
static void daemon_send_busy(ps4rf_daemon *d, int fd)
{
    char notice[PS4RF_DAEMON_BUSY_MAX + 2u];
    size_t n = ps4rf_daemon_busy_notice(d, notice, PS4RF_DAEMON_BUSY_MAX);
    if (n == 0u) return;
    notice[n] = '\n';
    notice[n + 1u] = '\0';
    (void)daemon_write_all(fd, notice, n + 1u);
}

/* W15R3 (owner D5 fix): the lifetime's single boot-binding measurement.
 *
 * It runs at most once per agent lifetime and only from daemon_checkpoint(), i.e. inside a session
 * that is already handshaken and has answered READY with its sealed attestation: the control plane
 * is up before any privileged call of the lifetime happens, and neither a failure nor a stall here
 * can keep the agent from dialing or end it. The outcome is cached for the lifetime: OK fills the
 * declared instant, every other status leaves the lifetime UNRESOLVED -- and the privileged
 * provider refuses on that state. It never retries, never re-arms and never guesses a value.
 * (The "never returns" case is deliberately not watched by a timer: the owner's rule is that it
 * can only ever occur here, after the control plane exists, and that the session may stall -- no
 * watchdog framework.) */
/* W15R3 (owner D5 fix): publish the lifetime's boot-binding outcome into the *live* session, so
 * the session that is open while the measurement runs can report it (the provider reads the
 * session runtime, nothing else). The daemon owns these values for the whole lifetime. */
static void daemon_boot_publish(ps4rf_daemon *d)
{
    ps4rf_rt *rt = (ps4rf_rt *)d->rt_current;
    if (rt == NULL) return;
    rt->boot_status = d->rep.boot_inputs;
    rt->boot_detail = d->boot_detail[0] != '\0' ? d->boot_detail : NULL;
    rt->boot_sec = d->rep.boot_sec;
    rt->boot_usec = d->rep.boot_usec;
}

static int daemon_boot_measure(ps4rf_daemon *d)
{
    if (d->boot_measured) return d->boot_cached;
    d->boot_measured = 1;                 /* one attempt per lifetime, whatever the outcome */
    if (d->boot_cached && d->boot_sec != 0ll) {
        /* The platform route already bound this lifetime (the W11 sysctl route answered at
         * bootstrap -- the case on a build where that hook exists). It is the same fact, so the
         * privileged gate is satisfied and nothing is measured a second time. On the console this
         * branch never runs: FW 13.52's userland sysctl route is dead, so the kread path below is
         * the one that measures. */
#ifdef PS4RF_TARGET_BOOTBIND
        ps4rf_kread_boot_record_platform();
        ps4rf_trace_marker("B09 boot binding MEASURED platform route");
#endif
        d->boot_detail[0] = '\0';
        daemon_boot_publish(d);
        return 1;
    }
#ifdef PS4RF_TARGET_BOOTBIND
    {
        long long sec = 0ll;
        long long usec = 0ll;
        int status;

        ps4rf_trace_marker("B08 before boot binding");
        status = ps4rf_kread_boot_binding(&g_boot_binding_info, &sec, &usec);
        if (status == PS4RF_KREAD_BOOT_OK) {
            d->boot_sec = sec;
            d->boot_usec = usec;
            d->rep.boot_sec = sec;
            d->rep.boot_usec = usec;
            d->boot_cached = 1;
            d->boot_detail[0] = '\0';
            d_copy(d->rep.boot_inputs, sizeof(d->rep.boot_inputs), "MEASURED");
            ps4rf_trace_marker("B09 boot binding MEASURED");
            daemon_boot_publish(d);
            return 1;
        }
        d_copy(d->boot_detail, sizeof(d->boot_detail), ps4rf_kread_boot_status_name(status));
        ps4rf_trace_marker(ps4rf_kread_boot_status_name(status));
    }
#endif
    d->boot_cached = 0;
    d->boot_sec = 0ll;
    d->boot_usec = 0ll;
    d->rep.boot_sec = 0ll;
    d->rep.boot_usec = 0ll;
    d_copy(d->rep.boot_inputs, sizeof(d->rep.boot_inputs), "UNRESOLVED");
    daemon_boot_publish(d);
    return 0;
}

/* Track A (W16 option B): the lifetime's fixed window step -- exactly ONE privileged read per
 * session, never more, and nothing here judges a byte.
 *
 * Session 1 spends its single transition on the boot binding above; every later session reads one
 * window of the fixed set: first the five binding fingerprints (STRICT, 16 bytes), then the six
 * observation windows (STRUCTURAL_ONLY, each with the row's own length). Both cursors belong to the
 * lifetime -- a session re-arm never touches them -- so no window is read twice and a failed one is
 * never retried. A lifetime without an established binding reads nothing: the report stays empty,
 * so the host can tell "nothing read" from "read". The host is the judge: it compares the binding
 * windows against the pinned image and records the observations.
 */
static void daemon_window_report_clear(ps4rf_daemon *d)
{
    d->window_kind[0] = '\0';
    d->window_status[0] = '\0';
    d->window_hex[0] = '\0';
    d->window_sha256[0] = '\0';
    d->window_index = 0u;
    d->window_len = 0u;
#ifdef PS4RF_TARGET_BOOTBIND
    d->window_cursor = ps4rf_kread_identity_cursor() + ps4rf_kread_obs_cursor();
    d->window_count = (unsigned)PS4RF_KREAD_BINDING_WINDOW_COUNT +
                      (unsigned)PS4RF_KREAD_OBS_WINDOW_COUNT;
#else
    d->window_cursor = 0u;
    d->window_count = 0u;
#endif
}

static void daemon_window_step(ps4rf_daemon *d)
{
#ifdef PS4RF_TARGET_BOOTBIND
    const uint8_t *bytes = 0;
    const uint8_t *sha = 0;
    uint32_t len = 0u;
    uint32_t sha_status = PS4RF_KREAD_SHA_NOT_MEASURED;

    daemon_window_report_clear(d);
    if (ps4rf_kread_identity_cursor() < (uint32_t)PS4RF_KREAD_BINDING_WINDOW_COUNT) {
        int status = ps4rf_kread_identity_next(&g_window_info, &d->window_identity);
        d_copy(d->window_kind, sizeof(d->window_kind), "BINDING");
        d_copy(d->window_status, sizeof(d->window_status),
               ps4rf_kread_identity_status_name(status));
        d->window_index = d->window_identity.index;
        d->window_len = d->window_identity.copied_len;
        bytes = d->window_identity.bytes;
        len = d->window_identity.copied_len;
        sha_status = d->window_identity.sha256_status;
        sha = d->window_identity.sha256;
    } else if (ps4rf_kread_obs_cursor() < (uint32_t)PS4RF_KREAD_OBS_WINDOW_COUNT) {
        int status = ps4rf_kread_obs_next(&g_window_info, &d->window_observation);
        d_copy(d->window_kind, sizeof(d->window_kind), "OBSERVATION");
        d_copy(d->window_status, sizeof(d->window_status),
               ps4rf_kread_obs_status_name(status));
        d->window_index = d->window_observation.index;
        d->window_len = d->window_observation.copied_len;
        bytes = d->window_observation.bytes;
        len = d->window_observation.copied_len;
        sha_status = d->window_observation.sha256_status;
        sha = d->window_observation.sha256;
    } else {
        /* Both sets are spent for this lifetime: this session reads nothing and says so. The
         * cursor in the report tells the host that the whole set was walked. */
        d_copy(d->window_status, sizeof(d->window_status), "SET_COMPLETE");
    }

    if (len > 0u && bytes != 0) {
        ps4rf_kread_hex(d->window_hex, sizeof(d->window_hex), bytes, len);
    }
    if (sha_status == PS4RF_KREAD_SHA_MEASURED && sha != 0) {
        ps4rf_kread_hex(d->window_sha256, sizeof(d->window_sha256), sha, 32u);
    }
#else
    (void)d;
#endif
}

/* Publish the (per session) window report into the *live* session, so the session.status response
 * of the session the step ran in carries it. The strings are the daemon's own buffers; the session
 * only points at them. */
static void daemon_window_publish(ps4rf_daemon *d)
{
    ps4rf_rt *rt = (ps4rf_rt *)d->rt_current;
    if (rt == NULL) return;
    rt->window_kind = d->window_kind;
    rt->window_status = d->window_status;
    rt->window_hex = d->window_hex;
    rt->window_sha256 = d->window_sha256;
    rt->window_index = d->window_index;
    rt->window_len = d->window_len;
    rt->window_cursor = d->window_cursor;
    rt->window_count = d->window_count;
}

/* The resident checkpoint. Installed for the duration of a run; the session loop calls it at
 * the top of every iteration. It can only *refuse* or *end* -- it dispatches no operation, it
 * reads no request and it holds no request state, so it cannot become an operation trigger. */
static int daemon_checkpoint(void *ctx)
{
    ps4rf_daemon *d = (ps4rf_daemon *)ctx;
    const ps4rf_rt *rt = d->rt_current;
    int fd;

    /* §4/§17: a session id that was already served is a replayed handshake. End the session
     * before a single request is served; the run then ends with PROTOCOL_CORRUPTION. */
    if (!d->session_id_checked && rt != NULL && rt->session_id[0] != '\0') {
        d->session_id_checked = 1;
        if (daemon_session_id_seen(d, rt->session_id)) {
            daemon_session_id_record(d, rt->session_id);
            d->session_id_replayed = 1;
            return 1;
        }
        daemon_session_id_record(d, rt->session_id);
    }

    /* W15R3 (owner D5 fix): this session's control plane is up -- the loop this checkpoint runs in
     * starts only after the handshake and the sealed READY. One breadcrumb per session, then the
     * lifetime's one boot-binding measurement: it happens here and nowhere earlier, a failure
     * leaves the lifetime UNRESOLVED (the privileged provider then refuses) and it never ends the
     * daemon. The host's own per-session comparison of the announced instant is the other half of
     * the binding rule. */
    if (!d->session_marked) {
        d->session_marked = 1;
        ps4rf_trace_marker("B07 control session established");
    }
    if (!d->window_marked) {
        d->window_marked = 1;
        if (!d->boot_measured) {
            (void)daemon_boot_measure(d);
        } else if (d->boot_cached) {
            daemon_window_step(d);
        }
        daemon_window_publish(d);
    }

    /* §13: a further connection attempt that reaches the agent while this session is active is
     * refused on that connection -- once per session, so that the next attempt after the
     * session is served again. */
    if (!d->cfg.refuse_while_busy || d->busy_refused_this_session) return 0;
    if (ps4rf_daemon_accept(d) != PS4RF_DAEMON_SESSION_BUSY) return 0;
    fd = daemon_dial(d, 1u);
    if (fd < 0) return 0;                      /* no controller offering: nothing to refuse */
    daemon_send_busy(d, fd);
    ps4rf_platform_get()->net_close(fd);
    d->busy_refused_this_session = 1;
    d->rep.busy_refusals++;
    return 0;
}

/* --------------------------------------------------------------------------- §2 lifecycle */

void ps4rf_daemon_init(ps4rf_daemon *d, const ps4rf_daemon_config *cfg)
{
    memset(d, 0, sizeof(*d));
    if (cfg != NULL) d->cfg = *cfg;
    d->state = PS4RF_DAEMON_STATE_BOOTSTRAP;
    d_copy(d->rep.state, sizeof(d->rep.state), d->state);
    d_copy(d->rep.stop, sizeof(d->rep.stop), PS4RF_DAEMON_EXIT_NONE);
    d_copy(d->rep.exit_reason, sizeof(d->rep.exit_reason), PS4RF_DAEMON_EXIT_NONE);
    d_copy(d->rep.boot_inputs, sizeof(d->rep.boot_inputs), "UNRESOLVED");
    /* §15: this process *is* a resident agent, so the lifetime-level operations are served here. */
    ps4rf_agent_set_resident(1);
}

const char *ps4rf_daemon_state(const ps4rf_daemon *d)
{
    return d->state;
}

const char *ps4rf_daemon_exit_reason(const ps4rf_daemon *d)
{
    return (d != NULL) ? d->rep.exit_reason : PS4RF_DAEMON_EXIT_NONE;
}

/* §11/W14: the boot-wide recovery state, established once per agent lifetime. It is raised by a
 * session (see ps4rf_daemon_session_recovery_required) or is present from the start -- a boot that
 * comes up in recovery, e.g. because an earlier, non-resident run ended with an unknown outcome.
 * Only a real boot/agent lifecycle reset clears it: this runs once per lifetime and nothing in the
 * session path ever writes 0 here. */
static void daemon_boot_recovery(ps4rf_daemon *d)
{
    if (d == NULL) return;
    if (d->cfg.initial_recovery) {
        d->recovery_required = 1;
        d->rep.recovery_required = 1;
        d->rep.recovery_transitions++;
        d_copy(d->rep.recovery_source, sizeof(d->rep.recovery_source), "BOOT");
    } else {
        d_copy(d->rep.recovery_source, sizeof(d->rep.recovery_source), "NONE");
    }
}

int ps4rf_daemon_bootstrap(ps4rf_daemon *d)
{
    const ps4rf_platform *pf = ps4rf_platform_get();
    long long sec = 0ll;
    long long usec = 0ll;

    d->boot_cached = 0;
    d->boot_measured = 0;
    d->boot_sec = 0ll;
    d->boot_usec = 0ll;
    d_copy(d->rep.boot_inputs, sizeof(d->rep.boot_inputs), "UNRESOLVED");

#ifdef PS4RF_TARGET_BOOTID
    {
        /* One bootstrap per boot: the full read-only boot binding is collected once. A build
         * that compiles the binding and cannot form it fails closed here. */
        ps4rf_boot_info info;
        int run_status = ps4rf_boot_collect(&info);
        if (run_status != PS4RF_BOOT_RUN_OK) {
            d->rep.bootstrap_failures++;
            return -1;
        }
        sec = info.sec1;
        usec = info.usec1;
        d->boot_cached = 1;
        d_copy(d->rep.boot_inputs, sizeof(d->rep.boot_inputs), "MEASURED");
    }
#else
    (void)pf;
    if (pf->boot_timeval != NULL && pf->boot_timeval(&sec, &usec) == PS4RF_TF_OK) {
        d->boot_cached = 1;
        d_copy(d->rep.boot_inputs, sizeof(d->rep.boot_inputs), "MEASURED");
    }
#ifdef PS4RF_TARGET_BOOTBIND
    /* W15R3 (owner D5 fix, W15-R2-D5 BOOT_BINDING_BLOCKS_CONTROL_PLANE): the boot binding is NOT
     * measured here any more. The privileged measurement used to run before the first dial, which
     * made the availability of the control plane depend on a privileged call: a block or a fault
     * there produced exactly the attempt-1 observation (no dial, not a single packet). The
     * measurement now runs once per agent lifetime inside the first session that is already
     * handshaken and has answered READY -- see daemon_boot_measure() and its one caller in
     * daemon_checkpoint(). Nothing in this bootstrap can block or refuse: the platform hook above
     * is the only source used here, and where it cannot answer the lifetime simply stays
     * UNRESOLVED until a session measures it. */
#endif
#endif
    d->boot_sec = sec;
    d->boot_usec = usec;
    d->rep.boot_sec = sec;
    d->rep.boot_usec = usec;
    /* §18: the lifetime identity. Plain decimal facts -- the platform, the boot instant this
     * lifetime was bound to and the monotonic instant it started at -- because it has to be
     * printable on a console and stable for exactly as long as this agent lifetime lasts. Every
     * session record in the report belongs to this id. */
    {
        size_t at = 0u;
        d->rep.lifetime_id[0] = '\0';
        at = d_append(d->rep.lifetime_id, sizeof(d->rep.lifetime_id), at, "LIFE-");
        at = d_append(d->rep.lifetime_id, sizeof(d->rep.lifetime_id), at, ps4rf_agent_platform());
        at = d_append(d->rep.lifetime_id, sizeof(d->rep.lifetime_id), at, "-");
        at = d_append_u64(d->rep.lifetime_id, sizeof(d->rep.lifetime_id), at,
                          (unsigned long long)(sec < 0ll ? 0ll : sec));
        at = d_append(d->rep.lifetime_id, sizeof(d->rep.lifetime_id), at, ".");
        at = d_append_u64(d->rep.lifetime_id, sizeof(d->rep.lifetime_id), at,
                          (unsigned long long)(usec < 0ll ? 0ll : usec));
        at = d_append(d->rep.lifetime_id, sizeof(d->rep.lifetime_id), at, "-");
        (void)d_append_u64(d->rep.lifetime_id, sizeof(d->rep.lifetime_id), at,
                           (unsigned long long)((pf->now_us != NULL) ? pf->now_us() : 0u));
    }
    d->rep.lifetime_start_sec = sec;
    daemon_boot_recovery(d);
    return 0;
}

int ps4rf_daemon_boot_recheck(ps4rf_daemon *d, char *detail, size_t detail_cap)
{
    const ps4rf_platform *pf = ps4rf_platform_get();
    long long sec = 0ll;
    long long usec = 0ll;

    if (!d->boot_cached) return 0;              /* nothing cached: nothing to re-check */
    if (pf->boot_timeval == NULL ||
        pf->boot_timeval(&sec, &usec) != PS4RF_TF_OK) {
        /* W15R3: this platform cannot re-read the boot inputs (FW 13.52: the userland sysctl route
         * is dead -- that is what the W11.1 diagnostics measured). A re-check that cannot read is
         * not evidence of a change, and refusing the session for it would put the control plane
         * back behind a platform shortcoming (the D5 failure class). The *detected* change below
         * still refuses the session, and the live host compares the announced instant against the
         * approved binding for every session of the lifetime. */
        d_copy(detail, detail_cap, "boot inputs cannot be re-read on this platform");
        return 0;
    }
    if (sec != d->boot_sec || usec != d->boot_usec) {
        d_copy(detail, detail_cap, "boot inputs changed under the resident agent");
        return -1;
    }
    return 0;
}

ps4rf_daemon_decision ps4rf_daemon_accept(const ps4rf_daemon *d)
{
    if (d->active) return PS4RF_DAEMON_SESSION_BUSY;
    if (d_eq(d->state, PS4RF_DAEMON_STATE_RESIDENT_IDLE)) return PS4RF_DAEMON_ACCEPT;
    return PS4RF_DAEMON_SESSION_BUSY;
}

/* ------------------------------------------------------------------- §3 exit condition map */

/* "RECOVERY_REQUIRED with an unsafe agent state" (the only form of RECOVERY_REQUIRED that ends
 * the agent): a recorded violation or an in-flight request. The resource demand of §10 is
 * checked separately and before, because it holds for *every* session end. */
/* §3/§9: the states that make an *exit* mandatory are the ones the agent cannot describe. A
 * session that broke a protocol obligation left artifacts nobody can trust; unfinished work
 * (an answered-but-undelivered mutation, objects that would not come back) is *known* state, so it
 * raises the boot-wide flag and the agent keeps serving the recovery-safe paths instead of exiting.
 * A plain lost transport is neither. */
static int agent_state_is_unsafe(const ps4rf_rt *rt)
{
    if (rt->ev.violations > 0u) return 1;
    return 0;
}

int ps4rf_daemon_session_recovery_required(const ps4rf_rt *rt, const char *cleanup)
{
    if (rt == NULL) return 1;                     /* no session state to judge: fail closed */
    if (rt->ev.violations > 0u) return 1;         /* a protocol obligation was broken */
    if (rt->recovery_required != 0) return 1;     /* raised inside the session for a real reason */
    if (rt->inflight != 0u) return 1;             /* a request was still being handled */
    if (rt->undelivered_mutations > 0u) return 1; /* a mutation happened, the host never heard */
    if (rt->cleanup_status != 0) return 1;        /* the teardown could not hand the set back */
    if (ps4rf_res_live(&rt->res) > 0u) return 1;  /* objects survive the session */
    if (cleanup == NULL || d_ne(cleanup, PS4RF_CLEANUP_COMPLETE)) return 1;
    /* §5: a lost transport on its own is *not* a recovery condition. Nothing was in flight, the
     * session handed its resources back empty and nothing was left undelivered -- so the peer that
     * disappeared merely ended a session, and the agent goes back to RESIDENT_IDLE with the
     * boot-wide flag untouched. The session-level BYE reason is a host-side signal, not a boot
     * state: a plain EOF must never park the whole boot in recovery. */
    return 0;
}

static const char *daemon_exit_for(ps4rf_daemon *d, ps4rf_agent_result result, const char *bye,
                                   const ps4rf_rt *rt, const char *cleanup,
                                   char *detail, size_t detail_cap)
{
    int recovery = ps4rf_daemon_session_recovery_required(rt, cleanup);
    if (recovery && !d->recovery_required) {
        d->rep.recovery_transitions++;         /* the session is what raised it */
        d_copy(d->rep.recovery_source, sizeof(d->rep.recovery_source), "SESSION");
    }
    if (recovery) {
        d->rep.recovery_required = 1;          /* boot-wide (§11), never reset automatically */
        d->recovery_required = 1;
    }

    /* §10/§2: the session teardown runs before the BYE, so a session end must leave the set
     * empty. What remains here is bookkeeping: a session whose runtime never got a session id
     * while its result claims it ran is corrupt state -- that is an internal integrity failure
     * (§3), and it is the only cleanup-related way to end the agent. A *leftover object* is a
     * recovery condition (§11, item 5), not an exit: the boot-wide flag blocks mutating work from
     * the next session on, and the agent stays available for the recovery-safe paths. */
    if (result == PS4RF_AGENT_RAN && rt->session_id[0] == '\0') {
        d_copy(detail, detail_cap, "a session ran without a session id");
        return PS4RF_DAEMON_EXIT_INTEGRITY;
    }

    switch (result) {
    case PS4RF_AGENT_RAN:
        /* §15: an authenticated admin shutdown is one of the four exit conditions. Nothing else
         * ends the lifetime on a *clean* session end, and this one is a decision the controller
         * made, not a fault: the session is over, its resources are back, the report is the
         * evidence, and the exit is clean. */
        if (bye != NULL && d_eq(bye, "ADMIN_SHUTDOWN")) {
            d_copy(detail, detail_cap, "authenticated admin shutdown");
            return PS4RF_DAEMON_EXIT_ADMIN;
        }
        if (d->session_id_replayed) {
            d_copy(detail, detail_cap, "session id replayed");
            return PS4RF_DAEMON_EXIT_PROTOCOL;
        }
        if (recovery && agent_state_is_unsafe(rt)) {
            d_copy(detail, detail_cap, "RECOVERY_REQUIRED with an unsafe agent state");
            return PS4RF_DAEMON_EXIT_RECOVERY;
        }
        if (recovery) d_copy(detail, detail_cap, "RECOVERY_REQUIRED, agent state sound");
        return PS4RF_DAEMON_EXIT_NONE;

    case PS4RF_AGENT_IO_FAILED:
        /* A lost transport is session-scoped, not an exit condition (§3): the resident agent
         * keeps its boot-wide recovery flag if one was raised and stays available. */
        d_copy(detail, detail_cap, "transport lost, session scoped");
        return PS4RF_DAEMON_EXIT_NONE;

    case PS4RF_AGENT_HELLO_FAILED:
    case PS4RF_AGENT_HANDSHAKE_FAILED:
        /* §8/§15: an attempt that never became a session is *refused*, not fatal. A wrong PSK, a
         * truncated answer, a port scanner or a pre-handshake "shutdown" cannot corrupt the target,
         * so none of them may be able to end the agent -- an unauthenticated peer with a kill switch
         * is exactly what a resident agent must not have. The attempt is counted
         * (`sessions_failed`), the agent stays resident, and its state is exactly what it was.
         * Frame-level corruption *inside* an authenticated session is a different thing and stays a
         * fatal exit below. */
        d_copy(detail, detail_cap, "an attempt without a session was refused");
        return PS4RF_DAEMON_EXIT_NONE;

    case PS4RF_AGENT_PROTOCOL_FAILED:
        d_copy(detail, detail_cap, bye != NULL ? bye : "protocol failure");
        return PS4RF_DAEMON_EXIT_PROTOCOL;

    case PS4RF_AGENT_READY_FAILED:
    case PS4RF_AGENT_ATTEST_FAILED:
    case PS4RF_AGENT_BOOT_FAILED:
    case PS4RF_AGENT_BOOTREAD_FAILED:
    case PS4RF_AGENT_KREAD_FAILED:
        d_copy(detail, detail_cap, bye != NULL ? bye : "fixed agent step failed");
        return PS4RF_DAEMON_EXIT_INTEGRITY;

    default:
        d_copy(detail, detail_cap, "unmapped agent result");
        return PS4RF_DAEMON_EXIT_INTEGRITY;    /* fail closed: never a silent continue */
    }
}

/* ------------------------------------------------------------------------------- one session */

static int daemon_run_session(ps4rf_daemon *d, int fd)
{
    ps4rf_rt rt;
    char bye[24];
    char detail[96];
    ps4rf_agent_result result;
    const char *cleanup;
    const char *exit_reason;

    detail[0] = '\0';
    bye[0] = '\0';
    d->active = 1;
    d->busy_refused_this_session = 0;
    d->session_id_checked = 0;
    d->session_id_replayed = 0;
    d->session_marked = 0;
    d->window_marked = 0;               /* Track A: the fixed window step is decided per session */
    daemon_window_report_clear(d);      /* ... and this session has read nothing yet */
    d_set_state(d, PS4RF_DAEMON_STATE_SESSION_ACTIVE);

    /* §5: the boot inputs cached at bootstrap are re-read for every session; a change means the
     * cache no longer describes this boot and the session is refused before any frame. */
    if (ps4rf_daemon_boot_recheck(d, detail, sizeof(detail)) != 0) {
        d->active = 0;
        d_set_state(d, PS4RF_DAEMON_STATE_SESSION_CLEANUP);
        d->rep.sessions_failed++;
        return daemon_finish(d, PS4RF_DAEMON_EXIT_INTEGRITY, detail);
    }

    memset(&rt, 0, sizeof(rt));
    rt.lifetime_s = d->cfg.lifetime_s;
    rt.idle_s = d->cfg.idle_s;
    /* W15R3: the session announces (and the status reports) the lifetime's current boot-binding
     * state -- UNRESOLVED until the checkpoint in this very session has measured it. */
    rt.boot_status = d->rep.boot_inputs;
    rt.boot_detail = d->boot_detail[0] != '\0' ? d->boot_detail : NULL;
    rt.boot_sec = d->rep.boot_sec;
    rt.boot_usec = d->rep.boot_usec;
    d->rt_current = &rt;
    daemon_window_publish(d);           /* Track A: the session points at the daemon's report */
    {
        /* §14: every session announces the same agent/boot identity and its own fresh nonce.
         * The boot id stays NULL on the agent side (W11: the digest is a host-side derivation);
         * the raw measured instant and its status are announced instead. */
        ps4rf_agent_identity id;
        int measured = d_eq(d->rep.boot_inputs, "MEASURED");
        ps4rf_agent_identity_init(&id, d->cfg.build_id, NULL,
                                  measured ? d->rep.boot_sec : -1ll,
                                  measured ? d->rep.boot_usec : -1ll,
                                  d->rep.boot_inputs, d->recovery_required);
        result = ps4rf_agent_run(fd, d->cfg.psk, d->cfg.label, d->cfg.context, d->cfg.provider_id,
                                 &id, &rt, bye, sizeof(bye));
    }
    d->rt_current = NULL;
    d->active = 0;
    d_set_state(d, PS4RF_DAEMON_STATE_SESSION_CLEANUP);
    d_copy(d->rep.last_bye, sizeof(d->rep.last_bye), bye);
    daemon_session_record_add(d, &rt, bye, 1);   /* the re-check above passed for this session */

    /* A session counts as served when a session id was negotiated; an attempt that never got
     * that far counts as failed. Both are reported, neither is hidden. */
    if (rt.session_id[0] != '\0') d->rep.sessions_served++;
    else d->rep.sessions_failed++;

    cleanup = ps4rf_res_cleanup_state(&rt.res);
    /* §2/§10/§11: the session's own teardown has already run (inside the session, before the BYE).
     * What it could not hand back is recorded, raises the boot-wide recovery flag and keeps the
     * agent resident -- the flag, not an exit, is what stops mutating work from here on. */
    d->rep.cleanup_reaped = rt.cleanup_reaped;
    d->rep.undelivered_responses += rt.undelivered_responses;
    d->rep.undelivered_mutations += rt.undelivered_mutations;
    d->rep.held_after_cleanup = ps4rf_res_live(&rt.res);
    d_copy(d->rep.cleanup_state, sizeof(d->rep.cleanup_state), cleanup);
    if (rt.cleanup_status != 0 || d->rep.held_after_cleanup > 0u ||
        cleanup == NULL || d_ne(cleanup, PS4RF_CLEANUP_COMPLETE)) {
        d->recovery_required = 1;
        d->rep.recovery_required = 1;
        d->rep.cleanup_refusals++;
    }
    exit_reason = daemon_exit_for(d, result, bye, &rt, cleanup, detail, sizeof(detail));
    return daemon_finish(d, exit_reason, detail);
}

/* ------------------------------------------------------------------------------------ run */

int ps4rf_daemon_run(ps4rf_daemon *d)
{
    const ps4rf_platform *pf = ps4rf_platform_get();

    if (ps4rf_daemon_bootstrap(d) != 0) {
        /* The exit reason first, the stop reason after: a failed bootstrap is reported as
         * BOOTSTRAP_FAILED, not as a generic exit-condition stop. */
        (void)daemon_finish(d, PS4RF_DAEMON_EXIT_INTEGRITY,
                            "bootstrap could not establish the boot inputs");
        d_copy(d->rep.stop, sizeof(d->rep.stop), PS4RF_DAEMON_STOP_BOOTSTRAP);
        return 1;
    }
    d_set_state(d, PS4RF_DAEMON_STATE_RESIDENT_IDLE);
    ps4rf_agent_set_checkpoint(daemon_checkpoint, d);

    for (;;) {
        int fd;

        if (d->cfg.max_sessions > 0u && d->rep.attempts >= d->cfg.max_sessions) {
            d_copy(d->rep.stop, sizeof(d->rep.stop), PS4RF_DAEMON_STOP_BUDGET);
            d_set_state(d, PS4RF_DAEMON_STATE_EXITED);
            ps4rf_agent_set_checkpoint(NULL, NULL);
            return 0;
        }

        d_set_state(d, PS4RF_DAEMON_STATE_RESIDENT_IDLE);
        if (!d->dial_marked) {
            d->dial_marked = 1;
            ps4rf_trace_marker("B03 before first dial");
        }
        fd = daemon_dial(d, d->cfg.dial_attempts);
        if (fd < 0) {
            d->rep.dial_misses++;
            d->rep.dial_misses_total++;
            if (d->cfg.idle_rounds > 0u && d->rep.dial_misses >= d->cfg.idle_rounds) {
                d_copy(d->rep.stop, sizeof(d->rep.stop), PS4RF_DAEMON_STOP_NODIAL);
                d_set_state(d, PS4RF_DAEMON_STATE_EXITED);
                ps4rf_agent_set_checkpoint(NULL, NULL);
                return 0;
            }
            d->rep.dial_backoff_us = daemon_backoff_us(d);
            if (pf->sleep_us != NULL) pf->sleep_us(d->rep.dial_backoff_us);
            continue;
        }
        d->rep.dial_misses = 0u;              /* a served session ends the backoff streak */

        if (ps4rf_daemon_accept(d) != PS4RF_DAEMON_ACCEPT) {
            /* Defensive: the gate is the only way into a session. Reaching this branch means the
             * state machine would have had two sessions in flight -- the attempt is refused on
             * its connection and the run continues (W14 harness: force_accepted_state). */
            daemon_send_busy(d, fd);
            pf->net_close(fd);
            continue;
        }

        d->rep.attempts++;
        if (daemon_run_session(d, fd) != 0) {
            pf->net_close(fd);
            ps4rf_agent_set_checkpoint(NULL, NULL);
            return 1;
        }
        pf->net_close(fd);
    }
}

/* --------------------------------------------------------------------------- report / notice */

size_t ps4rf_daemon_busy_notice(const ps4rf_daemon *d, char *out, size_t cap)
{
    jval *obj = jval_new_object();
    char *text = NULL;
    size_t len = 0u;
    const char *err = NULL;

    if (obj == NULL || out == NULL || cap == 0u) {
        jval_free(obj);
        return 0u;
    }
    /* No session id, no key material, no host input: a refusal notice is not a status report.
     * `active_sessions` is 1 in every refusal path -- that is what makes it a refusal. */
    if (jval_obj_set(obj, "active_sessions", jval_new_int(d->active ? 1 : 0)) != 0 ||
        jval_obj_set(obj, "agent_version",
                     jval_new_string(PS4RF_DAEMON_BUSY_VERSION)) != 0 ||
        jval_obj_set(obj, "build_id",
                     jval_new_string(d->cfg.build_id != NULL ? d->cfg.build_id : "")) != 0 ||
        jval_obj_set(obj, "msg", jval_new_string(PS4RF_DAEMON_BUSY_MSG)) != 0 ||
        jval_obj_set(obj, "sessions_served",
                     jval_new_int((int64_t)d->rep.sessions_served)) != 0 ||
        jval_obj_set(obj, "state", jval_new_string(d->state != NULL ? d->state : "")) != 0) {
        jval_free(obj);
        return 0u;
    }
    if (ps4rf_canonical_bytes(obj, &text, &len, &err) != PS4RF_OK) {
        jval_free(obj);
        return 0u;
    }
    jval_free(obj);
    if (text == NULL || len + 1u > cap) {
        free(text);
        return 0u;
    }
    memcpy(out, text, len);
    out[len] = '\0';
    free(text);
    return len;
}

size_t ps4rf_daemon_report_json(const ps4rf_daemon *d, char *out, size_t cap)
{
    jval *obj = jval_new_object();
    jval *ids = jval_new_array();
    char *text = NULL;
    size_t len = 0u;
    const char *err = NULL;
    unsigned i;
    int ok = 1;
    const char *reason = d->rep.exit_reason[0] != '\0' ? d->rep.exit_reason : PS4RF_DAEMON_EXIT_NONE;

    if (obj == NULL || ids == NULL || out == NULL || cap == 0u) {
        jval_free(obj);
        jval_free(ids);
        return 0u;
    }
    for (i = 0u; i < d->rep.session_id_count; i++) {
        if (jval_arr_add(ids, jval_new_string(d->rep.session_ids[i])) != 0) ok = 0;
    }
    /* The array is handed over with its own set; on any failure below it is still owned here,
     * so it is released exactly once (a successful set transfers ownership to the object). */
    /* §18: the session records, oldest first, each bound to `lifetime_id`. Bounded by construction:
     * the array holds PS4RF_DAEMON_SESSION_RECORDS entries and `session_records_total` counts them
     * all, so a long run does not grow the evidence. */
    {
        jval *records = jval_new_array();
        if (records == NULL) {
            ok = 0;
        } else {
            for (i = 0u; i < d->rep.session_record_count && ok; i++) {
                const ps4rf_daemon_session_record *rec = &d->rep.session_records[i];
                jval *entry = jval_new_object();
                if (entry == NULL) {
                    ok = 0;
                    break;
                }
                if (jval_obj_set(entry, "session_id", jval_new_string(rec->session_id)) != 0 ||
                    jval_obj_set(entry, "bye", jval_new_string(rec->bye)) != 0 ||
                    jval_obj_set(entry, "cleanup_state",
                                 jval_new_string(rec->cleanup_state)) != 0 ||
                    jval_obj_set(entry, "held_after_cleanup",
                                 jval_new_int((int64_t)rec->held_after_cleanup)) != 0 ||
                    jval_obj_set(entry, "reaped", jval_new_int((int64_t)rec->reaped)) != 0 ||
                    jval_obj_set(entry, "requests", jval_new_int((int64_t)rec->requests)) != 0 ||
                    jval_obj_set(entry, "provider_entries",
                                 jval_new_int((int64_t)rec->provider_entries)) != 0 ||
                    jval_obj_set(entry, "deferred", jval_new_int((int64_t)rec->deferred)) != 0 ||
                    jval_obj_set(entry, "invalid", jval_new_int((int64_t)rec->invalid)) != 0 ||
                    jval_obj_set(entry, "violations", jval_new_int((int64_t)rec->violations)) != 0 ||
                    jval_obj_set(entry, "recovery_at_start",
                                 jval_new_bool(rec->recovery_at_start ? 1 : 0)) != 0 ||
                    jval_obj_set(entry, "boot_recheck_ok",
                                 jval_new_bool(rec->boot_recheck_ok ? 1 : 0)) != 0 ||
                    jval_arr_add(records, entry) != 0) {
                    jval_free(entry);
                    ok = 0;
                    break;
                }
            }
            if (ok) {
                if (jval_obj_set(obj, "session_records", records) != 0) {
                    ok = 0;
                } else {
                    records = NULL;              /* ownership moved to the object */
                }
            }
            jval_free(records);
        }
    }
    if (ok) {
        if (jval_obj_set(obj, "attempts", jval_new_int((int64_t)d->rep.attempts)) != 0 ||
            jval_obj_set(obj, "boot_inputs", jval_new_string(d->rep.boot_inputs)) != 0 ||
            jval_obj_set(obj, "boot_sec", jval_new_int((int64_t)d->rep.boot_sec)) != 0 ||
            jval_obj_set(obj, "boot_usec", jval_new_int((int64_t)d->rep.boot_usec)) != 0 ||
            jval_obj_set(obj, "bootstrap_failures",
                         jval_new_int((int64_t)d->rep.bootstrap_failures)) != 0 ||
            jval_obj_set(obj, "busy_refusals",
                          jval_new_int((int64_t)d->rep.busy_refusals)) != 0 ||
            jval_obj_set(obj, "cleanup_reaped",
                         jval_new_int((int64_t)d->rep.cleanup_reaped)) != 0 ||
            jval_obj_set(obj, "cleanup_refusals",
                         jval_new_int((int64_t)d->rep.cleanup_refusals)) != 0 ||
            jval_obj_set(obj, "cleanup_state", jval_new_string(d->rep.cleanup_state)) != 0 ||
            jval_obj_set(obj, "dial_backoff_us",
                         jval_new_int((int64_t)d->rep.dial_backoff_us)) != 0 ||
            jval_obj_set(obj, "dial_misses", jval_new_int((int64_t)d->rep.dial_misses)) != 0 ||
            jval_obj_set(obj, "dial_misses_total",
                         jval_new_int((int64_t)d->rep.dial_misses_total)) != 0 ||
            jval_obj_set(obj, "recovery_source",
                         jval_new_string(d->rep.recovery_source)) != 0 ||
            jval_obj_set(obj, "recovery_transitions",
                         jval_new_int((int64_t)d->rep.recovery_transitions)) != 0 ||
            jval_obj_set(obj, "undelivered_mutations",
                         jval_new_int((int64_t)d->rep.undelivered_mutations)) != 0 ||
            jval_obj_set(obj, "undelivered_responses",
                         jval_new_int((int64_t)d->rep.undelivered_responses)) != 0 ||
            jval_obj_set(obj, "held_after_cleanup",
                         jval_new_int((int64_t)d->rep.held_after_cleanup)) != 0 ||
            jval_obj_set(obj, "exit_detail", jval_new_string(d->rep.exit_detail)) != 0 ||
            jval_obj_set(obj, "exit_reason", jval_new_string(reason)) != 0 ||
            jval_obj_set(obj, "last_bye", jval_new_string(d->rep.last_bye)) != 0 ||
            jval_obj_set(obj, "lifetime_id", jval_new_string(d->rep.lifetime_id)) != 0 ||
            jval_obj_set(obj, "lifetime_start_sec",
                         jval_new_int((int64_t)d->rep.lifetime_start_sec)) != 0 ||
            jval_obj_set(obj, "session_records_total",
                         jval_new_int((int64_t)d->rep.session_records_total)) != 0 ||
            jval_obj_set(obj, "recovery_required",
                         jval_new_bool(d->rep.recovery_required ? 1 : 0)) != 0 ||
            jval_obj_set(obj, "sessions_failed",
                         jval_new_int((int64_t)d->rep.sessions_failed)) != 0 ||
            jval_obj_set(obj, "sessions_served",
                         jval_new_int((int64_t)d->rep.sessions_served)) != 0 ||
            jval_obj_set(obj, "state", jval_new_string(d->rep.state)) != 0 ||
            jval_obj_set(obj, "stop", jval_new_string(d->rep.stop)) != 0 ||
            jval_obj_set(obj, "transitions",
                         jval_new_int((int64_t)d->rep.transitions)) != 0 ||
            jval_obj_set(obj, "session_ids", ids) != 0) {
            ok = 0;
        }
    }
    if (!ok) {
        jval_free(obj);
        jval_free(ids);
        return 0u;
    }
    if (ps4rf_canonical_bytes(obj, &text, &len, &err) != PS4RF_OK) {
        jval_free(obj);
        return 0u;
    }
    jval_free(obj);
    if (text == NULL || len + 1u > cap) {
        free(text);
        return 0u;
    }
    memcpy(out, text, len);
    out[len] = '\0';
    free(text);
    return len;
}
