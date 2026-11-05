/* PS4RF P4/W8 -- host build of the target agent (offline validation only).
 *
 * The console payload (ps4rfd_target.c) and this program share every module of the
 * dispatch path; only the platform layer differs. That is what makes the offline tests
 * meaningful: the logic that is exercised here is compiled from the same sources as the
 * logic that runs on the console.
 *
 * Modes:
 *   --selftest                 in-process checks of table, router, resources, telemetry
 *   --connect IP PORT --psk-file F [--label L] [--context C] [--lifetime S] [--idle S]
 *                              run one agent session against a host controller
 *   --resident --connect IP PORT --psk-file F [--sessions N] [--label L] [--context C]
 *              [--lifetime S] [--idle S] [--idle-rounds N] [--idle-pause-ms N]
 *              [--no-refuse-while-busy]
 *                              run the W14 resident daemon: BOOTSTRAP, then several sessions
 *                              over the same dial-out endpoint (the host controller listens
 *                              per session, the daemon dials in). The single-session driver is
 *                              unchanged. The daemon's own report is one JSON line on stdout.
 *
 * The report is a single JSON line on stdout. It never contains the pre-shared key.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "ps4rf_agent.h"
#include "ps4rf_daemon.h"
#include "ps4rf_platform.h"
#include "ps4rf_router.h"

static int read_psk(const char *path, uint8_t psk[32])
{
    FILE *f = fopen(path, "rb");
    unsigned char buf[64];
    size_t got;
    if (f == NULL) return -1;
    got = fread(buf, 1u, sizeof(buf), f);
    fclose(f);
    if (got < 32u) return -1;
    memcpy(psk, buf, 32u);
    memset(buf, 0, sizeof(buf));
    return 0;
}

/* ------------------------------------------------------------------- self-test */

static int run_selftest(void)
{
    ps4rf_rt rt;
    unsigned i;
    unsigned wired = 0u;
    unsigned deferred = 0u;
    unsigned entries_ok = 1u;
    ps4rf_rt_init(&rt, "SES-0123456789abcdef0123456789abcdef", "selftest-build", "selftest", "ps4rfd-native-stub");
    for (i = 0u; i < PS4RF_OP_TABLE_COUNT; i++) {
        if (PS4RF_OP_TABLE[i].target == PS4RF_TARGET_WIRED) wired++;
        else deferred++;
    }
    if (wired != PS4RF_OP_WIRED_COUNT || deferred != PS4RF_OP_DEFERRED_COUNT) entries_ok = 0u;
    if (ps4rf_router_entry_sites() != 1u) entries_ok = 0u;
    if (rt.tel.boot_id_ok && strncmp(rt.tel.boot_id, "BOOT-", 5u) != 0) entries_ok = 0u;

    /* A deferred operation must be refused without a provider entry, a wired one must be
     * served -- both through the same dispatch path. */
    {
        /* W13-C2 (wire catalog revision R2): kernel.read carries the bounded region triplet under
         * body.arguments; well formed, so the request reaches the route decision. W14 (catalog
         * revision R3): the operation is WIRED on the target now, so it enters the single
         * privileged provider -- on a build without that provider the wired row is still refused
         * fail-closed by the stub default, and that refusal happens *after* the provider entry.
         * The entry count is therefore 1 either way (the refusal is the route's, not the
         * validator's). */
        const char *req = "{\"body\":{\"arguments\":{\"region_index\":3,\"offset\":0,\"length\":16},"
                          "\"operation\":\"kernel.read\"},"
                          "\"header\":{\"request_id\":\"REQ-0123456789abcdef0123456789abcdef\"}}";
        jval *request = jval_parse(req, strlen(req));
        jval *response = NULL;
        ps4rf_route_outcome outcome = ps4rf_router_handle(&rt, request, &response);
        const jval *err = response != NULL ? jval_get(response, "error") : NULL;
        const char *code = err != NULL ? jval_string(jval_get(err, "code"), NULL) : NULL;
        if (outcome != PS4RF_ROUTE_OUTCOME_RESPONSE) entries_ok = 0u;
        if (rt.ev.provider_entries_total != 1u) entries_ok = 0u;
#ifdef PS4RF_TARGET_KREAD
        /* the productive provider: the bounded read runs (the host stand-in has no kernel, so
         * the record reports RESULT_INVALID -- a refusal inside the provider, not an argument
         * error, which is exactly the proof that the request was accepted and entered) */
        {
            const jval *res = response != NULL ? jval_get(response, "result") : NULL;
            const char *provider = res != NULL ? jval_string(jval_get(res, "provider"), NULL) : NULL;
            if (code != NULL) entries_ok = 0u;
            if (provider == NULL || strcmp(provider, "ps4rfd-kread-privileged") != 0) entries_ok = 0u;
        }
#else
        if (code == NULL || strcmp(code, "OPERATION_DEFERRED") != 0) entries_ok = 0u;
#endif
        jval_free(request);
        jval_free(response);
    }
    {
        /* The retired contract must be dead on the wire: addr/size is no longer an argument set
         * this operation accepts, so the request is refused by the argument validator before the
         * route decision -- no provider entry, no read. */
        const char *req = "{\"body\":{\"arguments\":{\"addr\":0,\"size\":16},"
                          "\"operation\":\"kernel.read\"},"
                          "\"header\":{\"request_id\":\"REQ-0123456789abcdef0123456789abcdef\"}}";
        jval *request = jval_parse(req, strlen(req));
        jval *response = NULL;
        ps4rf_route_outcome outcome = ps4rf_router_handle(&rt, request, &response);
        const jval *err = response != NULL ? jval_get(response, "error") : NULL;
        const char *code = err != NULL ? jval_string(jval_get(err, "code"), NULL) : NULL;
        if (outcome != PS4RF_ROUTE_OUTCOME_RESPONSE) entries_ok = 0u;
        if (code == NULL || strcmp(code, "ARGUMENT_INVALID") != 0) entries_ok = 0u;
        if (rt.ev.provider_entries_total != 1u) entries_ok = 0u;
        jval_free(request);
        jval_free(response);
    }
    {
        const char *req = "{\"body\":{\"arguments\":{},\"operation\":\"session.ping\"},"
                          "\"header\":{\"request_id\":\"REQ-0123456789abcdef0123456789abcdef\"}}";
        jval *request = jval_parse(req, strlen(req));
        jval *response = NULL;
        ps4rf_route_outcome outcome = ps4rf_router_handle(&rt, request, &response);
        const jval *res = response != NULL ? jval_get(response, "result") : NULL;
        const jval *pong = res != NULL ? jval_get(res, "pong") : NULL;
        if (outcome != PS4RF_ROUTE_OUTCOME_RESPONSE) entries_ok = 0u;
        if (pong == NULL || jval_kind(pong) != JVAL_BOOL || jval_bool(pong) != 1) entries_ok = 0u;
        if (rt.ev.provider_entries_total != 2u) entries_ok = 0u;
        jval_free(request);
        jval_free(response);
    }

    printf("{\"selftest\": \"%s\", \"ops\": %u, \"wired\": %u, \"deferred\": %u, "
           "\"provider_entries\": %u, \"deferred_total\": %u, \"invalid_total\": %u, \"violations\": %u, "
           "\"boot_id_status\": \"%s\", \"table_sha256\": \"%s\"}\n",
           entries_ok ? "PASS" : "FAIL", (unsigned)PS4RF_OP_TABLE_COUNT, wired, deferred,
           rt.ev.provider_entries_total, rt.ev.deferred_total, rt.ev.invalid_total, rt.ev.violations,
           rt.tel.boot_id_ok ? "DERIVED" : "BOOT_ID_UNVERIFIED", PS4RF_OP_TABLE_SHA256);
    return entries_ok ? 0 : 1;
}

/* ------------------------------------------------------------------ resident daemon (W14) */

static int run_resident(int argc, char **argv)
{
    const char *ip = NULL;
    unsigned port = 0u;
    const char *psk_file = NULL;
    const char *label = "ps4rfd-host-daemon";
    const char *context = "host-resident-session";
    unsigned lifetime = 900u;
    unsigned idle = 180u;
    unsigned sessions = 0u;
    unsigned idle_rounds = 0u;
    unsigned idle_pause_ms = 250u;
    unsigned backoff_max_ms = 0u;
    int refuse_while_busy = 1;
    uint8_t psk[32];
    char report[PS4RF_DAEMON_REPORT_MAX];
    size_t n;
    int i;
    ps4rf_daemon daemon;
    ps4rf_daemon_config cfg;
    int ended_on_exit;

    for (i = 2; i < argc; i++) {
        if (strcmp(argv[i], "--connect") == 0 && i + 2 < argc) {
            ip = argv[++i];
            port = (unsigned)strtoul(argv[++i], NULL, 10);
        } else if (strcmp(argv[i], "--psk-file") == 0 && i + 1 < argc) {
            psk_file = argv[++i];
        } else if (strcmp(argv[i], "--label") == 0 && i + 1 < argc) {
            label = argv[++i];
        } else if (strcmp(argv[i], "--context") == 0 && i + 1 < argc) {
            context = argv[++i];
        } else if (strcmp(argv[i], "--lifetime") == 0 && i + 1 < argc) {
            lifetime = (unsigned)strtoul(argv[++i], NULL, 10);
        } else if (strcmp(argv[i], "--idle") == 0 && i + 1 < argc) {
            idle = (unsigned)strtoul(argv[++i], NULL, 10);
        } else if (strcmp(argv[i], "--sessions") == 0 && i + 1 < argc) {
            sessions = (unsigned)strtoul(argv[++i], NULL, 10);
        } else if (strcmp(argv[i], "--idle-rounds") == 0 && i + 1 < argc) {
            idle_rounds = (unsigned)strtoul(argv[++i], NULL, 10);
        } else if (strcmp(argv[i], "--idle-pause-ms") == 0 && i + 1 < argc) {
            idle_pause_ms = (unsigned)strtoul(argv[++i], NULL, 10);
        } else if (strcmp(argv[i], "--backoff-max-ms") == 0 && i + 1 < argc) {
            backoff_max_ms = (unsigned)strtoul(argv[++i], NULL, 10);
        } else if (strcmp(argv[i], "--no-refuse-while-busy") == 0) {
            refuse_while_busy = 0;
        }
    }
    if (ip == NULL || port == 0u || psk_file == NULL) {
        fprintf(stderr, "usage: %s --resident --connect IP PORT --psk-file F [--sessions N] "
                        "[--idle-rounds N] [--idle-pause-ms N] [--backoff-max-ms N] "
                        "[--no-refuse-while-busy]\n",
                argv[0]);
        return 2;
    }
    if (read_psk(psk_file, psk) != 0) {
        fprintf(stderr, "cannot read 32-byte psk from %s\n", psk_file);
        return 2;
    }

    memset(&cfg, 0, sizeof(cfg));
    cfg.label = label;
    cfg.context = context;
    cfg.provider_id = "ps4rfd-native-stub";
    cfg.build_id = "host-build";
    cfg.psk = psk;
    cfg.host = ip;
    cfg.port = port;
    cfg.dial_attempts = 1u;              /* the resident loop owns its retry schedule */
    cfg.lifetime_s = lifetime;
    cfg.idle_s = idle;
    cfg.max_sessions = sessions;
    cfg.idle_rounds = idle_rounds;
    cfg.idle_pause_us = idle_pause_ms * 1000u;
    cfg.backoff_max_us = backoff_max_ms * 1000u;
    /* §11 stand-in (host builds only): a boot that comes up in the recovery state. The console has
     * no environment, so this cannot exist there; the value is a *boot* fact, not a session one --
     * no session can set or clear it. */
    {
        const char *force = getenv("PS4RF_HOST_FORCE_RECOVERY");
        cfg.initial_recovery = (force != NULL && force[0] != '0') ? 1 : 0;
    }
    cfg.refuse_while_busy = refuse_while_busy;

    ps4rf_daemon_init(&daemon, &cfg);
    ended_on_exit = ps4rf_daemon_run(&daemon);
    memset(psk, 0, sizeof(psk));

    n = ps4rf_daemon_report_json(&daemon, report, sizeof(report));
    if (n == 0u) {
        printf("{\"daemon\":\"FAIL\",\"reason\":\"report_unavailable\"}\n");
        return 1;
    }
    printf("%s\n", report);
    /* §15: an authenticated admin shutdown is a clean end, not a fault -- the process leaves with 0,
     * exactly like a run that simply reached its budget. Every other exit condition keeps 1. */
    if (ended_on_exit && strcmp(ps4rf_daemon_exit_reason(&daemon), PS4RF_DAEMON_EXIT_ADMIN) == 0) {
        return 0;
    }
    return ended_on_exit ? 1 : 0;
}

/* ------------------------------------------------------------------- session */

static int run_connect(int argc, char **argv)
{
    const char *ip = NULL;
    unsigned port = 0u;
    const char *psk_file = NULL;
    const char *label = "ps4rfd-host-agent";
    const char *context = "host-agent-session";
    unsigned lifetime = 900u;
    unsigned idle = 180u;
    uint8_t psk[32];
    int fd;
    int i;
    ps4rf_rt rt;
    char bye[24];
    ps4rf_agent_result result;

    for (i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--connect") == 0 && i + 2 < argc) {
            ip = argv[++i];
            port = (unsigned)strtoul(argv[++i], NULL, 10);
        } else if (strcmp(argv[i], "--psk-file") == 0 && i + 1 < argc) {
            psk_file = argv[++i];
        } else if (strcmp(argv[i], "--label") == 0 && i + 1 < argc) {
            label = argv[++i];
        } else if (strcmp(argv[i], "--context") == 0 && i + 1 < argc) {
            context = argv[++i];
        } else if (strcmp(argv[i], "--lifetime") == 0 && i + 1 < argc) {
            lifetime = (unsigned)strtoul(argv[++i], NULL, 10);
        } else if (strcmp(argv[i], "--idle") == 0 && i + 1 < argc) {
            idle = (unsigned)strtoul(argv[++i], NULL, 10);
        }
    }
    if (ip == NULL || port == 0u || psk_file == NULL) {
        fprintf(stderr, "usage: %s --connect IP PORT --psk-file F [--label L] [--context C] "
                        "[--lifetime S] [--idle S]\n", argv[0]);
        return 2;
    }
    if (read_psk(psk_file, psk) != 0) {
        fprintf(stderr, "cannot read 32-byte psk from %s\n", psk_file);
        return 2;
    }
    fd = ps4rf_platform_get()->net_connect(ip, port, 20);
    if (fd < 0) {
        printf("{\"agent\": \"FAIL\", \"reason\": \"connect_failed\"}\n");
        return 1;
    }
    memset(&rt, 0, sizeof(rt));
    rt.lifetime_s = lifetime;
    rt.idle_s = idle;
    {
        /* §14: the host stand-in has no boot binding of its own; its build id is the driver's
         * label for the artefact, and the boot identity is reported as unresolved, never guessed. */
        ps4rf_agent_identity id;
        ps4rf_agent_identity_init(&id, "host-build", NULL, -1ll, -1ll, "UNRESOLVED", 0);
        result = ps4rf_agent_run(fd, psk, label, context, "ps4rfd-native-stub", &id, &rt, bye,
                                 sizeof(bye));
    }
    ps4rf_platform_get()->net_close(fd);
    memset(psk, 0, sizeof(psk));
    printf("{\"agent\": \"%s\", \"bye_reason\": \"%s\", \"requests\": %u, \"served\": %u, "
           "\"provider_entries\": %u, \"deferred\": %u, \"unsupported\": %u, \"invalid\": %u, "
           "\"recovery_refusals\": %u, \"violations\": %u, \"live_resources\": %u, "
           "\"cleanup_state\": \"%s\", \"inflight_max\": %u, \"boot_id_status\": \"%s\"}\n",
           result == PS4RF_AGENT_RAN ? "RAN" : "FAILED", bye, rt.ev.requests_total,
           rt.requests_served, rt.ev.provider_entries_total, rt.ev.deferred_total,
           rt.ev.unsupported_total, rt.ev.invalid_total, rt.ev.recovery_refusals,
           rt.ev.violations, ps4rf_res_live(&rt.res), ps4rf_res_cleanup_state(&rt.res),
           rt.inflight_max_seen, rt.tel.boot_id_ok ? "DERIVED" : "BOOT_ID_UNVERIFIED");
    return result == PS4RF_AGENT_RAN ? 0 : 1;
}

int main(int argc, char **argv)
{
    if (argc > 1 && strcmp(argv[1], "--selftest") == 0) return run_selftest();
    if (argc > 1 && strcmp(argv[1], "--resident") == 0) return run_resident(argc, argv);
    if (argc > 1 && strcmp(argv[1], "--connect") == 0) return run_connect(argc, argv);
    fprintf(stderr, "usage: %s --selftest | --connect IP PORT --psk-file F [...] | "
                    "--resident --connect IP PORT --psk-file F [...]\n", argv[0]);
    return 2;
}
