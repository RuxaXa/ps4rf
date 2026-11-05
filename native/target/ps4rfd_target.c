/* PS4RF P4/W8 -- PS4 userland target agent (the artifact that is sent to the console).
 *
 * Single translation unit on purpose: crt0 + one object + libPS4.a is the live-proven
 * shape, and it keeps the linker from dragging in archive members the agent does not use.
 *
 * Scope (W8): wire R1 (HELLO/HELLO_ACK/AUTH/AUTH_ACK), AEAD channels, the sealed READY
 * attestation, the RPC dispatch path (registry -> router -> native stub provider ->
 * resources -> evidence) and a controlled exit. No kernel primitive, no kernel read, no
 * kernel write, no kexec, no GPUVM/KeyMgr/CCP/SAMU, no payload beyond this file, no
 * persistent change -- the 14 deferred privilege providers and the host-chain provider
 * answer OPERATION_DEFERRED with provider_entry=false.
 *
 * Build: native/target/build_ps4.sh (libPS4 toolchain regime, reproducible twice).
 */
#include "ps4.h"

#include "ps4rf_agent.h"
#include "ps4rf_daemon.h"
#include "ps4rf_optable_data.h"
#include "ps4rf_platform.h"
#include "ps4rf_router.h"
#include "ps4rf_runtime.h"
#include "ps4rf_stub.h"

#include "ps4rf_target_config.h"   /* generated: host, port, label, context, build id, psk */

void ps4rf_platform_probe(void);

int _main(struct thread *td)
{
    uint8_t psk[32];
#ifndef PS4RF_TARGET_RESIDENT
    const ps4rf_platform *pf;
    ps4rf_rt rt;
    int fd;
    char bye[24];
#endif

    (void)td;

    /* The proven init chain: kernel/module pointers, libc pointers, network. */
    initKernel();
    /* W15R3 breadcrumbs: fixed literals through the platform's debug-out (the kernel debug log
     * the operator captures passively). B00 is emitted as the first marker the marker path can
     * carry -- it needs the SDK's syscall entry, which initKernel fills -- so a capture that
     * starts with B00 proves the payload reached _main and came through the init chain. */
    ps4rf_trace_marker("B00 main entered");
    initLibc();
    initNetwork();
    ps4rf_trace_marker("B01 net ready");
    ps4rf_platform_probe();

    memcpy(psk, PS4RF_TARGET_PSK, sizeof(psk));
#ifndef PS4RF_TARGET_RESIDENT
    pf = ps4rf_platform_get();
#endif

#ifdef PS4RF_TARGET_RESIDENT
    /* W14 (§2/§12): the resident entry point. One upload, one agent lifetime, several fully
     * separated sessions -- the daemon owns the dial-out loop, so this file never dials itself
     * and never names the loader port. The session budget is a *run* bound (0 = unbounded here:
     * the lifetime is ended by the authenticated admin shutdown, and `lifetime_s` is the
     * fail-safe), and every session is still driven by the frozen `ps4rf_agent_run` under the
     * single acceptance gate. */
    {
        static ps4rf_daemon daemon;      /* static: the daemon carries its report and registries */
        ps4rf_daemon_config cfg;

        memset(&cfg, 0, sizeof(cfg));
        cfg.label = PS4RF_TARGET_LABEL;
        cfg.context = PS4RF_TARGET_CONTEXT;
        cfg.provider_id = PS4RF_TARGET_PROVIDER_ID;
        cfg.build_id = PS4RF_TARGET_BUILD_ID;
        cfg.psk = psk;
        cfg.host = PS4RF_TARGET_HOST;
        cfg.port = PS4RF_TARGET_PORT;
        cfg.dial_attempts = 1u;          /* the resident loop owns its retry schedule (§6) */
        cfg.lifetime_s = PS4RF_TARGET_LIFETIME_S;
        cfg.idle_s = PS4RF_TARGET_IDLE_S;
        cfg.max_sessions = PS4RF_TARGET_MAX_SESSIONS;
        cfg.idle_rounds = PS4RF_TARGET_IDLE_ROUNDS;
        cfg.idle_pause_us = PS4RF_TARGET_IDLE_PAUSE_MS * 1000u;
        cfg.backoff_max_us = PS4RF_TARGET_BACKOFF_MAX_MS * 1000u;
        cfg.initial_recovery = 0;
        cfg.refuse_while_busy = 1;       /* §13: refuses a second attempt, once per session */
        ps4rf_daemon_init(&daemon, &cfg);
        ps4rf_trace_marker("B02 daemon init done");
        (void)ps4rf_daemon_run(&daemon);
        /* The agent-side report is not emitted here: the console build has no output channel and
         * the artefact's symbol set is pinned. The host side holds the evidence (frames, BYE,
         * cleanup, identity) and the absence of any further dial after an ADMIN_SHUTDOWN. */
    }
    memset(psk, 0, sizeof(psk));
    return 0;
#else
    fd = pf->net_connect(PS4RF_TARGET_HOST, PS4RF_TARGET_PORT, PS4RF_TARGET_CONNECT_ATTEMPTS);
    if (fd < 0) {
        /* No host: do nothing at all and end the payload instance. No console change. */
        memset(psk, 0, sizeof(psk));
        return 0;
    }

    memset(&rt, 0, sizeof(rt));
    rt.lifetime_s = PS4RF_TARGET_LIFETIME_S;
    rt.idle_s = PS4RF_TARGET_IDLE_S;
    {
        /* §14: the console build reports the build identity that build_ps4.sh injected, and no
         * boot instant here -- the boot binding (W11) is a separate, build-gated step. */
        ps4rf_agent_identity id;
        ps4rf_agent_identity_init(&id, PS4RF_TARGET_BUILD_ID, NULL, -1ll, -1ll, "UNRESOLVED", 0);
        (void)ps4rf_agent_run(fd, psk, PS4RF_TARGET_LABEL, PS4RF_TARGET_CONTEXT,
                              PS4RF_TARGET_PROVIDER_ID, &id, &rt, bye, sizeof(bye));
    }
    pf->net_close(fd);
    memset(psk, 0, sizeof(psk));
    return 0;
#endif /* PS4RF_TARGET_RESIDENT */
}
