/* PS4RF P4/W8 target agent -- session driver (agent side of wire R1).
 *
 * Wire R1 only: HELLO -> HELLO_ACK -> AUTH -> AUTH_ACK (frozen agent handshake), then
 * exactly one sealed READY frame carrying the target attestation, then the REQUEST /
 * RESPONSE loop, then a best-effort BYE. The AEAD channels, the transcript, the replay
 * checks and the framing are the frozen W2 implementation -- the target agent has no
 * wire variant of its own.
 */
#ifndef PS4RF_AGENT_H
#define PS4RF_AGENT_H

#include <stddef.h>
#include <stdint.h>

#include "ps4rf_libc.h"
#include "ps4rf_protocol.h"
#include "ps4rf_runtime.h"

typedef enum {
    PS4RF_AGENT_RAN = 0,            /* handshake + READY + loop done, BYE attempted */
    PS4RF_AGENT_HELLO_FAILED = 1,
    PS4RF_AGENT_HANDSHAKE_FAILED = 2,
    PS4RF_AGENT_READY_FAILED = 3,
    PS4RF_AGENT_IO_FAILED = 4,
    PS4RF_AGENT_PROTOCOL_FAILED = 5,
    PS4RF_AGENT_ATTEST_FAILED = 6,     /* W9: the fixed attestation step did not complete */
    PS4RF_AGENT_BOOT_FAILED = 7,       /* W11: the read-only boot binding did not complete */
    PS4RF_AGENT_BOOTREAD_FAILED = 8,   /* W11.2: the fixed privileged boot read did not complete */
    PS4RF_AGENT_KREAD_FAILED = 9       /* W12: the bounded kernel.read provider did not complete */
} ps4rf_agent_result;

/* W14 §14 -- the identity a session announces in HELLO.
 *
 * Static across the *agent lifetime*: the build identity, the platform and (if the build has
 * one) the bound profile. Per *boot*: the measured boot identity and the boot-wide recovery
 * state (§11). Per *session* the agent generates a fresh nonce; the host answers with a fresh
 * session id, and the transcript plus both directional key sets are derived from those two
 * nonces -- so nothing session-bound exists before this session and nothing survives it.
 *
 * `profile_id` and `boot_id` are NULL when the corresponding identity does not exist in this
 * build/boot: the agent then reports JSON null, never a fabricated value. */
typedef struct {
    const char *build_id;      /* static: agent build identity, never NULL ("unresolved") */
    const char *platform;      /* static: "ps4" or "host-standin" */
    const char *profile_id;    /* static: NULL = no bound profile in this build */
    const char *boot_id;       /* per boot: NULL = boot identity unresolved */
    long long boot_sec;        /* per boot: -1 = unresolved */
    long long boot_usec;
    const char *boot_status;   /* per boot: "MEASURED" | "UNRESOLVED" */
    int recovery_required;     /* per boot, boot-wide (§11): never reset by a session */
} ps4rf_agent_identity;

/* Fills `id` with the caller's lifetime/boot facts; NULL ids keep their "no such identity"
 * meaning. `platform` is always set from the build itself. */
void ps4rf_agent_identity_init(ps4rf_agent_identity *id, const char *build_id, const char *boot_id,
                               long long boot_sec, long long boot_usec, const char *boot_status,
                               int recovery_required);

/* The platform this build runs on ("ps4" or "host-standin"), a compile-time fact. */
const char *ps4rf_agent_platform(void);

/* The build identity a session announces as `agent_version` (W15 §10).
 *
 * It names the *wave identity* of the agent code, not the artefact: the artefact's own identity is
 * the build id (source hash) and the label/context from the generated config. It is a single
 * constant so a stale string is a visible edit and can be gated (W14-D1: the console build reported
 * `ps4rfd-target-w8` while its build id, label and context were already W14/W15). */
#define PS4RF_AGENT_VERSION "ps4rfd-target-w15"

/* W14 §15 -- the resident mode, set once for the whole agent lifetime by the resident daemon.
 *
 * It exists because "end the agent" only means something when there *is* an agent across sessions:
 * the lifetime-level operation `session.shutdown` is served in this mode and refused outside it, so
 * the single-session profiles (the console one-session entry point, the plain host driver) keep
 * exactly the served set they had. Per-session state stays per session -- this is a mode, not a
 * session fact, and no session can change it. */
void ps4rf_agent_set_resident(int on);
int ps4rf_agent_is_resident(void);

/* Runs one session on `fd` with the pre-shared key. `bye_reason_out` receives the frozen
 * BYE reason that was used ("CLIENT_CLOSE", "SERVER_CLOSE", "RECOVERY_REQUIRED").
 *
 * Every session derives its own keys from its own transcript and wipes them before returning;
 * a caller that runs several sessions must pass a fresh `rt` (the runtime is the session state). */
ps4rf_agent_result ps4rf_agent_run(int fd, const uint8_t psk[32], const char *label,
                                   const char *context, const char *provider_id,
                                   const ps4rf_agent_identity *identity, ps4rf_rt *rt,
                                   char *bye_reason_out, size_t bye_reason_cap);

/* W14 (resident ps4rfd): the resident checkpoint. A resident caller installs one checkpoint;
 * the session loop calls it at the top of every iteration. It receives a caller-owned context
 * and returns 0 to continue or non-zero to end the session -- the agent then stops with BYE
 * "SERVER_CLOSE" and the caller owns the reason.
 *
 * The checkpoint is deliberately narrow: it receives no request, no argument object and no
 * address, it can only *refuse* or *end* a session, and it dispatches no operation. That is why
 * it cannot become an operation trigger and why the stage-A property (the session loop holds
 * no kernel.read state, no request parse and no call site) still holds by construction.
 *
 * Installing nothing (the console payload, the single-session host mode) or uninstalling with
 * (NULL, NULL) leaves the session loop exactly as it was before this wave. */
typedef int (*ps4rf_agent_checkpoint_fn)(void *ctx);

void ps4rf_agent_set_checkpoint(ps4rf_agent_checkpoint_fn fn, void *ctx);

#endif /* PS4RF_AGENT_H */
