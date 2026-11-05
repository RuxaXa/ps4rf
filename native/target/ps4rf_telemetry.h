/* PS4RF P4/W8 target agent -- target attestation (read only, measured).
 *
 * Every fact carries its own status: a value the agent cannot prove with a legitimate
 * read-only userland API is reported as UNRESOLVED together with the API that was tried.
 * Nothing is derived from expectations, from the build or from a profile.
 *
 * boot_id: the agent must not emit its own launch time as a boot identifier. It is
 * derived only from measured boot facts (firmware identity + model + kern.boottime) --
 * a reboot therefore yields a different boot_id while relaunching the agent does not. If
 * any of those facts is unavailable the status is BOOT_ID_UNVERIFIED, no identifier is
 * emitted, and the runtime binding stays fail closed.
 */
#ifndef PS4RF_TELEMETRY_H
#define PS4RF_TELEMETRY_H

#include <stddef.h>
#include <stdint.h>

#include "jcs.h"
#include "ps4rf_libc.h"
#include "ps4rf_optable_data.h"
#include "ps4rf_platform.h"

#define PS4RF_TEL_FIELD_MAX 96u
#define PS4RF_BOOT_ID_LEN 24u          /* "BOOT-" + 16 hex + NUL */

typedef struct {
    char platform[PS4RF_TEL_FIELD_MAX];
    char architecture[PS4RF_TEL_FIELD_MAX];
    char firmware[PS4RF_TEL_FIELD_MAX];
    ps4rf_fact_status firmware_status;
    char model[PS4RF_TEL_FIELD_MAX];
    ps4rf_fact_status model_status;
    long process_id;
    ps4rf_fact_status process_id_status;
    long long boot_time_epoch;
    ps4rf_fact_status boot_time_status;
    char boot_id[PS4RF_BOOT_ID_LEN];
    int boot_id_ok;                        /* 1 only with a derived identifier */
    char boot_id_source[PS4RF_TEL_FIELD_MAX];
    char nonce_source[PS4RF_TEL_FIELD_MAX];
} ps4rf_telemetry;

void ps4rf_telemetry_collect(ps4rf_telemetry *tel);

/* Builds the READY attestation object (canonical serialization is applied by the
 * caller). Wired and deferred counts/names come from the generated operation table. */
jval *ps4rf_telemetry_ready_body(const ps4rf_telemetry *tel, const char *build_id,
                                 unsigned protocol_version, unsigned max_frame_bytes,
                                 unsigned lifetime_s, unsigned idle_s, const char *provider_id);

#endif /* PS4RF_TELEMETRY_H */
