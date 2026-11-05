/* PS4RF P4/W8 target agent -- request accounting ("evidence minimal").
 *
 * The agent records one record per dispatch attempt inside its own session, plus the
 * counters that make the W8 invariants checkable in the live run:
 *
 *   * every dispatch attempt has exactly one record
 *   * `provider_entry` counts how often a provider handler was entered
 *   * a non-wired operation must never have a provider entry (invariant guard; a
 *     violation ends the session with RECOVERY_REQUIRED instead of being reported OK)
 *
 * The host reconstructs the same table from the responses it receives; the agent's own
 * counters are the independent cross-check (they must agree, otherwise the session is
 * refused). Nothing here is transmitted and nothing is persisted.
 */
#ifndef PS4RF_EVIDENCE_H
#define PS4RF_EVIDENCE_H

#include <stddef.h>
#include <stdint.h>

#define PS4RF_EV_MAX 64u
#define PS4RF_EV_REQUEST_ID_LEN 40u

typedef struct {
    unsigned seq;
    char request_id[PS4RF_EV_REQUEST_ID_LEN];
    const char *op;
    unsigned char route;
    unsigned char provider_entry;
    unsigned char ok;
    const char *code;          /* frozen error code, NULL on success */
    unsigned refs_after;
    uint64_t ts_us;
} ps4rf_ev_record;

typedef struct {
    ps4rf_ev_record ring[PS4RF_EV_MAX];
    unsigned head;
    unsigned count;
    unsigned requests_total;
    unsigned provider_entries_total;
    unsigned deferred_total;
    unsigned unsupported_total;
    unsigned invalid_total;
    unsigned recovery_refusals;
    unsigned violations;
} ps4rf_ev;

void ps4rf_ev_init(ps4rf_ev *ev);
ps4rf_ev_record *ps4rf_ev_next(ps4rf_ev *ev);          /* reserves the next record */
void ps4rf_ev_note_entry(ps4rf_ev *ev);                /* provider handler entered */
void ps4rf_ev_note_violation(ps4rf_ev *ev);
unsigned ps4rf_ev_count(const ps4rf_ev *ev);
const ps4rf_ev_record *ps4rf_ev_at(const ps4rf_ev *ev, unsigned index);

#endif /* PS4RF_EVIDENCE_H */
