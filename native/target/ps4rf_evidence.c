/* PS4RF P4/W8 target agent -- request accounting (see ps4rf_evidence.h). */
#include "ps4rf_evidence.h"

void ps4rf_ev_init(ps4rf_ev *ev)
{
    unsigned i;
    for (i = 0u; i < PS4RF_EV_MAX; i++) {
        ev->ring[i].seq = 0u;
        ev->ring[i].request_id[0] = '\0';
        ev->ring[i].op = NULL;
        ev->ring[i].route = 0u;
        ev->ring[i].provider_entry = 0u;
        ev->ring[i].ok = 0u;
        ev->ring[i].code = NULL;
        ev->ring[i].refs_after = 0u;
        ev->ring[i].ts_us = 0u;
    }
    ev->head = 0u;
    ev->count = 0u;
    ev->requests_total = 0u;
    ev->provider_entries_total = 0u;
    ev->deferred_total = 0u;
    ev->unsupported_total = 0u;
    ev->invalid_total = 0u;
    ev->recovery_refusals = 0u;
    ev->violations = 0u;
}

ps4rf_ev_record *ps4rf_ev_next(ps4rf_ev *ev)
{
    ps4rf_ev_record *rec = &ev->ring[ev->head];
    ev->head = (ev->head + 1u) % PS4RF_EV_MAX;
    if (ev->count < PS4RF_EV_MAX) ev->count++;
    rec->seq = ev->requests_total + 1u;
    rec->request_id[0] = '\0';
    rec->op = NULL;
    rec->route = 0u;
    rec->provider_entry = 0u;
    rec->ok = 0u;
    rec->code = NULL;
    rec->refs_after = 0u;
    rec->ts_us = 0u;
    ev->requests_total++;
    return rec;
}

void ps4rf_ev_note_entry(ps4rf_ev *ev)
{
    ev->provider_entries_total++;
}

void ps4rf_ev_note_violation(ps4rf_ev *ev)
{
    ev->violations++;
}

unsigned ps4rf_ev_count(const ps4rf_ev *ev)
{
    return ev->count;
}

const ps4rf_ev_record *ps4rf_ev_at(const ps4rf_ev *ev, unsigned index)
{
    unsigned start;
    if (index >= ev->count) return NULL;
    start = (ev->head + PS4RF_EV_MAX - ev->count) % PS4RF_EV_MAX;
    return &ev->ring[(start + index) % PS4RF_EV_MAX];
}
