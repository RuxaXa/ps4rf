/* PS4RF P4/W8 target agent -- the single dispatch path.
 *
 *   REQUEST -> envelope validation -> registry lookup -> argument validation
 *           -> recovery check -> capability/route decision -> [provider entry] -> RESPONSE
 *
 * Exactly one function enters a provider handler (`ps4rf_provider_enter`), and it is only
 * reachable for an operation whose frozen route is `stub` *and* which is part of the
 * approved W8 live scope. Every other operation -- privileged, host-chain, mock-only or
 * out of scope -- is refused with `OPERATION_DEFERRED` (or `OPERATION_UNSUPPORTED` when it
 * is not in the frozen registry at all) *before* any handler is entered. There is no
 * fallback route and no implicit provider selection.
 */
#ifndef PS4RF_ROUTER_H
#define PS4RF_ROUTER_H

#include "jcs.h"
#include "ps4rf_runtime.h"

typedef enum {
    PS4RF_ROUTE_OUTCOME_NONE = 0,   /* nothing to send */
    PS4RF_ROUTE_OUTCOME_RESPONSE,   /* *response_out carries the RESPONSE */
    PS4RF_ROUTE_OUTCOME_CLOSE       /* protocol violation: end the session */
} ps4rf_route_outcome;

ps4rf_route_outcome ps4rf_router_handle(ps4rf_rt *rt, const jval *request, jval **response_out);

/* Number of provider entry sites in the router translation unit (must stay 1). */
unsigned ps4rf_router_entry_sites(void);

#endif /* PS4RF_ROUTER_H */
