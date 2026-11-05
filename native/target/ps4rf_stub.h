/* PS4RF P4/W8 target agent -- stub provider (the only code that executes an operation).
 *
 * Native counterpart of the frozen stub (tools/primitive_iface/stub.py): same argument
 * rules, same result fields, same error codes, same default wait budget. Nothing here
 * touches the console: the objects are the agent's own memory and its own in-process
 * sync objects.
 */
#ifndef PS4RF_STUB_H
#define PS4RF_STUB_H

#include "jcs.h"
#include "ps4rf_runtime.h"

#define PS4RF_STUB_MAX_ALLOC 1048576u
#define PS4RF_STUB_MAX_HELD 16u
#define PS4RF_STUB_DEFAULT_WAIT_MS 5000u

/* Executes one wired operation. Returns NULL on success (with *result_out set) or a
 * frozen error code. `detail_out` receives a short reason for the wire error detail. */
const char *ps4rf_stub_invoke(ps4rf_rt *rt, const ps4rf_op_row *row, const jval *args,
                              jval **result_out, const char **detail_out);

/* W14: per-session setup of the provider state. Called exactly once at the start of a session
 * (from the agent's session entry, never from a request): it re-arms the privileged one shot of
 * the bounded kernel.read provider so that each session -- and only a whole session -- may
 * perform at most one privileged transition. Compiles to nothing when the build has no
 * privileged provider. */
void ps4rf_stub_session_begin(void);

#endif /* PS4RF_STUB_H */
