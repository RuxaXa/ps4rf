/* PS4RF W9 - host-build stand-ins for the two SDK entry points the attestation uses.
 *
 * On the console both come from libPS4 (kexec() makes the privileged transition, and
 * get_kernel_base() returns the LSTAR-derived image base). A host build has no kernel, so
 * this file is deliberately honest about it: kexec() fails, no kernel memory is read, and the
 * attestation run reports the failure instead of inventing measurements. That is the
 * fail-closed path, and the offline end-to-end run exercises exactly that.
 *
 * The offline *success* path is exercised by tests/harness/attest_host_sim.c, which provides
 * these two symbols with a simulating kernel (and is only linked into the test build, never
 * into a shipped artefact).
 */

#include <stdint.h>

#include "ps4rf_attest.h"

int kexec(void *func, void *user_arg) {
  (void)func;
  (void)user_arg;
  return -1;                 /* no privileged transition without a kernel */
}

uint64_t get_kernel_base(void) {
  return 0ull;               /* no kernel base without a kernel */
}
