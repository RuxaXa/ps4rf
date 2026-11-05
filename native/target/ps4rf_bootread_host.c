/* PS4RF W11.2 -- host-build stand-ins for the two SDK entry points the boot read uses.
 *
 * On the console both come from libPS4 (kexec() makes the privileged transition, and
 * get_kernel_base() returns the LSTAR-derived image base). A host build has no kernel, so this
 * file is deliberately honest about it: kexec() fails and no kernel base exists, so the run
 * reports the failure instead of inventing a measurement -- the fail-closed path, which the
 * offline end-to-end run exercises exactly.
 *
 * The offline *success* path is exercised by the harness (tests/harness/bootread_*), which
 * provides these symbols plus the two weak leaf reads with a simulating image; those are only
 * linked into test builds, never into a shipped artefact.
 */

#include <stdint.h>

#include "ps4rf_bootread.h"

int kexec(void *func, void *user_arg) {
  (void)func;
  (void)user_arg;
  return -1;                 /* no privileged transition without a kernel */
}

uint64_t get_kernel_base(void) {
  return 0ull;               /* no kernel base without a kernel */
}
