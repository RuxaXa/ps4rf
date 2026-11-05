/* PS4RF W17 -- host-build stand-ins for the two SDK entry points the bounded recipe read uses.
 *
 * On the console both come from libPS4 (kexec() makes the privileged transition, and
 * get_kernel_base() returns the LSTAR-derived image base). A host build has no kernel, so this
 * file is deliberately honest about it: kexec() fails and no kernel base exists, so a recipe run
 * reports the failure instead of inventing a measurement -- the fail-closed path.
 *
 * The definitions are WEAK on purpose: the dev-host rehearsal links
 * tests/harness/ps4rf_recipe_sim.c, which defines the same two symbols strongly (a simulated
 * kernel base and a simulated syscall-11 dispatch). That object is only ever linked into a
 * rehearsal build; a console artefact has no simulated object at all.
 */
#include <stdint.h>

#include "ps4rf_recipe_target.h"

__attribute__((weak)) int kexec(void *func, void *user_arg) {
  (void)func;
  (void)user_arg;
  return -1;                 /* no privileged transition without a kernel */
}

__attribute__((weak)) uint64_t get_kernel_base(void) {
  return 0ull;               /* no kernel base without a kernel */
}
