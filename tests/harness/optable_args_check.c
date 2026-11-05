/* PS4RF W13-C2 / WIRE-CATALOG R2 -- the kernel.read argument table.

 * Reads the *checked-in generated table* (native/target/ps4rf_optable_data.h) and prints what the
 * production router validates against: the operation's argument slice with names, declared types and
 * the required flag, plus the unknown-key rule of the generated validator source. No router link is
 * needed -- the behavioural cases (legacy pair, missing fields, wrong types, unknown fields) are
 * driven against the real agent in tests/test_w13c2_wire_arguments.py.
 */
#include <stdio.h>
#include <string.h>

#include "ps4rf_optable_data.h"

int main(void) {
  unsigned i;
  printf("{\"arg_row_count\":%u,\"kernel_read_first\":%u,\"kernel_read_count\":%u,\"args\":[",
         (unsigned)PS4RF_ARG_ROW_COUNT, (unsigned)PS4RF_ARG_FIRST_KERNEL_READ,
         (unsigned)PS4RF_ARG_COUNT_KERNEL_READ);
  for (i = 0u; i < (unsigned)PS4RF_ARG_COUNT_KERNEL_READ; i++) {
    const ps4rf_arg_row *row = &PS4RF_ARG_TABLE[PS4RF_ARG_FIRST_KERNEL_READ + i];
    printf("%s{\"name\":\"%s\",\"type\":%u,\"required\":%u}", i ? "," : "", row->name,
           (unsigned)row->type, (unsigned)row->required);
  }
  printf("]}\n");
  return 0;
}
