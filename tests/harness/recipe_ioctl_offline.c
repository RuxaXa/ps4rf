/* recipe_ioctl_offline.c -- offline harness for the W17 providers.
 *
 * Runs the *generated* recipe table through the real runner against a faked
 * target, then exercises every follow guard, the index bounds, the block bound
 * and the ioctl policy. One JSON line per check.
 */
#include <stdio.h>
#include <string.h>
#include <stdint.h>

#include "ps4rf_recipe.h"
#include "ps4rf_recipe_data.h"
#include "ps4rf_ioctl.h"
#include "ps4rf_ioctl_policy_data.h"

#define IMAGE_LO 0xffffffffd0000000ull
/* W17F: the generated tables are pointer free and carry no named struct per recipe any more. A
   name resolves through the index table to a slice of the flat entry table -- exactly the path the
   provider takes at run time, so the harness exercises the resolution and not a hand-made alias. */
static const ps4rf_recipe_index *g_q6;
static const ps4rf_recipe_index *g_on1;

static const ps4rf_recipe_index *recipe_index(const char *name) {
  for (uint32_t i = 0; i < PS4RF_RECIPE_TABLE_COUNT; i++) {
    if (strcmp(PS4RF_RECIPE_INDEX_TABLE[i].name, name) == 0) return &PS4RF_RECIPE_INDEX_TABLE[i];
  }
  return NULL;
}

#define RECIPE_ENTRIES(ix) (&PS4RF_RECIPE_ENTRIES[(ix)->first])
#define BLOB_CAP 64u

static const uint64_t RVA_CDEV = 0x2684810ull;
static const uint64_t RVA_WIN_A = 0x2684840ull;   /* state + 0x30 */
static const uint64_t RVA_WIN_B = 0x2684848ull;   /* state + 0x38 */
static const uint64_t RVA_BMP_ROOT = 0x238A870ull;
static const uint64_t RVA_PT_ROOT = 0x23D4558ull;

static const uint64_t WIN_A_BASE = 0xffff82da068f0000ull;
static const uint64_t WIN_B_BASE = 0xffff82da068f1000ull;
static const uint64_t BMP_BASE = 0xffffff80055dc000ull;
static const uint64_t PT_BASE = 0xffff82da052c6000ull;

struct state { int attach; int ioctl_calls; int rc; int err; };
static struct state g_state;

static void store64(uint8_t *p, uint64_t v) { for (int i = 0; i < 8; i++) p[i] = (uint8_t)(v >> (8 * i)); }

static int fake_read(void *ctx, uint64_t va, uint32_t len, uint8_t *out, uint32_t *out_len) {
  struct state *st = (struct state *)ctx;
  if (va == 0 || len == 0 || len > PS4RF_RECIPE_MAX_ENTRY_LEN) return -1;
  for (uint32_t i = 0; i < len; i++) out[i] = (uint8_t)((va + i) * 7u);
  if (va >= IMAGE_LO) {
    uint64_t rva = va - IMAGE_LO;
    if (rva == RVA_CDEV) store64(out, 0xffff82da068ef200ull);
    else if (rva == RVA_WIN_A) store64(out, st->attach ? WIN_A_BASE : 0ull);
    else if (rva == RVA_WIN_B) store64(out, st->attach ? WIN_B_BASE : 0ull);
    else if (rva == RVA_BMP_ROOT) store64(out, BMP_BASE);
    else if (rva == RVA_PT_ROOT) store64(out, PT_BASE);
  }
  *out_len = len;
  return 0;
}

static void *fake_open(void *ctx, const char *device, uint32_t flags) {
  (void)flags;
  struct state *st = (struct state *)ctx;
  if (device == NULL || strcmp(device, "/dev/pup_update0") != 0) return NULL;
  return st;
}

static int fake_ioctl(void *ctx, void *fd, uint32_t command, uint8_t *blob,
                      uint32_t blob_len, uint8_t *out, uint32_t *out_len, int32_t *err_out) {
  (void)fd; (void)blob;
  struct state *st = (struct state *)ctx;
  st->ioctl_calls++;
  *out_len = 0;
  *err_out = st->err;
  if (command == 0xC010440Au) { for (uint32_t i = 0; i < 260u && i < PS4RF_IOCTL_MAX_OUT; i++) out[i] = (uint8_t)i; *out_len = 260u; }
  else if (blob_len != 24u) { *err_out = 22; return -1; }
  return st->rc;
}

static void fake_close(void *ctx, void *fd) { (void)ctx; (void)fd; }

/* the provider-owned transfer buffer: the device sees THIS address, never one the caller sent.
   W18: it carries the alignment the driver's cpuaddr boundary check demands. */
static uint8_t g_transfer[PS4RF_IOCTL_XFER_BYTES] PS4RF_IOCTL_ALIGNED;
static uint8_t *fake_transfer(void *ctx, uint32_t len) {
  (void)ctx;
  if (len > (uint32_t)sizeof(g_transfer)) return NULL;
  return g_transfer;
}

/* a second region that is deliberately NOT on the boundary: the provider must refuse it instead of
   handing an address to the device that the driver would reject */
static uint8_t g_offset[PS4RF_IOCTL_XFER_BYTES + 8u];
static uint8_t *fake_transfer_off(void *ctx, uint32_t len) {
  (void)ctx;
  if (len > (uint32_t)sizeof(g_offset) - 1u) return NULL;
  return g_offset + 1u;
}

static void emit(const char *check, int ok, const char *detail) {
  printf("{\"suite\":\"w17_recipe_ioctl_offline\",\"check\":\"%s\",\"ok\":%s,\"detail\":\"%s\"}\n",
         check, ok ? "true" : "false", detail ? detail : "");
}

int main(void) {
  char detail[256];
  memset(&g_state, 0, sizeof(g_state));
  g_state.attach = 1;
  g_q6 = recipe_index("q6-recipe-v3");
  g_on1 = recipe_index("own1-recipe-v2");

  /* 1: generated table */
  ps4rf_recipe_index const *g_diag = recipe_index("diag1-control");
  snprintf(detail, sizeof(detail), "recipes=%u q6_entries=%u own1_entries=%u diag=%d max_entries=%u",
           PS4RF_RECIPE_TABLE_COUNT, g_q6 ? g_q6->count : 0u, g_on1 ? g_on1->count : 0u,
           g_diag != NULL, PS4RF_RECIPE_TABLE_MAX_ENTRIES);
  emit("recipe_table_loaded", PS4RF_RECIPE_TABLE_COUNT == 14u && g_q6 != NULL && g_on1 != NULL
       && g_diag != NULL
       && g_q6->count == 8u && g_on1->count == 12u && g_diag->count == 2u
       && PS4RF_RECIPE_TABLE_MAX_ENTRIES <= PS4RF_RECIPE_MAX_ENTRIES, detail);

  /* 2: full Q6 recipe */
  static uint8_t block[16 * 0x1000];
  ps4rf_recipe_result res;
  int rc = ps4rf_recipe_run(RECIPE_ENTRIES(g_q6), g_q6->count, IMAGE_LO, NULL, 0, block, sizeof(block), fake_read, &g_state, &res);
  snprintf(detail, sizeof(detail), "rc=%d ok=%u attach=%u bytes=%u c3=%s/%s c4=%s/%s root1=%llx",
           rc, res.ok_cells, res.attach, res.total_bytes,
           ps4rf_recipe_status_name(res.cells[3].status), ps4rf_recipe_why_name(res.cells[3].why),
           ps4rf_recipe_status_name(res.cells[4].status), ps4rf_recipe_why_name(res.cells[4].why),
           (unsigned long long)res.cells[1].root_value);

  emit("q6_recipe_run", rc == 0 && res.ok_cells == 8u && res.attach == 1u
       && res.cells[3].addr == WIN_A_BASE + 0x0ull && res.cells[4].addr == WIN_A_BASE + 0x160ull
       && res.cells[7].addr == WIN_B_BASE + 0x160ull
       && res.cells[3].root_value == WIN_A_BASE && res.cells[5].root_value == WIN_A_BASE
       && res.cells[6].root_value == WIN_B_BASE, detail);

  /* 3: attach gate */
  g_state.attach = 0;
  rc = ps4rf_recipe_run(RECIPE_ENTRIES(g_q6), g_q6->count, IMAGE_LO, NULL, 0, block, sizeof(block), fake_read, &g_state, &res);
  int skip = (res.cells[3].status == PS4RF_RECIPE_ATTACH_SKIP) + (res.cells[4].status == PS4RF_RECIPE_ATTACH_SKIP)
           + (res.cells[5].status == PS4RF_RECIPE_ATTACH_SKIP) + (res.cells[6].status == PS4RF_RECIPE_ATTACH_SKIP)
           + (res.cells[7].status == PS4RF_RECIPE_ATTACH_SKIP);
  snprintf(detail, sizeof(detail), "attach=%u ok=%u skipped=%d bytes=%u", res.attach, res.ok_cells, skip, res.total_bytes);
  emit("q6_attach_zero", rc == 0 && res.attach == 0u && skip == 5 && res.ok_cells == 3u, detail);
  g_state.attach = 1;

  /* 4: indexed follows on the OWN-1 recipe */
  uint32_t good[2] = { 3028u, 7u }, bad[2] = { 3029u, 7u };
  rc = ps4rf_recipe_run(RECIPE_ENTRIES(g_on1), g_on1->count, IMAGE_LO, good, 2u, block, sizeof(block), fake_read, &g_state, &res);
  int ok_bmp = res.cells[2].status == PS4RF_RECIPE_OK && res.cells[2].addr == BMP_BASE + 3028ull * 8ull;
  int ok_pt = res.cells[8].status == PS4RF_RECIPE_OK && res.cells[8].addr == PT_BASE + 7ull * 8ull;
  ps4rf_recipe_result bad_res;
  ps4rf_recipe_run(RECIPE_ENTRIES(g_on1), g_on1->count, IMAGE_LO, bad, 2u, block, sizeof(block), fake_read, &g_state, &bad_res);
  snprintf(detail, sizeof(detail), "ok_cells=%u bmp=%d pt=%d bad_status=%u bad_why=%s",
           res.ok_cells, ok_bmp, ok_pt, bad_res.cells[2].status, ps4rf_recipe_why_name(bad_res.cells[2].why));
  emit("own1_indexed_follow", rc == 0 && ok_bmp && ok_pt && bad_res.cells[2].status == PS4RF_RECIPE_REFUSED
       && bad_res.cells[2].why == PS4RF_RECIPE_WHY_INDEX, detail);

  /* 5: follow guards */
  uint32_t why = 0;
  int g1 = !ps4rf_recipe_follow_ok(0ull, 0, 8u, &why) && why == PS4RF_RECIPE_WHY_ROOT_ZERO;
  int g2 = !ps4rf_recipe_follow_ok(0x0000ffff80000000ull, 0, 8u, &why) && why == PS4RF_RECIPE_WHY_ROOT_CANON;
  int g3 = !ps4rf_recipe_follow_ok(BMP_BASE + 1ull, 0, 8u, &why) && why == PS4RF_RECIPE_WHY_ROOT_ALIGN;
  int g4 = !ps4rf_recipe_follow_ok(BMP_BASE, 0x1001u, 8u, &why) && why == PS4RF_RECIPE_WHY_DISP;
  int g5 = !ps4rf_recipe_follow_ok(BMP_BASE, 0, 0x1001u, &why) && why == PS4RF_RECIPE_WHY_LEN;
  int g6 = !ps4rf_recipe_follow_ok(0xfffffffffffffff0ull, 0x10u, 8u, &why) && why == PS4RF_RECIPE_WHY_WRAP;
  int g7 = ps4rf_recipe_follow_ok(0xffff800000000000ull, 0x1000u, 0x1000u, &why) && why == PS4RF_RECIPE_WHY_NONE;
  int g8 = ps4rf_recipe_follow_ok_indexed(BMP_BASE, 0u, 3028u, 512u, &why) && why == PS4RF_RECIPE_WHY_NONE;
  int g9 = !ps4rf_recipe_follow_ok_indexed(BMP_BASE, 0u, 5000u, 512u, &why) && why == PS4RF_RECIPE_WHY_INDEX_SPAN;
  int g10 = !ps4rf_recipe_follow_ok_indexed(0x0000ffff80000000ull, 0u, 1u, 512u, &why) && why == PS4RF_RECIPE_WHY_ROOT_CANON;
  snprintf(detail, sizeof(detail), "zero=%d canon=%d align=%d disp=%d len=%d wrap=%d ok_lo=%d idx_ok=%d span=%d canon_idx=%d", g1, g2, g3, g4, g5, g6, g7, g8, g9, g10);
  emit("follow_guards", g1 && g2 && g3 && g4 && g5 && g6 && g7 && g8 && g9 && g10, detail);

  /* 6: block bound */
  rc = ps4rf_recipe_run(RECIPE_ENTRIES(g_q6), g_q6->count, IMAGE_LO, NULL, 0, block, 300u, fake_read, &g_state, &res);
  int exhausted = 0;
  for (uint32_t i = 0; i < res.entries; i++) if (res.cells[i].status == PS4RF_RECIPE_BLOCK_EXHAUSTED) exhausted++;
  snprintf(detail, sizeof(detail), "exhausted=%d bytes=%u", exhausted, res.total_bytes);
  emit("block_exhausted", rc == 0 && exhausted > 0 && res.total_bytes <= 300u, detail);

  /* 7: a recipe whose follow names a later entry is rejected */
  static const ps4rf_recipe_entry bad_entries[] = {
    { "X", 0u, PS4RF_RECIPE_TYPE_FOLLOW_ONCE, 8u, 1u, 0u, PS4RF_RECIPE_FLAG_ATTACH_GATE, 0ull,
      PS4RF_RECIPE_INDEX_NONE, 0u },
    { "Y", 0u, PS4RF_RECIPE_TYPE_RVA_READ, 8u, 0u, 0u, 0u, 0x100ull, PS4RF_RECIPE_INDEX_NONE, 0u },
  };
  snprintf(detail, sizeof(detail), "validate=%d", ps4rf_recipe_validate(bad_entries, 2u));
  emit("validate_rejects_forward_root", ps4rf_recipe_validate(bad_entries, 2u) != 0, detail);

  /* 8: ioctl policy */
  uint32_t mode1 = 1u, mode2 = 2u;
  const ps4rf_ioctl_rule *rule = NULL;
  int v_dev = ps4rf_ioctl_policy_check(&PS4RF_IOCTL_POLICY, "/dev/other", 0xC0184401u, 24u, NULL, &rule);
  int v_cmd = ps4rf_ioctl_policy_check(&PS4RF_IOCTL_POLICY, "/dev/pup_update0", 0xC0184402u, 24u, NULL, &rule);
  int v_blob = ps4rf_ioctl_policy_check(&PS4RF_IOCTL_POLICY, "/dev/pup_update0", 0xC0184401u, 8u, NULL, &rule);
  int v_mode = ps4rf_ioctl_policy_check(&PS4RF_IOCTL_POLICY, "/dev/pup_update0", 0xC0184404u, 24u, &mode2, &rule);
  int v_nomode = ps4rf_ioctl_policy_check(&PS4RF_IOCTL_POLICY, "/dev/pup_update0", 0xC0184404u, 24u, NULL, &rule);
  int v_ok = ps4rf_ioctl_policy_check(&PS4RF_IOCTL_POLICY, "/dev/pup_update0", 0xC0184404u, 24u, &mode1, &rule);
  snprintf(detail, sizeof(detail), "dev=%s cmd=%s blob=%s mode=%s nomode=%s ok=%s",
           ps4rf_ioctl_verdict_name((uint32_t)v_dev), ps4rf_ioctl_verdict_name((uint32_t)v_cmd),
           ps4rf_ioctl_verdict_name((uint32_t)v_blob), ps4rf_ioctl_verdict_name((uint32_t)v_mode),
           ps4rf_ioctl_verdict_name((uint32_t)v_nomode), ps4rf_ioctl_verdict_name((uint32_t)v_ok));
  emit("ioctl_policy_refusals", v_dev == (int)PS4RF_IOCTL_REFUSED_DEVICE && v_cmd == (int)PS4RF_IOCTL_REFUSED_COMMAND
       && v_blob == (int)PS4RF_IOCTL_REFUSED_BLOB && v_mode == (int)PS4RF_IOCTL_REFUSED_MODE
       && v_nomode == (int)PS4RF_IOCTL_REFUSED_MODE && v_ok == (int)PS4RF_IOCTL_OK
       && PS4RF_IOCTL_POLICY.count == 3u, detail);

  /* 9: bounded invoke returns rc/errno/output */
  const ps4rf_ioctl_ops ops = { fake_open, fake_ioctl, fake_close, fake_transfer };
  uint8_t blob[BLOB_CAP];
  memset(blob, 0, sizeof(blob));
  blob[0] = 1u;
  ps4rf_ioctl_result io;
  g_state.rc = 0; g_state.err = 0; g_state.ioctl_calls = 0;
  ps4rf_ioctl_invoke(&g_state, &PS4RF_IOCTL_POLICY, &ops, "/dev/pup_update0", 0xC0184401u, blob, 24u, NULL, &io);
  int ok_submit = io.verdict == PS4RF_IOCTL_OK && io.rc == 0 && io.out_len == 0u;
  ps4rf_ioctl_invoke(&g_state, &PS4RF_IOCTL_POLICY, &ops, "/dev/pup_update0", 0xC010440Au, blob, 24u, NULL, &io);
  int ok_status = io.verdict == PS4RF_IOCTL_OK && io.out_len == 260u && io.out[5] == 5u;
  g_state.rc = -1; g_state.err = 12;
  ps4rf_ioctl_invoke(&g_state, &PS4RF_IOCTL_POLICY, &ops, "/dev/pup_update0", 0xC0184404u, blob, 24u, &mode1, &io);
  int ok_fail = io.verdict == PS4RF_IOCTL_REFUSED_IOCTL && io.rc == -1 && io.err == 12;
  snprintf(detail, sizeof(detail), "submit=%d status=%d fail=%d calls=%d", ok_submit, ok_status, ok_fail, g_state.ioctl_calls);
  emit("ioctl_invoke_bounded", ok_submit && ok_status && ok_fail && g_state.ioctl_calls == 3, detail);

  /* 10: the corrected submit ABI (W18). The provider overwrites exactly the declared field -- the
   * block's first u64 -- with the address of its own staging region, keeps the caller's request
   * size (field 8) and mode word (field 0x10) byte for byte, and the host value at that offset can
   * never reach the device. A staging region off the driver's 0x4000 boundary is refused. */
  uint8_t abi[24];
  memset(abi, 0, sizeof(abi));
  uint64_t host_ptr = 0xdeadbeefcafe0000ull;   /* what the host would like the device to use */
  store64(abi, host_ptr);
  store64(abi + 8u, 0x4000ull);                /* the request size the handler round checks */
  abi[0x10] = 0x00u;                           /* the proven mode word: base transfer only */
  abi[0x14] = 0xAAu;                           /* padding: must survive untouched */
  const ps4rf_ioctl_rule *abi_rule = NULL;
  int abi_policy = ps4rf_ioctl_policy_check(&PS4RF_IOCTL_POLICY, "/dev/pup_update0", 0xC0184401u,
                                            24u, NULL, &abi_rule) == (int)PS4RF_IOCTL_OK
                   && abi_rule != NULL && abi_rule->ptr_field == 0u;
  static uint8_t payload[0x2000];
  for (uint32_t i = 0; i < (uint32_t)sizeof(payload); i++) payload[i] = (uint8_t)(0x40u + (i & 0x3fu));
  int patched = 0;
  uint8_t *staged = ps4rf_ioctl_stage(&g_state, &ops, abi_rule, abi, 24u, payload,
                                      (uint32_t)sizeof(payload), &patched);
  uint8_t *staged_base = staged;               /* the block is the front of the object */
  uint64_t field0 = 0ull;
  if (staged != NULL) for (int i = 0; i < 8; i++) field0 |= (uint64_t)staged[i] << (8 * i);
  int f0_is_own = staged != NULL
                  && field0 >= (uint64_t)(uintptr_t)(staged_base + PS4RF_IOCTL_DATA_OFFSET)
                  && field0 + (uint64_t)sizeof(payload)
                     <= (uint64_t)(uintptr_t)(staged_base + PS4RF_IOCTL_XFER_BYTES);
  int f0_boundary = staged != NULL && (field0 & (uint64_t)(PS4RF_IOCTL_ALIGN - 1u)) == 0ull;
  int f0_not_host = staged != NULL && field0 != host_ptr && memcmp(staged, abi, 8u) != 0;
  int fields_kept = staged != NULL;
  for (uint32_t i = 8u; staged != NULL && i < 24u; i++) if (staged[i] != abi[i]) fields_kept = 0;
  int payload_ok = staged != NULL && f0_boundary
                   && memcmp((const void *)(uintptr_t)field0, payload, sizeof(payload)) == 0;
  /* a payload that cannot fit behind the aligned boundary is refused, even from a staging region
     that is itself unaligned: the transfer region of that call is one byte off a boundary */
  const ps4rf_ioctl_rule *big_rule = NULL;
  uint32_t one_mode = 1u;                       /* the trigger command requires its declared mode */
  int big_ok = ps4rf_ioctl_policy_check(&PS4RF_IOCTL_POLICY, "/dev/pup_update0", 0xC0184404u,
                                        24u, &one_mode, &big_rule) == (int)PS4RF_IOCTL_OK
               && big_rule != NULL;
  const ps4rf_ioctl_ops ops_off = { fake_open, fake_ioctl, fake_close, fake_transfer_off };
  static uint8_t big[0x10000];
  int patched_off = 0;
  uint8_t *refused = big_ok ? ps4rf_ioctl_stage(&g_state, &ops_off, big_rule, abi, 24u, big,
                                                (uint32_t)sizeof(big), &patched_off) : NULL;
  int fit_guard = big_ok && refused == NULL && patched_off == 0;
  snprintf(detail, sizeof(detail),
           "policy=%d patched=%d f0_own=%d f0_boundary=%d f0_not_host=%d fields_kept=%d payload=%d fit=%d",
           abi_policy, patched, f0_is_own, f0_boundary, f0_not_host, fields_kept, payload_ok,
           fit_guard);
  emit("submit_abi_staged_block", abi_policy && patched == 1 && f0_is_own && f0_boundary
       && f0_not_host && fields_kept && payload_ok && fit_guard, detail);

  return 0;
}
