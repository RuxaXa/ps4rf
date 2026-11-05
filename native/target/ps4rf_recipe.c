/* ps4rf_recipe.c -- generic bounded snapshot recipe runner (W17). */
#include "ps4rf_recipe.h"

#include <string.h>

static uint64_t load64(const uint8_t *p) {
  uint64_t v = 0;
  for (int i = 0; i < 8; i++) v |= (uint64_t)p[i] << (8 * i);
  return v;
}

int ps4rf_recipe_kva_ok(uint64_t va) {
  return va >= PS4RF_RECIPE_KVA_LO && va <= PS4RF_RECIPE_KVA_HI;
}

int ps4rf_recipe_follow_ok(uint64_t root, uint32_t disp, uint32_t len, uint32_t *why) {
  uint32_t w = PS4RF_RECIPE_WHY_NONE;
  if (root == 0) w = PS4RF_RECIPE_WHY_ROOT_ZERO;
  else if (!ps4rf_recipe_kva_ok(root)) w = PS4RF_RECIPE_WHY_ROOT_CANON;
  else if ((root & 7u) != 0) w = PS4RF_RECIPE_WHY_ROOT_ALIGN;
  else if (disp > PS4RF_RECIPE_MAX_DISP) w = PS4RF_RECIPE_WHY_DISP;
  else if (len == 0 || len > PS4RF_RECIPE_MAX_ENTRY_LEN) w = PS4RF_RECIPE_WHY_LEN;
  else if (root > PS4RF_RECIPE_KVA_HI - (uint64_t)disp - (uint64_t)len) w = PS4RF_RECIPE_WHY_WRAP;
  if (why) *why = w;
  return w == PS4RF_RECIPE_WHY_NONE;
}

int ps4rf_recipe_follow_ok_indexed(uint64_t root, uint32_t base_disp, uint32_t idx,
                                   uint32_t len, uint32_t *why) {
  uint32_t w = PS4RF_RECIPE_WHY_NONE;
  uint64_t span = (uint64_t)idx * 8u + (uint64_t)len;
  if (len == 0 || len > PS4RF_RECIPE_MAX_ENTRY_LEN) w = PS4RF_RECIPE_WHY_LEN;
  else if (base_disp > PS4RF_RECIPE_MAX_DISP) w = PS4RF_RECIPE_WHY_DISP;
  else if (span > PS4RF_RECIPE_MAX_INDEX_SPAN) w = PS4RF_RECIPE_WHY_INDEX_SPAN;
  else if (root == 0) w = PS4RF_RECIPE_WHY_ROOT_ZERO;
  else if (!ps4rf_recipe_kva_ok(root)) w = PS4RF_RECIPE_WHY_ROOT_CANON;
  else if ((root & 7u) != 0) w = PS4RF_RECIPE_WHY_ROOT_ALIGN;
  else if (root > PS4RF_RECIPE_KVA_HI - (uint64_t)base_disp - span) w = PS4RF_RECIPE_WHY_WRAP;
  if (why) *why = w;
  return w == PS4RF_RECIPE_WHY_NONE;
}

int ps4rf_recipe_validate(const ps4rf_recipe_entry *entries, uint32_t count) {
  if (entries == 0) return -1;
  if (count == 0 || count > PS4RF_RECIPE_MAX_ENTRIES) return -1;
  for (uint32_t i = 0; i < count; i++) {
    const ps4rf_recipe_entry *e = &entries[i];
    if (e->length == 0 || e->length > PS4RF_RECIPE_MAX_ENTRY_LEN) return -1;
    if (e->type == PS4RF_RECIPE_TYPE_RVA_READ) {
      if (e->root_index != 0 || e->index_source != PS4RF_RECIPE_INDEX_NONE) return -1;
    } else if (e->type == PS4RF_RECIPE_TYPE_FOLLOW_ONCE) {
      if (e->root_index >= i) return -1;                  /* must name an earlier entry */
      if (e->disp > PS4RF_RECIPE_MAX_DISP) return -1;
      if (e->index_source != PS4RF_RECIPE_INDEX_NONE && e->max_index == 0) return -1;
    } else {
      return -1;
    }
  }
  return 0;
}

static uint32_t index_for(const ps4rf_recipe_entry *e, const uint32_t *indices,
                          uint32_t index_count, uint32_t *why) {
  if (e->index_source == PS4RF_RECIPE_INDEX_NONE) return 0;
  if (indices == 0 || e->index_source > index_count) {
    *why = PS4RF_RECIPE_WHY_INDEX_MISSING;
    return 0;
  }
  uint32_t v = indices[e->index_source - 1];
  if (v > e->max_index || v > PS4RF_RECIPE_MAX_INDEX) {
    *why = PS4RF_RECIPE_WHY_INDEX;
    return 0;
  }
  return v;
}

int ps4rf_recipe_run(const ps4rf_recipe_entry *entries, uint32_t count, uint64_t kbase,
                     const uint32_t *indices, uint32_t index_count,
                     uint8_t *block, uint32_t block_len,
                     ps4rf_recipe_read_fn read_fn, void *ctx,
                     ps4rf_recipe_result *out) {
  if (ps4rf_recipe_validate(entries, count) != 0 || read_fn == 0 || out == 0) return -1;
  memset(out, 0, sizeof(*out));
  out->entries = count;
  out->attach = 0;
  out->kbase = kbase;

  uint32_t cursor = 0;
  for (uint32_t i = 0; i < count; i++) {
    const ps4rf_recipe_entry *e = &entries[i];
    ps4rf_recipe_cell *c = &out->cells[i];
    c->root_index = e->root_index;
    c->why = PS4RF_RECIPE_WHY_NONE;

    uint64_t va = 0;
    if (e->type == PS4RF_RECIPE_TYPE_RVA_READ) {
      va = kbase + e->addr;
      if (!ps4rf_recipe_kva_ok(va)) { c->status = PS4RF_RECIPE_REFUSED; c->why = PS4RF_RECIPE_WHY_ROOT_CANON; continue; }
    } else {
      uint32_t why = PS4RF_RECIPE_WHY_NONE;
      const ps4rf_recipe_cell *root = &out->cells[e->root_index];
      uint64_t root_value = 0;
      if (root->status == PS4RF_RECIPE_OK && root->length == 8) root_value = load64(root->data);
      c->root_value = root_value;
      if (e->flags & PS4RF_RECIPE_FLAG_ATTACH_GATE) {
        if (root_value == 0) { c->status = PS4RF_RECIPE_ATTACH_SKIP; c->why = PS4RF_RECIPE_WHY_ROOT_ZERO; continue; }
      }
      uint32_t idx = index_for(e, indices, index_count, &why);
      if (why != PS4RF_RECIPE_WHY_NONE) { c->status = PS4RF_RECIPE_REFUSED; c->why = why; continue; }
      uint32_t disp = e->disp + idx * 8u;
      int guarded = (e->index_source == PS4RF_RECIPE_INDEX_NONE)
                      ? ps4rf_recipe_follow_ok(root_value, e->disp, e->length, &why)
                      : ps4rf_recipe_follow_ok_indexed(root_value, e->disp, idx, e->length, &why);
      if (!guarded) { c->status = PS4RF_RECIPE_REFUSED; c->why = why; continue; }
      va = root_value + (uint64_t)disp;
    }

    if (cursor + e->length > block_len) { c->status = PS4RF_RECIPE_BLOCK_EXHAUSTED; continue; }
    uint32_t got = 0;
    int rc = read_fn(ctx, va, e->length, block + cursor, &got);
    if (rc != 0 || got > e->length) { c->status = PS4RF_RECIPE_REFUSED; c->why = PS4RF_RECIPE_WHY_ROWS; continue; }
    c->status = PS4RF_RECIPE_OK;
    c->length = got;
    c->addr = va;
    c->data = block + cursor;
    cursor += got;
    out->ok_cells++;
    if (e->type == PS4RF_RECIPE_TYPE_FOLLOW_ONCE && (e->flags & PS4RF_RECIPE_FLAG_ATTACH_GATE)) out->attach = 1;
  }
  out->total_bytes = cursor;
  return 0;
}

const char *ps4rf_recipe_status_name(uint32_t status) {
  switch (status) {
    case PS4RF_RECIPE_OK: return "OK";
    case PS4RF_RECIPE_REFUSED: return "REFUSED";
    case PS4RF_RECIPE_ATTACH_SKIP: return "ATTACH_SKIP";
    case PS4RF_RECIPE_BLOCK_EXHAUSTED: return "BLOCK_EXHAUSTED";
    default: return "UNKNOWN";
  }
}

const char *ps4rf_recipe_why_name(uint32_t why) {
  switch (why) {
    case PS4RF_RECIPE_WHY_NONE: return "NONE";
    case PS4RF_RECIPE_WHY_ROWS: return "READ_ERROR";
    case PS4RF_RECIPE_WHY_LEN: return "LEN";
    case PS4RF_RECIPE_WHY_ROOT_ZERO: return "ROOT_ZERO";
    case PS4RF_RECIPE_WHY_ROOT_CANON: return "ROOT_NOT_CANONICAL";
    case PS4RF_RECIPE_WHY_ROOT_ALIGN: return "ROOT_NOT_ALIGNED";
    case PS4RF_RECIPE_WHY_DISP: return "DISP";
    case PS4RF_RECIPE_WHY_WRAP: return "WRAP";
    case PS4RF_RECIPE_WHY_INDEX: return "INDEX";
    case PS4RF_RECIPE_WHY_INDEX_MISSING: return "INDEX_MISSING";
    case PS4RF_RECIPE_WHY_INDEX_SPAN: return "INDEX_SPAN";
    default: return "UNKNOWN";
  }
}
