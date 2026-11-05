/* ps4rf_recipe.h -- generic bounded snapshot recipe (W17).

A recipe is profile data: an ordered list of at most PS4RF_RECIPE_MAX_ENTRIES
entries, each either an RVA_READ (profile defined region) or a FOLLOW_ONCE
pointer dereference. The provider reads through an injected callback so the
same code runs under the offline harness and on the console.

The host never supplies an address: only a recipe identifier plus the bounded
indices that the declared indexed entries need.
*/
#ifndef PS4RF_RECIPE_H
#define PS4RF_RECIPE_H

#include <stdint.h>

#define PS4RF_RECIPE_MAX_ENTRIES 16u
#define PS4RF_RECIPE_MAX_ENTRY_LEN 0x1000u
#define PS4RF_RECIPE_MAX_DISP 0x1000u
#define PS4RF_RECIPE_MAX_INDEX 0xFFFFu
#define PS4RF_RECIPE_MAX_INDEX_SPAN 0x8000u  /* idx*8 + len, profile declared */
#define PS4RF_RECIPE_NAME_MAX 24u            /* inline name, so the tables stay pointer free */
#define PS4RF_RECIPE_KVA_LO 0xffff800000000000ull
#define PS4RF_RECIPE_KVA_HI 0xffffffffffffffffull

enum { PS4RF_RECIPE_TYPE_RVA_READ = 1u, PS4RF_RECIPE_TYPE_FOLLOW_ONCE = 2u };
enum { PS4RF_RECIPE_INDEX_NONE = 0u, PS4RF_RECIPE_INDEX_BITMAP_WORD = 1u, PS4RF_RECIPE_INDEX_PTSLOT = 2u };
#define PS4RF_RECIPE_FLAG_ATTACH_GATE 1u

/* per cell status */
enum {
  PS4RF_RECIPE_OK = 0u,
  PS4RF_RECIPE_REFUSED = 1u,
  PS4RF_RECIPE_ATTACH_SKIP = 2u,
  PS4RF_RECIPE_BLOCK_EXHAUSTED = 3u
};

/* refusal reasons (stable, part of the evidence format) */
enum {
  PS4RF_RECIPE_WHY_NONE = 0u,
  PS4RF_RECIPE_WHY_ROWS = 1u,
  PS4RF_RECIPE_WHY_LEN = 2u,
  PS4RF_RECIPE_WHY_ROOT_ZERO = 3u,
  PS4RF_RECIPE_WHY_ROOT_CANON = 4u,
  PS4RF_RECIPE_WHY_ROOT_ALIGN = 5u,
  PS4RF_RECIPE_WHY_DISP = 6u,
  PS4RF_RECIPE_WHY_WRAP = 7u,
  PS4RF_RECIPE_WHY_INDEX = 8u,
  PS4RF_RECIPE_WHY_INDEX_MISSING = 9u,
  PS4RF_RECIPE_WHY_INDEX_SPAN = 10u
};

typedef struct {
  /* W17F: the name is an inline array, not a pointer. A pointer-valued initializer would put the
   * table into .data.rel.ro and force R_X86_64_RELATIVE dynamic relocations into the artefact,
   * and this payload is loaded without a dynamic loader: the build gate requires zero
   * relocations. The name is copied at compile time, so the table stays pointer free. */
  char name[PS4RF_RECIPE_NAME_MAX];
  uint32_t recipe_id;       /* index into the pointer-free recipe index table */
  uint32_t type;
  uint32_t length;
  uint32_t root_index;
  uint32_t disp;
  uint32_t flags;
  uint64_t addr;            /* RVA for RVA_READ; 0 for FOLLOW_ONCE */
  uint32_t index_source;    /* PS4RF_RECIPE_INDEX_* */
  uint32_t max_index;
} ps4rf_recipe_entry;

/* one recipe of the generated index: a name, the first entry of the flat table and how many
 * entries belong to it. No pointers -- see above. */
typedef struct {
  char name[PS4RF_RECIPE_NAME_MAX];
  uint32_t first;
  uint32_t count;
} ps4rf_recipe_index;

/* one bounded read; fills out/out_len, returns 0 on success */
typedef int (*ps4rf_recipe_read_fn)(void *ctx, uint64_t va, uint32_t len,
                                    uint8_t *out, uint32_t *out_len);

typedef struct {
  uint32_t status;          /* PS4RF_RECIPE_* */
  uint32_t why;             /* PS4RF_RECIPE_WHY_* */
  uint32_t length;          /* bytes returned */
  uint32_t root_index;
  uint64_t addr;            /* resolved runtime VA, 0 when unresolved */
  uint64_t root_value;      /* the pointer value a follow used, 0 otherwise */
  const uint8_t *data;      /* into the caller's block */
} ps4rf_recipe_cell;

typedef struct {
  uint32_t entries;
  uint32_t attach;          /* 0 when every attach gated entry was skipped */
  uint32_t ok_cells;
  uint32_t total_bytes;
  uint64_t kbase;
  ps4rf_recipe_cell cells[PS4RF_RECIPE_MAX_ENTRIES];
} ps4rf_recipe_result;

int ps4rf_recipe_kva_ok(uint64_t va);
int ps4rf_recipe_follow_ok(uint64_t root, uint32_t disp, uint32_t len, uint32_t *why);
/* indexed follow: the profile declares base disp (<= MAX_DISP) and max_index;
   the index contribution is bounded separately by MAX_INDEX_SPAN */
int ps4rf_recipe_follow_ok_indexed(uint64_t root, uint32_t base_disp, uint32_t idx,
                                   uint32_t len, uint32_t *why);
/* the recipe index table (generated): the caller resolves a name to the slice of the flat entry
   table (both tables are pointer free, see the header of the generated file) */
int ps4rf_recipe_validate(const ps4rf_recipe_entry *entries, uint32_t count);
int ps4rf_recipe_run(const ps4rf_recipe_entry *entries, uint32_t count, uint64_t kbase,
                     const uint32_t *indices, uint32_t index_count,
                     uint8_t *block, uint32_t block_len,
                     ps4rf_recipe_read_fn read_fn, void *ctx,
                     ps4rf_recipe_result *out);
const char *ps4rf_recipe_status_name(uint32_t status);
const char *ps4rf_recipe_why_name(uint32_t why);

#endif /* PS4RF_RECIPE_H */
