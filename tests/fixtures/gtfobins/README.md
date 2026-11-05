# GTFOBins adapter fixtures (knowledge adapter v0.1)

Offline fixtures for `tools/knowledge/gtfobins/` — the corpus is an external
input and is **not** vendored; everything in this directory is synthetic.

## Provenance of the on-disk format (consulted 2026-10-05, not vendored)

The corpus format was confirmed against the public GTFOBins repository
(`GTFOBins/GTFOBins.github.io`, branch `master`) by fetching these files
read-only. None of them is vendored into this repository; the fixtures below
are written by hand in the same format with **invented placeholder recipes**
(no upstream recipe text was copied):

| URL | `sha256` |
|---|---|
| `https://raw.githubusercontent.com/GTFOBins/GTFOBins.github.io/master/_gtfobins/find` | `05ca0fbad02068f852e26a7853eb4f6305b6ff6529eb95096f332f5698bd228a` |
| `https://raw.githubusercontent.com/GTFOBins/GTFOBins.github.io/master/_gtfobins/base64` | `d8385206ee59428e347980801b05aca4bd323c82f972300d2bca6e38d32d7c81` |
| `https://raw.githubusercontent.com/GTFOBins/GTFOBins.github.io/master/_data/functions.yml` | `4d94fb9882f8db039817031eabc4864830ac977e0333af10de50a19d5222bd69` |
| `https://raw.githubusercontent.com/GTFOBins/GTFOBins.github.io/master/_data/contexts.yml` | `e71e8522809b22f713a46336527b480644c9500d57015ecb733cef86b1ab2c0e` |
| `https://raw.githubusercontent.com/GTFOBins/GTFOBins.github.io/master/linter/schema.py` | `3e8de6772c0d135c929d61c8693b32ce40a2450a1c0da36277f7515d4573e2af` |
| `https://raw.githubusercontent.com/GTFOBins/GTFOBins.github.io/master/linter/loader.py` | `d9efcfc52f432e030cc3cf69415eddc5fb1449cd0387ea0d4ffda248c074f626` |
| `https://raw.githubusercontent.com/GTFOBins/GTFOBins.github.io/master/CONTRIBUTING.md` | `ee8693417eed86012d79cf571275352c20c7bedb8cc2fafbc60a6be74b2a8482` |

Confirmed on-disk facts used by the indexer: one extensionless YAML file per
binary under `_gtfobins/`, opening `---` front matter delimiter, a
`functions` mapping whose values are lists of examples, per-example
`contexts` blocks (`unprivileged` / `sudo` / `suid` / `capabilities`, with
`list: [CAP_*]` under `capabilities`), an optional per-example `version`
field, and `alias: <name>` entries.

## `corpus/` — synthetic entries (all clearly labelled synthetic)

Six extensionless files in the upstream format. The label `synthetic-` marks
them as fixtures; names do not collide with real upstream entries and every
`code` value is an invented placeholder (`./synthetic-*`), not a recipe.

| File | Routes exercised | `sha256` |
|---|---|---|
| `corpus/synthetic-alpha` | sudo + suid + capabilities + unprivileged, version constraint | `7548376093538802d499df2929e99ac2abe268382d9696d3c92f90c471d79f4a` |
| `corpus/synthetic-beta` | unprivileged only (incl. legacy `restricted_shell` name) | `75c5a98b9b33d0001d7833ae0c617964e47e74aac794281b46f1cb6db7bbf6b1` |
| `corpus/synthetic-delta` | suid only (gating fixture) | `345ff0b8cbc602615f272ba76f4b39146fa9ba5da28997c6b3b6b2f3084a7582` |
| `corpus/synthetic-epsilon` | capabilities only (incl. a no-`list` "any capability" route) | `a29644cfb1e4655838522e97ad5e33e14424c656e3e9973480180bb85b52fd95` |
| `corpus/synthetic-gamma` | sudo only (gating fixture; alias target) | `00bc4f93bda250896b1a7240fd7c4313e31cff7e2e9fff278643598e53fcce41` |
| `corpus/synthetic-zeta` | alias entry (`alias: synthetic-gamma`) | `f8bda947ccb2dcaa2038ae0da6a06cdffe235c3b5053ec3403c47c53acff5e5b` |

Aggregate corpus hash (definition: sha256 over `"{relative_path}\t{file_sha256}\n"`
lines sorted by relative path, UTF-8):

`corpus_sha256 = 0d4f9c0d361760e6f5517ce49e80df6c43aa0784943cf21299a0f02587025ee2`

## `index-v1.json` — pinned index (`ps4rf.knowledge.gtfobins.index/v1`)

Produced by `build_index()` from `corpus/`; deterministic (sorted keys, no
timestamps, no absolute paths, trailing newline), so the bytes are pinned:

`sha256 = ea380ae47a3606e6202ea8251ce5f624ca4f41820889c16a577c3709d7396b6f`

Both values are pinned in `tests/test_gtfobins_adapter.py` (`CORPUS_SHA`,
`INDEX_SHA`); the drift tests fail if the corpus or the index changes without
regeneration. No recipe text reaches the index by construction: only
technique routes, capability requirement names, version-constraint strings
and the per-binary reference URL are stored.

Regeneration recipe (from the repo root, requires the unchanged `corpus/`):

```bash
.venv/bin/python - <<'PY'
from tools.knowledge.gtfobins.indexer import build_index, write_index
index = build_index("tests/fixtures/gtfobins/corpus")
write_index(index, "tests/fixtures/gtfobins/index-v1.json")
PY
```

Determinism was checked by rebuilding from a copy of `corpus/` at a different
absolute path: byte-identical index (no path dependence).
