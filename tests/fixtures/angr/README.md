# angr adapter fixtures (P3 v0.1)

Offline fixtures for `tools/angr/` — no angr, no network, no artifact execution
(the mock hashes the bytes and serves a canned catalog).

## `artifact.bin`

Synthetic 16 406-byte blob, **not** an executable and not claimed to be one:

```
b"PS4RF-ANGR-FIXTURE-v1\n" + bytes(range(256)) * 64
```

`sha256 = efd361839429619ba5d83586dc973688fd21c9e55ae9e5b580fcc63db82238dd`

The mock (`tools/angr/mock/angr_mock.py`) catalogues exactly this hash: any
other artifact is refused (exit 3), which is what makes "unknown artifact" a
testable fail-closed case.

## `export-*-v1.json` — runner exports

Deterministic `ps4rf.angr.export/v1` documents written by the mock runner
(sorted keys, 2-space indent, no timestamps, no paths):

| File | Mode | Pinned sha256 |
|---|---|---|
| `export-analyze-v1.json` | analyze (info/entry/functions/cfg) | `6da39512295789260153018aa9915c76f9428b79804ca3fdd2fd47f9acf7c13c` |
| `export-dataflow-0x401060-v1.json` | dataflow (function/edges) | `a3451fbfbd1eca8a93809ba8f3ea124d44d5b63f1049e09b61b8364144fc201d` |
| `export-symbolic-0x40110c-v1.json` | symbolic (target/paths) | `7a2c70980c4b98881549e1161f73bb8d260db5eb3037e674f438ed951a1f0a4c` |

Every export embeds the sha256 of the committed runner placeholder:

`tools/angr/scripts/ps4rf_angr_run.py sha256 = edf328c2a4bf64dabf1e6261094854f6dde9a84a6c069bf540306d18a7388527`

so the adapter's runner-hash binding is a real cross-check between the shipped
contract file and the recorded run (regenerating any export requires the
unchanged placeholder, otherwise the pinned hashes deliberately fail).

**Requests are not committed**: `ps4rf.angr.request/v1` documents embed the
absolute artifact path and are therefore machine-specific. Their shape is
pinned by `test_request_document_matches_contract` instead.

Regeneration recipe (requires the unchanged mock at `9.2.4-mock`):

```bash
.venv/bin/python - <<'PY'
from tools.angr.adapter import AngrAdapter, AngrConfig
cfg = AngrConfig(work_dir="/tmp/angr-gen")
a = AngrAdapter(cfg)
art = "tests/fixtures/angr/artifact.bin"
a.analyze(art, export_path="/tmp/angr-gen/export-analyze-v1.json")
a.dataflow(art, "0x401060", export_path="/tmp/angr-gen/export-dataflow-0x401060-v1.json")
a.symbolic(art, "0x40110c", export_path="/tmp/angr-gen/export-symbolic-0x40110c-v1.json")
PY
```

Determinism: two full runs produced byte-identical exports per (mode, target).
Each mode/target gets its own request and export file
(`{artifact8}-{mode}[-{target}].{request,export}.json`), so queries never
clobber each other's evidence (`test_runs_keep_distinct_evidence_files`).
