# Ghidra adapter fixtures (P3 v0.1)

Offline fixtures for `tools/ghidra/` — no real Ghidra, no Java.

## `artifact.bin`

Synthetic 16 408-byte blob, **not** an executable and not claimed to be one:

```
b"PS4RF-GHIDRA-FIXTURE-v1\n" + bytes(range(256)) * 64
```

`sha256 = bb249eaf3b7666d21e9149147d4c7a1ef04c4695cd5b539e251094d3795e7c95`

The offline mock (`tools/ghidra/mock/headless_mock.py`) catalogues exactly this
hash: any other artifact is refused (exit 3), which is what makes "unknown
artifact" a testable fail-closed case.

## `export-v1.json`

`ps4rf.ghidra.export/v1` document produced by a real run of that mock through
`GhidraAdapter.analyze()` (generated 2026-10-05, repo commit before P3):

```
.venv/bin/python - <<'PY'
from tools.ghidra.adapter import GhidraAdapter, GhidraConfig
cfg = GhidraConfig(project_dir="/tmp/ghidra-gen/proj")
a = GhidraAdapter(cfg)
a.analyze("tests/fixtures/ghidra/artifact.bin", output_path="/tmp/ghidra-gen/out.json")
PY
```

`sha256 = 82d5e0b82931e98ccfbabde8c9ac3f9fac56683154307da31644cf86321c35b7`

Determinism: two consecutive runs produced byte-identical exports (sorted keys,
no timestamps, artifact path not embedded). The export embeds the postscript
hash, so regenerating this fixture requires the unchanged
`tools/ghidra/scripts/ps4rf_ghidra_export.py`:

`script sha256 = a10264395399644b03b2981de1e18b4da4113f1ac1d5b2a252be23ea0fa9a9f0`

All three hashes are pinned in `tests/test_ghidra_adapter.py`; the parity test
fails if the mock, the postscript or the fixtures drift apart.
