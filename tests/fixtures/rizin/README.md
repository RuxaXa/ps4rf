# Rizin adapter fixtures (P3 v0.1)

Offline fixtures for `tools/rizin/` — no real rizin, no network, no artifact
execution (the mock hashes the bytes and serves a canned catalog).

## `artifact.bin`

Synthetic 16 407-byte blob, **not** an executable and not claimed to be one:

```
b"PS4RF-RIZIN-FIXTURE-v1\n" + bytes(range(256)) * 64
```

`sha256 = 2e2a2432c1032d47fcf55327fbc9518ff4c1f822bfad7ec9f78b8c434a1468b5`

The mock (`tools/rizin/mock/rizin_mock.py`) catalogues exactly this hash: any
other artifact is refused (exit 3), which is what makes "unknown artifact" a
testable fail-closed case.

## `stdout-*-v1.txt` — raw stdout captures

Byte-exact stdout of one mock invocation each, as captured by the adapter
(these files are the evidence format itself: the adapter always stores stdout
verbatim and hash-binds it):

| File | Query | `sha256` |
|---|---|---|
| `stdout-analyze-v1.txt` | `aaa` + `ij` + `aflj` (2 marker sections) | `26456a7fab49c18da8001b59d4c769b7c0549b236a4fbb01a84873c742a6bdae` |
| `stdout-xrefs-to-0x401158-v1.txt` | `axtj @ 0x401158` | `e127b685b5861f0fdfdecca1b5101de967af32ec3c6020b56d740fb67127e9cf` |
| `stdout-xrefs-from-0x401070-v1.txt` | `axfj @ 0x401070` | `fd886cd7dc822c67bb8038e3b6ebcef10e4378216bdc401d75767d703a7889c0` |
| `stdout-cfg-0x4010cc-v1.txt` | `agfj @ 0x4010cc` | `5fa2edf6ff794a5a9fbdd7440082502756170b861bce3d6dcfcda115ffd690ff` |
| `stdout-bb-0x401048-v1.txt` | `afbj @ 0x401048` | `3fb9382571abe7cbf22e739c09304196b048df4643606e9341c8d37ff2153949` |

Determinism: two full runs (5 queries each) produced byte-identical stdout per
query (sorted JSON keys, no timestamps, no paths, no seek addresses). Each query
kind gets its own evidence file — `{artifact8}-{kind}[-{target}].stdout.txt` — so
two queries can never clobber each other's capture (regression test:
`test_two_queries_keep_distinct_evidence_files`).

Regeneration recipe (requires the unchanged mock at the pinned version
`0.7.4-mock`, otherwise the pinned hashes deliberately fail):

```bash
.venv/bin/python - <<'PY'
from tools.rizin.adapter import RizinAdapter, RizinConfig
cfg = RizinConfig(work_dir="/tmp/rizin-gen")
a = RizinAdapter(cfg)
art = "tests/fixtures/rizin/artifact.bin"
a.analyze(art, stdout_path="/tmp/rizin-gen/stdout-analyze-v1.txt")
a.xrefs("0x401158", artifact_path=art,
        stdout_path="/tmp/rizin-gen/stdout-xrefs-to-0x401158-v1.txt")
a.xrefs("0x401070", "from", artifact_path=art,
        stdout_path="/tmp/rizin-gen/stdout-xrefs-from-0x401070-v1.txt")
a.cfg("0x4010cc", artifact_path=art,
      stdout_path="/tmp/rizin-gen/stdout-cfg-0x4010cc-v1.txt")
a.boundaries("0x401048", artifact_path=art,
             stdout_path="/tmp/rizin-gen/stdout-bb-0x401048-v1.txt")
PY
```

All hashes above are pinned in `tests/test_rizin_adapter.py`; the parity tests
fail if mock, adapter or fixtures drift apart.
