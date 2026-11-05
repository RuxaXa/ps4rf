# AFL++ adapter fixtures (P3 v0.1)

Offline fixtures for `tools/aflplusplus/` — no afl binaries, no fuzzing, no
target execution, no external debugger. The mock
(`tools/aflplusplus/mock/afl_mock.py`) applies deterministic mock rules to these
bytes; the real AFL++ semantics land with real tools.

## Synthetic inputs

| File | Content | sha256 |
|---|---|---|
| `target.bin` | `b"PS4RF-AFL-TARGET-v1\n" + bytes(range(256)) * 64` | `7c3408ffce2d37de47dfb79fbf64c91ea94031d185130912b5dd4e1af9ae0a1e` |
| `corpus/seed0.bin` | `00 01 00 02 00 03 00 04` | `fc700fd55e6347e711ea0586b240e7b69815ec943a4001fe268c8f46a76cbc5a` |
| `corpus/seed1.bin` | seed0 + `junk-tail` (same head) | `4c5a96b8d68b0ae95b2a1a3498fcb841c900c5568939f33efc9e609d8bbfa3a6` |
| `corpus/seed2.bin` | `00 05 00 06 00 07 00 08` | `232d53dafea1606ef639e78ea5f3d3e6d7a85724281d412c5f4b83865f1d6401` |
| `corpus/seed3.bin` | `00 01 00 05 00 03 00 07` (subset) | `ea4d707227097746bd4c1892311964b576148ac7f5dfb95f9710b860a47a5c21` |
| `crashes/crash_a.bin` | crash magic + `AAAAAAAA` + `tail1` | `dfb355acb8fa8a80e5e1e12d381e648999882aa943ad417789418731638b802b` |
| `crashes/crash_b.bin` | crash magic + `AAAAAAAA` + `different-tail` | `4956fc17855aa9cdfaad91ee0b749371f38feb3f995613344aa09342f2ed70d7` |
| `crashes/crash_c.bin` | crash magic + `BBBBBBBB` + `tail3` | `6e220af7e1f8778cc76492085bb84bfbf580c4dc850e3863be5b43271e3ee371` |

Crash magic is `b"PS4RF-AFL-CRASH-v1\n"` (19 bytes). Corpus seeds are built so
that `afl-cmin` mock semantics have something to keep and both drop reasons to
show; crash files are built so that triage has one two-member group and one
singleton.

## `result-*-v1.json` + `minimized-crash_a-v1.bin`

Deterministic result documents written by the mock (sorted keys, 2-space
indent, no timestamps, no paths — only hashes and sizes):

| File | Tool | Pinned sha256 |
|---|---|---|
| `result-showmap-seed0-v1.json` | afl-showmap (clean seed) | `dd1c6684d93da8adef8b278f442fcc0e0d87db9509a09fc4414be180517a2262` |
| `result-showmap-crash_a-v1.json` | afl-showmap (crash input) | `f5e0746a9feeba486913c7fe1eeff632153b56c52f3c028b26445a42ce7db310` |
| `result-cmin-v1.json` | afl-cmin | `aca6533192443d96eaced184e6c2500d55adc8acb046b26c57cb40619d4fc26b` |
| `result-tmin-v1.json` | afl-tmin | `6e7f6f6f3c519163114dfdf1e58730a8afa0977bf8e87e1c540e648ba03c949e` |
| `result-collect-v1.json` | afl-collect (triage) | `1b533a4193cb2a6247bb8d5b191c4f59af73c4a9a444e9ea5397b8cb9be1c124` |
| `minimized-crash_a-v1.bin` | afl-tmin output (23 B) | `c4986c5d7f9e0497ca09e07bd99975d4172d4484268c3bf7bec83b3e5e04e5ef` |

Determinism: two full runs produced byte-identical results and minimized files
(`test_run_records_verify_and_detect_tamper`, distinctness test for two
showmap queries). Regeneration recipe:

```bash
.venv/bin/python - <<'PY'
from tools.aflplusplus.adapter import AflAdapter, AflConfig
F, G = "tests/fixtures/aflplusplus", "/tmp/afl-gen"
a = AflAdapter(AflConfig(work_dir=G))
a.showmap(f"{F}/target.bin", f"{F}/corpus/seed0.bin", result_path=f"{G}/showmap-seed0.json")
a.showmap(f"{F}/target.bin", f"{F}/crashes/crash_a.bin", result_path=f"{G}/showmap-crash.json")
a.cmin(f"{F}/corpus", result_path=f"{G}/cmin.json")
a.triage(f"{F}/crashes", result_path=f"{G}/collect.json")
a.tmin(f"{F}/crashes/crash_a.bin", minimized_path=f"{G}/minimized.bin", result_path=f"{G}/tmin.json")
PY
```

All hashes above are pinned in `tests/test_aflplusplus_adapter.py`; the parity
tests fail if mock, adapter or fixtures drift apart.
