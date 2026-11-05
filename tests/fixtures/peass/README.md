# PEASS adapter fixtures (P4 v0.1)

Offline fixtures for `tools/recon/peass/` — no real PEASS-ng, no target, no
network. Everything here is **synthetic** and clearly marked as such in the
files themselves; no credential or SSID values are present anywhere.

## `scan-linux.txt` / `scan-orbisos.txt`

Deterministic linPEAS-style scan reports emitted by the offline mock
(`tools/recon/peass/mock/linpeas_mock.py`) for a simulated Linux host and a
simulated FreeBSD/OrbisOS (PS4-family) console. Generated 2026-10-05:

```
.venv/bin/python -m tools.recon.peass.mock.linpeas_mock --target linux \
    --output tests/fixtures/peass/scan-linux.txt
.venv/bin/python -m tools.recon.peass.mock.linpeas_mock --target orbisos \
    --output tests/fixtures/peass/scan-orbisos.txt
```

```
scan-linux.txt   sha256 = 5ecef87f3bc15e937d862d29a639a38fcbf6cf98fd31e93139525a57d987c61d
scan-orbisos.txt sha256 = b9ded18bdc3757718a0b71f0cbe038cdb071dc52c57734dcc9a2f8737d4d84d5
```

Determinism: the mock emits sorted sections, no timestamps, no host-local
paths and exactly one trailing newline; two consecutive runs are byte-identical.
The `/usr/...`, `/srv/...`, `/home/operator/...`, `/data/...` paths they mention
are *synthetic target data* (what a scan would observe), not build environment
paths. No real credentials: credential sections report presence only.

## `analysis-linux.json` / `analysis-orbisos.json`

Canonical analysis documents produced by a real adapter run over the scan
fixtures (generated 2026-10-05):

```
.venv/bin/python - <<'PY'
from tools.recon.peass.adapter import PeassAdapter
from tools.recon.peass.models import PeassConfig
adapter = PeassAdapter(PeassConfig(work_dir=".work/peass-gen"))
adapter.ingest("tests/fixtures/peass/scan-linux.txt",
               analysis_path="tests/fixtures/peass/analysis-linux.json")
adapter.ingest("tests/fixtures/peass/scan-orbisos.txt",
               analysis_path="tests/fixtures/peass/analysis-orbisos.json")
PY
```

```
analysis-linux.json   sha256 = c9cb57ad9a584709e00c1cc52693a1ff33576e15aa156e726d79e9bea792442e
analysis-orbisos.json sha256 = cd8c19e88e86aeff2f35fc9d2a369ef9d3d005d8f795db910e34bab2271c6922
```

Each document embeds the sha256 of the scan it was parsed from; it contains no
timestamps, no scanner paths and no host paths, so repeated runs produce
byte-identical output (see `dump_canonical` in `tools/recon/peass/models.py`).

## Mock pin

The mock module itself is pinned too, so drift anywhere in the chain
(mock → scan fixtures → parser → analysis documents) is detected:

```
tools/recon/peass/mock/linpeas_mock.py
    sha256 = dfa6fa833e83c066f3154a1ad865fc05f083257fd2e8a85fb814198b5695628e
```

All five hashes are pinned in `tests/test_peass_adapter.py`; the parity tests
fail if the mock, the parser or the fixtures drift apart. The mock's sha256
changed? Then the scan fixtures must be regenerated with the commands above and
all hashes re-pinned.
