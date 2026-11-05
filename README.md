# PS4RF — PlayStation 4 Research Framework

PS4RF is an offline-first framework for authorized PlayStation 4 security research. Its
current focus is the static discovery engine under `tools/discovery`: control-flow,
object-lifetime, ownership, lock coverage, firmware differential analysis, candidate queues,
semantic graphs and evidence-backed chain composition.

> **Public source export:** this repository starts from a fresh, one-commit export of the
> reviewed local source. The original Git history is deliberately not published because a
> tracked research archive contained Sony firmware bytes and key-reference material. See
> [`PUBLIC-EXPORT.md`](PUBLIC-EXPORT.md) for provenance and exclusions.

No Sony firmware image, console secret, credential, held-back answer payload or original
Git-history blob is included. You must provide lawfully obtained local images yourself.

## Current verified baseline

- Source lineage: local commit `03a82c8` (baseline `93cc148` + developer patch 01).
- D3 instruction ordering: stores before the first observed lock call in a basic block stay
  exposed; stores after it do not. D3 remains rank 2 — this is not a lock-identity proof.
- Maintainer verification on the pinned local images:
  - discovery tests: **311 passed, 1187 deselected**;
  - FW 13.52: +66 rank-2 D3 identities, 142/142 new stores witnessed before the first lock
    in the same block;
  - FW 9.00 and the actionable labelled-pair gate: unchanged.
- Blind benchmark: **BLOCKED** (no independent uncontaminated holdout).
- Ownership: 12 conditional transfers, 0 proven (`must`) transfers.

Read, in order:

1. [`docs/HANDOFF-DEV-20261105.md`](docs/HANDOFF-DEV-20261105.md)
2. [`docs/S1.9-FINDINGS.md`](docs/S1.9-FINDINGS.md)
3. [`docs/S1.9-MEASUREMENT.md`](docs/S1.9-MEASUREMENT.md)
4. [`docs/DEVELOPER-TAKEOVER-01.md`](docs/DEVELOPER-TAKEOVER-01.md)
5. [`docs/PATCH-01-COUNTERCHECK.md`](docs/PATCH-01-COUNTERCHECK.md)

## Install

Python 3.12 is the measured runtime.

```bash
python3.12 -m venv .venv
. .venv/bin/activate
python -m pip install -e '.[dev]'
```

Exact packages used for the recorded run are listed in `requirements-freeze.txt`; project
constraints live in `pyproject.toml`.

## Synthetic verification (no firmware required)

```bash
python tests/fixtures/discovery/gen_cfg.py --check
python tests/fixtures/discovery/gen_double_release.py --check
python tests/fixtures/discovery/gen_lock_coverage.py --check
python tests/fixtures/discovery/gen_summaries.py --check

python -m pytest -q \
  tests/test_discovery_cfg.py \
  tests/test_discovery_double_release.py \
  tests/test_discovery_lock_coverage.py \
  tests/test_discovery_lock_paths_unit.py
```

Firmware-backed tests and scanner commands require the images configured under
`tools/discovery/data/fw/`. Those JSON files retain the maintainer's absolute paths as
provenance; change `image.path` to your local image while preserving and checking the expected
SHA-256. Never compare measurements from a different image as if they were the frozen baseline.

## Scanner

```bash
python -m tools.discovery.cli facts
python -m tools.discovery.cli validate
python -m tools.discovery.cli scan --fw 13.52 --out scan.json
python -m tools.discovery.cli chainmap \
  --fw 13.52 --scan scan.json --out chains.json
```

Finding ranks are report priorities, not proofs. Every claim must carry an instruction-level
witness or an explicit refusal/counter-evidence reason. `may` must never be presented as `must`.

## Repository layout

- `tools/discovery/` — discovery engine and CLI
- `tools/discovery/data/` — public training/reference corpus, firmware facts and redacted split metadata
- `tests/test_discovery_*.py` — engine regressions
- `tests/fixtures/discovery/` — assembler-backed synthetic fixtures and generators
- `core/`, `ctl/`, `mock/`, `native/` — broader PS4RF framework components
- `docs/` — architecture, evidence boundaries and phase records

## Safety and scope

- Authorized research only.
- No hardware action or payload execution is required by the discovery engine.
- The FW 13.52 measurements use a `NOT_PRISTINE` image; they must not be reported as
  pristine-kernel results.
- The public corpus contains disclosed root-cause material for training and regression. It is
  never a valid blind-test input.
- Local RFC1918 addresses and `/home/hermes` paths remain in historical evidence/configuration
  records. They are inert defaults/provenance, not credentials. Re-point them before use.

## License

No open-source license has been selected. Public visibility does not grant additional reuse
rights; add a license only after the repository owner makes that legal choice.
