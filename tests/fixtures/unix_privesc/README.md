# unix_privesc fixtures — synthetic collector documents (v0.1)

Offline fixtures for `tools/recon/unix_privesc/` — produced by the inert mock
generator (`tools/recon/unix_privesc/mock/collector_mock.py`). Both documents
are synthetic: fake hosts (`synth-*`), no credentials, generic/typical paths
only. No target was ever touched.

## `collector-linux.json`

Linux variant (`platform_hint`: `Linux`), including `procfs`/`systemd`
entries and no `jails` block.

`sha256 = fcbc305efc0cca7382b13c9d2c91635036604a3e456b6a4c57c14d62a0e8f95b`

## `collector-freebsd-orbisos.json`

FreeBSD/OrbisOS variant (`platform_hint`: `OrbisOS (FreeBSD 12.1, synthetic)`),
including `jails` entries, a `platform_specific` bucket, and **no** `procfs` or
`systemd` material anywhere (no `/proc`, no `systemd` token).

`sha256 = 392384f265fd5704097bb1d8a087ae29d3300a75753ddef3c6bc8622173845c8`

## Determinism

Both documents are byte-reproducible: `json.dumps(..., indent=2,
sort_keys=True)` plus a trailing newline, no timestamps, no absolute generator
paths (target paths are generic/typical). Regeneration must reproduce the
pinned hashes byte-for-byte.

## Regeneration command

From the repo root:

```bash
.venv/bin/python -m tools.recon.unix_privesc.mock.collector_mock \
    --variant linux --out tests/fixtures/unix_privesc/collector-linux.json
.venv/bin/python -m tools.recon.unix_privesc.mock.collector_mock \
    --variant freebsd_orbisos --out tests/fixtures/unix_privesc/collector-freebsd-orbisos.json
```

The hashes above are also pinned in `tests/test_unix_privesc_adapter.py`; a
drift between mock, fixtures and pins fails the test suite and requires
regenerating both the files and the pinned hashes.
