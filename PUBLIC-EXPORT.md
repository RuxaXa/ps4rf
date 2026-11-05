# Public export provenance

This repository is a **fresh source export**, not a push of the maintainer's original Git
history.

## Source lineage

- Local integration commit: `03a82c8` — developer patch 01 integrated and independently
  counterchecked.
- Prior S1.9 baseline: `93cc14854e985cf22152c3e560be10cd91e8a201`.
- Original reviewed source ZIP: `ps4rf-source-handoff-93cc148.zip`, SHA-256
  `bb45b381e614684aec76c9667808a1ca15a8f4c2d783240384dd3df454b80a5e`.
- Patch 01 SHA-256:
  `170c9de24e0d7351d21eb65a66725c8a456cb55a2df56901f4ebe190e8631914`.
- Patch 01 handoff SHA-256:
  `df43a5c6da5293eba8a8c3da0da55953312bf4e5ced52f9000c7c696370f747f`.

The public repository has one initial commit so excluded blobs cannot be recovered through its
history.

## Deliberate exclusions

The whole `references/` directory was excluded before `git init`. Its three tracked archives
included, among other research material:

- `fw900-kernel-rx.bin` (Sony firmware-derived bytes),
- an EMC slot body,
- `psdevwiki-ps4-keys.md`.

Those files are not required by `tools/discovery` or its synthetic fixtures. Their paths remain
in the historical `SHA256SUMS`, so `tests/test_freeze_drift.py::test_no_undocumented_drift`
reports those three absent files in this public export. The freeze manifest was intentionally
not rewritten to hide the exclusion.

The two `held_back` records (`pppwn-cycle2`, `relapse-cycle2`) remain present for split/leak
accounting, but their `expected` and `entries` answer payloads are redacted. The live runtime
model string recorded in two historical documents is also replaced with
`[REDACTED_RUNTIME_MODEL]`; generic console model-family/revision values remain because they are
analysis parameters, not unique identifiers.

## Content checks

The export gate rejects:

- `references/` or the three excluded archive names,
- firmware filenames (`kernel.bin`, `fw900-kernel-48m.bin`, `fw900-kernel-rx.bin`),
- private-key markers and common GitHub/cloud token formats,
- nested ZIP files,
- untracked content from the local worktree.

Small `.bin` files under `tests/fixtures/` and `tests/harness/` are synthetic host fixtures,
not Sony firmware. They are retained because tests consume them.

## Known local literals

Some historical evidence and host-tool defaults contain private RFC1918 addresses, the local
account path `/home/hermes`, and a lab worker name. They carry no authentication material and
are kept byte-for-byte because several evidence/profile artefacts are content-hash pinned.
Replace configuration paths and network defaults before use; do not treat them as public
endpoints.

## Verification truth

On the maintainer's analysis host with the two hash-pinned firmware images available:

```text
pytest tests/ -q -k discovery
311 passed, 1187 deselected
```

The full framework suite has seven pre-existing failures (`test_boot_binding_live` ×6 and
`test_target_build` ×1). In this public export, the freeze-drift test adds one expected failure
because the three archived references above are deliberately absent. Firmware-backed tests
cannot reproduce the recorded 311 count without the same images; use the synthetic command set
in `README.md` for a firmware-free check.
