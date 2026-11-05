# P4 — Toolchain manifest (W1 deliverable, D4/D16)

The repository is **source of truth** for how a native artifact was built. Every
build — offline prototype today, real payload later — is described by one
manifest file that is validated before anything is produced or delivered.

## 1. Files

| Path | Role |
|---|---|
| `tools/toolchain/toolchain_manifest.py` | validator + CLI (also importable for the gate) |
| `tools/toolchain/examples/toolchain-manifest.example.json` | example, explicitly marked as such (no real SDK is present offline) |
| `tests/test_toolchain_manifest.py` | gate checks: valid example passes, every violation is refused |

## 2. Validation rules (binding)

1. `manifest_version` present; `kind` is `ps4rf.toolchain-manifest`.
2. Every entry of `external_inputs[]` (SDK, toolchain, libraries, corpora) carries
   `name`, `version`, `source_id`/path, and a full lowercase **sha256**. An entry
   without a pin fails validation — this is the D4 rule: *an unpinned external
   SDK must not produce a reproducible build*.
3. `build.compiler` and `build.linker` carry name + version; `build.flags` is a
   list; `build.source_commit` is a 40-char hex git commit.
4. `build.timestamp` may exist but must declare `"hash_authority": false`
   (D16: timestamp is metadata, not hash authority).
5. `artifacts[]`: each entry has `name`, `kind` (`elf` | `bin`), `sha256` and
   `path`. **Every `elf` artifact must declare `elf_type: "ET_DYN"`** — the D2
   build check; `ET_EXEC`/`ET_REL` fails.
6. `pins` in the manifest must agree with the artifact hashes it names (a
   mismatch between a recorded pin and the artifact entry is an error).

## 3. Example

`tools/toolchain/examples/toolchain-manifest.example.json` is a *shape* example for
the W2 skeleton; it deliberately contains placeholder hashes and marks itself
`"example": true`. Real manifests must contain real hashes; the validator refuses
zero/placeholder-only values only when they are syntactically invalid (a real
all-zero hash is syntactically valid, so the *example* flag exists to keep the
distinction visible instead of pretending).

## 4. CLI

```bash
python tools/toolchain/toolchain_manifest.py path/to/manifest.json      # exit 0 = valid
python tools/toolchain/toolchain_manifest.py --self-test               # validate the example
```

## 5. How W2/W4 use it

* W2 (skeleton): produce the manifest for the first ET_DYN build, hash both
  artifacts (ELF + optional flat BIN), validate, archive in the run's evidence.
* W4 (native primitives): the changelog entry for a new primitive references the
  approved Capability Missing Record, the tests and the evidence (§70.10); the
  manifest is part of that evidence.
* P5 handoff: the manifest plus the five items of `docs/PAYLOAD-SDK-CONTRACT.md` §9.

## 6. Why a validator and not just a document

D4 is a *fail-closed* rule: without machine checks, "hash-pinned" degrades into a
comment. The validator turns it into a build gate — the W2 gate calls it, the
tests refuse each violation class, and the manifest's own hash is recorded in the
evidence pack so the pin cannot drift silently.
