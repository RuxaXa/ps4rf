# tools/knowledge/gtfobins — GTFOBins knowledge adapter (v0.1)

Pure-data, offline knowledge adapter. It turns an **operator-provided local
GTFOBins corpus** (external input, never vendored into this repository) into a
deterministic, hash-bound index, and matches enumerated binaries against that
index. Nothing here is ever executed: recipes are not even stored, and the
package contains no process spawning, no network access, no dynamic loading,
no shell and no execution of corpus content — enforced by a static guard
test.

## Pipeline rule (fixed)

**Never automatic execution of a GTFOBins recipe.** Recon and matching yield
`OBSERVATION`/`CANDIDATE` material only; this adapter emits `CANDIDATE`
records exclusively. PS4RF later decides reachability, attacker control,
preconditions, target compatibility and verification experiments. A candidate
is a pointer into external knowledge with stated preconditions and
`requires_verification=true` — it is never a claim that a technique works on
a target.

## Corpus (external input)

* One entry file per binary, in the upstream GTFOBins on-disk format
  (extensionless YAML document, `---` front matter, `functions` mapping,
  per-example `contexts` blocks, optional per-example `version`, `alias`
  entries). Format provenance with URLs and sha256 values:
  `tests/fixtures/gtfobins/README.md`.
* The path is configurable; point it at the entries directory of a local
  checkout (e.g. `_gtfobins/`). Every non-hidden file under the directory is
  treated as an entry — one unparsable entry refuses the whole build
  (fail closed). Hidden files and directories are ignored.
* Upstream function names are normalized (`file-read` -> `file_read`);
  `restricted_shell` is accepted as a legacy name. Unknown function names and
  unknown context names are refusals. Auxiliary metadata (root `comment`,
  recipe `code`/`comment` fields and similar) is ignored and never stored.

## Index (`ps4rf.knowledge.gtfobins.index/v1`)

`build_index()` yields, per binary:

* `functions` — sorted union of normalized function names and the privilege
  route markers (`sudo`, `suid`, `capabilities`) declared anywhere in the
  entry; `contexts` — the precise per-function route sets;
* `capability_requirements` — per-function capability requirement sets
  (empty inner list = "any declared capability");
* `version_constraints` — sorted union of example-level `version` values;
* `sha256` per file plus one aggregate `corpus_sha256` (sha256 over
  `"{relative_path}\t{file_sha256}\n"` lines sorted by relative path).

The serialization is deterministic: sorted keys, no timestamps, no absolute
paths, trailing newline — so an index can be pinned byte-for-byte (see the
fixture README for the pinned values and the regeneration command).

## Matching rules

Input: one enumerated binary record (`binary_path`, `name`, `version?`,
`owner`, `mode`, `suid`, `sgid`, `capabilities`, `execution_context` in
`sudo` / `suid` / `capabilities` / `session`; `mode` and the suid/sgid flags
must agree — contradictory records are refused).

| Route (context) | Gate |
|---|---|
| `unprivileged` | none (execution access is a PS4RF verification question) |
| `sudo` | `execution_context == "sudo"` |
| `suid` | enumerated `suid == true` |
| `capabilities` | one declared requirement set is covered by the enumerated capability set; a context declared without `list` means "any capability", which still requires at least one capability |

A function matches when at least one of its routes passes; the candidate's
`functions` list carries the matched functions plus the markers of the routes
that passed. No match yields an empty list — never a guess. Version
constraints are **never evaluated**: they surface in `preconditions` as
unverified statements (also when the enumerated binary declares no version),
so applicability is never claimed.

Output: `CANDIDATE` records with `source=external_knowledge`,
`technique=gtfobins`, `binary`, matched `functions`, `preconditions`, a
`reference` URL, `classification=CANDIDATE` and `requires_verification=true`.
The candidate model has **no command/code field** and extra fields are
refused, so recipe text cannot leak into results by construction (tested).

## Fail-closed policy

Refusals (never guesses): missing corpus directory; no entries; unparsable
entry (no `---`, bad YAML, non-mapping root, missing/empty `functions`,
example without `contexts`); unknown function name; unknown context name;
empty capability list; broken alias (missing target, cycle, extra keys);
duplicate entry names; index documents violating the schema; corpus content
drifting from a pinned index (`verify_corpus`).

## Files

| File | Role |
|---|---|
| `models.py` | strict pydantic models (index, enumerated record, candidate), vocabulary and error taxonomy |
| `indexer.py` | deterministic `build_index` / `write_index` / `load_index` / `verify_corpus` / `index_sha256` |
| `matcher.py` | `match_binary`: context gating, candidate-only output, no recipe text |
| `adapter.py` | `GtfobinsAdapter` / `GtfobinsConfig` facade (build/load index, drift check, match) |

Tests: `tests/test_gtfobins_adapter.py` · fixtures: `tests/fixtures/gtfobins/`
(synthetic corpus, pinned index, provenance).
