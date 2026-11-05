# P3 — Blind-test architecture for autonomous root-cause rediscovery

**Status:** design + first executable slice (`tools/discovery/splits.py`).
**Decision it implements:** no historical root cause is deleted from the repository. All 19
corpus families stay in the training and regression corpus with their full references. Blind
evidence is produced by *separation of contexts*, not by removing knowledge from this one.

## Why separation, not deletion

The old plan was to withhold families from the corpus. That is wrong twice over: it destroys
the regression value of the best-documented families, and it does not even produce a blind
test, because this session has already read those root causes. Deleting the file does not
delete the agent context, the delegation logs, the skills, the chat summaries or the model's
own training data.

A case is blind iff the **solving context** never had access to the answer. That is a property
of process, directories, credentials and exposure history — not of a file's absence.

## Four corpora, four claims

| Corpus | Contents | Claim it supports | Claim it must never carry |
| --- | --- | --- | --- |
| `train` | the 19 families, full references, firmware map, mitigations | "the rules were shaped by known history" | any generalisation claim |
| `retro` | questions masked from *known* families (name, root cause, patch, class stripped) | "the engine can re-derive what we already documented" — **retrospective, explicitly not blind** | "blind", "independent", "generalisation" |
| `holdback` | questions from families that were never described in this repo, in any session, or in any skill | "independent rediscovery" | — |
| `variant` / `cross` | variants of known families on other firmware bands; chains that must cross a subsystem boundary | "rule vs. memorisation", "combination capability" | "new family discovery" |

The naming is load-bearing. A retrospective pass is a capability measurement with known
contamination; calling it blind is the exact over-claim the audit rejected.

## Directory separation (mechanical, not advisory)

```
/home/hermes/work/ps4rf-a1/                    # DISCOVERY TREE — the engine's world
  tools/discovery/data/corpus/                 #   train + burned, full references
  tools/discovery/data/blind/<split>/          #   questions only: firmware id, image hash,
                                               #   scope; no class, no site, no patch
  tools/discovery/splits.py                    #   manifest verifier (no answers inside)
  tools/discovery/seal.py                      #   audit hook: refuses corpus/blind reads
                                               #   during a blind run

/home/hermes/ps4rf-eval/                       # EVALUATOR ROOT — never mounted, never read
  splits/<split>/manifest.json                 #   hashes + case list + exposure history
  solutions/<split>/answers.json               #   root-cause oracle (site, class,
                                               #   mechanism, patch evidence, authorization)
  exposure.log                                 #   append-only, one line per exposure event
  scorecards/<split>/<run-id>.json             #   per-case verdicts + leak-audit result
```

The discovery process runs with the discovery tree as its only project path. The evaluator
runs as a **different process, different working directory, no shared environment**, invoked
by a human, after the discovery run has finished and its artefacts are written. It never runs
the engine; the engine never sees `solutions/`.

## Split manifest — versioned and immutable

Each split is created once and then frozen:

* `split_id` is unique and never reused (`holdback-r1`, `variant-r2`, …).
* `manifest.json` records for every case: `case_id`, `firmware`, `image_sha256`,
  `question_sha256` (hash of the masked question payload), `answer_sha256` (hash of the
  corresponding entry in `solutions/`), `created_at`, `kind`, `model_prior_risk`.
* Any change to a question or an answer produces a **new split_id**; mutating a frozen split
  is refused by the verifier, because a moving evaluation is not an evaluation.
* `exposure.log` is append-only; the verifier refuses a log that lost a line. Each line:
  `{ts, split_id, case_id, actor, channel, detail, contamination}`.

## Exposure history decides the label

`contamination` levels: `none`, `metadata` (name/firmware known), `root_cause`,
`full_solution`. Any case at `root_cause` or `full_solution` is **downgraded to `retro`
automatically** and may not carry `blind_claim: true`.

The honest starting position: **this session read all 19 root causes** (corpus merge,
`families.json`, SOURCES references). All 19 therefore enter `exposure.log` at
`contamination: root_cause`, and the only corpora available today are `train` and `retro`.
That is the correct state, and the verifier says so rather than letting a `holdback` label be
declared by intention.

## Root-cause oracle

`solutions/<split>/answers.json` uses the same schema the scorer consumes — site(s) with a
byte tolerance, bug class, mechanism text (never keyword-matched), patch evidence, entry
authorization basis, object-relation claim. The oracle is the *only* place a solution exists
in machine-readable form, and it lives outside the discovery tree.

## Leak audit (runs before any score is produced)

Refuses the evaluation — not warns — if any of the following holds:

1. An `answers.json` path resolves under the discovery tree.
2. The discovery tree (code, docs, data, `tools/discovery/data/reference/`) contains a token
   from the answer set: family name, CVE id, distinctive mechanism phrase.
3. Any commit in the discovery repository's history contains those tokens
   (`git grep <token> $(git rev-list --all)`), because a reverted leak is still a leak.
4. The declared agent surfaces contain them: skills directory, memory files, delegation logs,
   session artefacts under a declared list of roots.
5. `model_prior_risk: high` for a case that is publicly documented (PPPwn, pOOBs4, BD-J,
   Lapse/ReLapse, …) and the run claims it as independent evidence. Those cases can only
   support a *variant* claim at best; a strong blind claim needs a family that is not
   publicly attributed.
6. The run's own artefacts were written under the discovery tree **before** the seal was
   active (`blindrun.py` records the seal state; a run without it is not scored).

## Generalisation tests this enables

* **Family** — hold back whole families (not single cases): if the engine only finds the
  mechanism class it has a rule for, family-level holdback exposes it.
* **Variant** — same mechanism, different firmware band or struct layout; the answer's site
  moves, so a hardcoded offset fails and a real analysis passes.
* **Cross-subsystem** — the case is only reachable by chaining two subsystems; scored on the
  chain, not on the primitive alone.

## What this architecture refuses to claim

* A retrospective pass is not evidence of generalisation, no matter how clean the masking.
* A single holdback hit is not generalisation; the next case must not be a variant of it.
* Model priors cannot be measured from inside this machine. They are declared per case
  (`model_prior_risk`) and excluded from the claim, not measured away.
