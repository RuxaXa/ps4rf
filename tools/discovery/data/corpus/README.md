# PS4/PS5 exploit corpus — schema and separation policy

Purpose: a historical corpus of published PlayStation 4 / PlayStation 5 kernel and
userland bugs, used (a) to derive and test generic detectors and (b) to measure whether
the engine can rediscover a bug it was never told about. Those two uses must never share
labels.

## Separation policy (binding)

* `training` — the case is allowed to shape rules, ranking and heuristics. It may be cited
  as a positive result. Its root cause may be described in `families.json`.
* `held_back` — the case must **not** touch rules, search space, ranking or detector code.
  Only its existence and its firmware range may be recorded here. Any work that reads a
  held-back root cause must be documented as such before it happens.
* `burned` — the case has been used to change rules and can no longer validate anything.
  It stays as a regression control only. A burned case must never be re-labelled as a
  blind test, and a family whose root cause is described in this repository is burned by
  definition.
* `negative` — a false-positive denominator, always scoped to specific functions and a
  specific bug class. An unlabelled function is `UNKNOWN`, never a true negative.

Corollary: a blind test is only fresh if the *whole* available context is clean — agent
history, evidence directories, prompts and summaries, not just detector sources. That is
audit finding A1-08 and it stays open until a new held-back set is locked in a separate
process.

## Entry shape

One file per family under `tools/discovery/data/corpus/<family>.json`:

```json
{
  "id": "pppwn",
  "name": "PPPwn — PPPoE/sppp LCP-Configure-Request heap overflow",
  "role": "training|held_back|burned",
  "burned_reason": "",
  "platform": ["ps4", "ps5"],
  "bug_class": "HEAP_OVERFLOW",
  "subsystem": "network/ppp",
  "root_cause": {
    "summary": "one paragraph, mechanism only",
    "primitive": "linear heap overflow into an adjacent kmalloc bucket",
    "trigger": "unauthenticated LCP Configure-Request over PPPoE",
    "consequence": "controlled kernel heap overwrite"
  },
  "discovery_approach": {
    "summary": "how the public research found it",
    "signals": ["what a scanner could have seen"],
    "blind_usable": false
  },
  "firmware": {
    "affected": ["7.50", "9.00", "11.00"],
    "fixed_in": "11.50",
    "differences": ["what changed between versions"]
  },
  "patch_evidence": {
    "available": true,
    "what": "public writeup, no binary diff in this repo",
    "limits": "no firmware bytes are stored here"
  },
  "sources": [
    {"url": "https://…", "supports": "which claim it backs", "kind": "writeup|repo|advisory"}
  ],
  "confidence": "high|medium|low",
  "gaps": ["what is still unknown"]
}
```

Rules for entries:

* Every non-obvious claim carries a source. A claim without a source is `confidence: low`
  and lands in `gaps`.
* No firmware bytes, no Sony binaries, no keys, no console addresses in this directory.
  Offsets from public writeups may be quoted as text with the source that states them.
* `discovery_approach.blind_usable` is `false` for every case whose root cause is written
  down here — that is what "burned" means in practice.
* Firmware differences must name the mechanism that changed (driver replaced, check
  added, allocator flag changed), not just "patched".
