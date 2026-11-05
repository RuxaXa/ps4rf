# OrbisProbe leads-store fixture

`leads_store.json` is a synthetic leads store **generated with the real OrbisProbe
code** (`LeadStore.to_json()`) to guarantee schema fidelity:

- Source repo: `https://github.com/RuxaXa/Orbisprobe` @ `3ee779f257d3784b5f2cdd768b3dd264b00744f0` (0.3.0.dev0)
- Generator: run in a scratch venv with the real package on `sys.path`; leads are
  synthetic (no live/audit data), covering: active EDGE-2 (score 41), inactive
  EDGE-3PLUS (16), artifact-blocked (-27, nonvolatile sink class), terminal
  VULNERABILITY_CANDIDATE (64, PROOF_MODE), active EDGE-1 (49), active EDGE-0
  PROOF_MODE (52) and a full tie pair (38/38).
- Fixture sha256: `a1c32b0d897fd702a56e842533b8e3e88e6e9f1b5c3539ef383bb686349bc479`
- Expected active ranking on this fixture (produced by the real
  `orbisprobe.leads.scoring.rank_leads`):

  1. `V5-P1-dddddddddddd` (52)
  2. `V5-P1-cccccccccccc` (49)
  3. `V5-P1-0123456789ab` (41)
  4. `V5-P1-eeeeeeeeeeee` (38)
  5. `V5-P1-ffffffffffff` (38)

The adapter's `rank()` mirrors the documented scoring/ordering constants
(`orbisprobe/leads/scoring.py:7-30,59-68,115-131`); the env-gated cross-check test
(`ORBISPROBE_PYTHON` + `ORBISPROBE_SRC`) re-verifies equality against the real
implementation when those are provided.
