# PLACEHOLDER postscript (P3 v0.1).
#
# Interface intent: this file is what a *real* Ghidra headless run would execute
# (`analyzeHeadless ... -scriptPath tools/ghidra/scripts -postScript
# ps4rf_ghidra_export.py <out.json>`) to emit the `ps4rf.ghidra.export/v1`
# document described in tools/ghidra/README.md.
#
# It is NOT run by anything in this repository: the offline mock only hashes it
# (its sha256 is bound into every run record). The real implementation lands in
# a later phase together with the first real Ghidra run; until then the export
# contract is exercised end-to-end through the mock.

SCHEMA_ID = "ps4rf.ghidra.export/v1"


def main(args):  # pragma: no cover - would run inside Ghidra, not here
    raise NotImplementedError(
        "real Ghidra postscript: implement together with the first real "
        "headless run (export contract: %s)" % SCHEMA_ID)


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(
        "This is a placeholder; run it inside Ghidra in a later phase.")
