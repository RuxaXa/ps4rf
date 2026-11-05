#!/usr/bin/env python3
"""W13 — the W6 integration contract: read evidence becomes an input, never an authorisation.

Workflow (owner's §7):

    kernel.read evidence  ->  normalized artifact  ->  W6 differential  ->  OBSERVATION candidates

The normalized artifact is a ``ps4rf.differential.inventory.v1`` document with **relative locators
only** (rva + window); it passes the differential's own normalization, which rejects address-style
fields. The differential then compares two inventories (a pinned baseline and the live read) and
emits findings *and* candidates whose impact on W4 is ``NONE`` -- the existing harness already
states that ("no W4 reason is removed, no provider allowed, no assurance raised"). This module makes
that contract explicit and testable for W13 reads:

* findings and candidates are *observations*; they can never
  - grant or extend a capability,
  - change a region's W13 class,
  - add an entry to the research read plan,
  - produce a new read by themselves;
* the boot/profile binding stays in the research dataset index, not in the differential artifact
  (the artifact must stay boot independent to be comparable).
"""
from __future__ import annotations

import hashlib
import json
import pathlib
import subprocess
import sys

REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:  # allow direct script execution
    sys.path.insert(0, str(REPO_ROOT))

from tools.differential import candidates as DIF_CANDIDATES                 # noqa: E402
from tools.differential.normalize import normalize_document, sha256_bytes    # noqa: E402
from tools.differential.schema import INVENTORY_SCHEMA                      # noqa: E402
from tools.research import classification as C                              # noqa: E402

SCHEMA_CONTRACT = 'ps4rf.research.w6-contract.v1'
TOOL_MODULE = 'tools.differential.cli'

CONTRACT_RULES = (
    'a research read becomes a normalized artifact (ps4rf.differential.inventory.v1) with relative '
    'locators only: the artifact carries an rva window, never a runtime or absolute address',
    'the boot and profile binding stays in the research dataset index; the differential artifact is '
    'boot independent so that two boots (or a pinned image baseline) remain comparable',
    'the differential compares artifact inventories and emits findings plus OBSERVATION candidates',
    'candidates have no authorisation effect: w4 impact NONE, no reason removed, no provider '
    'allowed, no assurance raised, no region promoted and no read plan entry added',
    'a candidate never triggers a read by itself: a follow-up read needs its own approval, session '
    'and stored evidence',
    'the differential output is stored with the dataset snapshot it belongs to (same read_run_id) '
    'so an observation is always traceable to the read that produced it',
)

FORBIDDEN_IN_ARTIFACT = ('runtime_address', 'absolute_address', 'abs_addr', 'slide', 'kbase',
                         'boot_id')


class ContractError(Exception):
    """The artifact or the integration is malformed (fail closed)."""


def read_inventory(*, read_run_record: dict, region_name: str, region_detail: dict | None = None,
                   profile: dict | None = None) -> dict:
    """One normalized artifact inventory for one bounded research read."""
    profile = C.DEFAULT_PROFILE if profile is None else profile
    evidence = (read_run_record or {}).get('read_evidence') or {}
    if evidence.get('requested_region') != region_name:
        raise ContractError(f'the read-run record read {evidence.get("requested_region")!r}, '
                            f'not {region_name!r}')
    raw = bytes.fromhex(evidence.get('bytes_hex') or '')
    if not raw:
        raise ContractError(f'{region_name}: no bytes in the read-run evidence')
    from tools.profiles import regions as R
    registry = R.regions().get(region_name)
    if registry is None:
        raise ContractError(f'{region_name}: not registered')
    if C.classify(registry, profile) != C.CLASS_APPROVED_READ:
        raise ContractError(f'{region_name}: not an APPROVED_READ region, no artifact')
    locator = C.profile_locator(profile, registry.locator) or {}
    digest = sha256_bytes(raw)
    document = {
        'schema': INVENTORY_SCHEMA,
        'kind': 'kernel-window',
        'fixture': False,
        'path': f'kernel/{region_name}',
        'module': 'fw13.52-kernel',
        'architecture': 'x86-64',
        'size': len(raw),
        'manifest_entries': {},
        'notes': [
            'W13 research read artifact: relative locator only (rva + window), no runtime or '
            'absolute address',
            'boot/profile binding lives in the research dataset index, not in this artifact',
            f'read_run_id {read_run_record.get("read_run_id")}',
        ],
        'entries': [{
            'path': f'kernel/{region_name}',
            'kind': 'region-window',
            'locator': {'kind': 'rva', 'value': registry.rva},
            'file_offset': None,
            'size': len(raw),
            'sha256': digest,
            'permissions': locator.get('permissions') or (region_detail or {}).get('permissions'),
            'hash_scope': 'window',
            'window': {'offset': int(evidence.get('requested_offset', 0)), 'length': len(raw)},
        }],
    }
    normalize_document(document, f'kernel/{region_name}')     # fail closed on address-style fields
    return document


def write_inventory(path: str | pathlib.Path, document: dict) -> str:
    """Write the artifact canonically; returns the file hash (the differential's input hash)."""
    target = pathlib.Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(document, indent=1, sort_keys=True, ensure_ascii=False) + '\n')
    return hashlib.sha256(target.read_bytes()).hexdigest()


def differential_command(before: str | pathlib.Path, after: str | pathlib.Path) -> list[str]:
    return [sys.executable, '-m', TOOL_MODULE, 'diff', 'artifacts', str(before), str(after)]


def run_differential(before: str | pathlib.Path, after: str | pathlib.Path) -> dict:
    """Run the real W6 differential over two artifact inventories and return its report."""
    completed = subprocess.run(differential_command(before, after), cwd=str(REPO_ROOT),
                               capture_output=True, text=True)
    if completed.returncode != 0:
        raise ContractError(f'the differential refused: {completed.stderr.strip()[:400]}')
    return json.loads(completed.stdout)


def candidates_of(report: dict) -> list[dict]:
    """The report's candidates, each asserted to be observation-only."""
    candidates = list(report.get('candidates') or [])
    for candidate in candidates:
        impact = candidate.get('impact') or {}
        if candidate.get('status') != 'OBSERVATION':
            raise ContractError(f"a candidate status is {candidate.get('status')!r}")
        if impact.get('w4') != 'NONE':
            raise ContractError(f"a candidate has W4 impact {impact.get('w4')!r}")
    return candidates


def artifact_differences(before: dict, after: dict) -> list[str]:
    """The region windows whose bytes differ between two artifact inventories (observation only)."""
    def by_path(document):
        return {entry['path']: entry for entry in document.get('entries', ())}

    left, right = by_path(before), by_path(after)
    differences = []
    for path in sorted(set(left) | set(right)):
        first, second = left.get(path), right.get(path)
        if first is None or second is None:
            differences.append(f'{path}: {"added" if first is None else "removed"}')
        elif first['sha256'] != second['sha256']:
            differences.append(f'{path}: bytes differ ({first["sha256"][:12]}… vs '
                               f'{second["sha256"][:12]}…)')
    return differences


def contract() -> dict:
    return {'schema': SCHEMA_CONTRACT, 'workflow': 'kernel.read evidence -> normalized artifact -> '
                                                   'W6 differential -> OBSERVATION candidates',
            'rules': list(CONTRACT_RULES), 'artifact_schema': INVENTORY_SCHEMA,
            'forbidden_in_artifact': list(FORBIDDEN_IN_ARTIFACT),
            'differential_command': 'python -m tools.differential.cli diff artifacts <before> <after>',
            'candidate_status': 'OBSERVATION', 'w4_impact': 'NONE',
            'candidates_module': 'tools/differential/candidates.py'}


def contract_problems() -> list[str]:
    """Invariants of the integration, including a real round trip through the W6 harness."""
    problems: list[str] = []
    import tempfile

    if DIF_CANDIDATES.IMPACT.get('w4') != 'NONE':
        problems.append('the differential no longer states W4 impact NONE for candidates')

    baseline = {
        'read_run_id': 'RUN-baseline', 'outcome': 'READ', 'provider_entries': 1,
        'run_separation': {'separated': True, 'run_ids_distinct': True,
                           'session_ids_distinct': True},
        'read_evidence': {'requested_region': 'amd_iommu', 'requested_offset': 0,
                          'observed_length': 4, 'bytes_hex': '414d4420',
                          'output_sha256': sha256_bytes(b'AMD ')},
    }
    changed = json.loads(json.dumps(baseline))
    changed['read_run_id'] = 'RUN-live'
    changed['read_evidence']['bytes_hex'] = '414d4421'
    changed['read_evidence']['output_sha256'] = sha256_bytes(b'AMD!')

    with tempfile.TemporaryDirectory() as tmp:
        try:
            before_doc = read_inventory(read_run_record=baseline, region_name='amd_iommu')
            after_doc = read_inventory(read_run_record=changed, region_name='amd_iommu')
        except ContractError as exc:
            return problems + [f'the artifact builder refused: {exc}']
        before_path = pathlib.Path(tmp) / 'before.json'
        after_path = pathlib.Path(tmp) / 'after.json'
        write_inventory(before_path, before_doc)
        write_inventory(after_path, after_doc)
        blob = json.dumps(before_doc)
        for forbidden in FORBIDDEN_IN_ARTIFACT:
            if f'"{forbidden}"' in blob:
                problems.append(f'the artifact carries a {forbidden} field')
        report = run_differential(before_path, after_path)
        differences = artifact_differences(before_doc, after_doc)
        if not differences:
            problems.append('the round trip found no difference between two different reads')
        candidates = candidates_of(report)
        if not candidates:
            problems.append('the differential produced no candidate for a real difference')
        for candidate in candidates:
            if candidate.get('impact', {}).get('w4') != 'NONE':
                problems.append('a candidate claims W4 impact')
        # a candidate must not be able to add a plan entry: the plan is derived from the
        # classification only, and the classification is data derived -- assert both
        from tools.research import read_plan as RP
        plan = RP.read_plan()
        if report.get('candidates') and set(RP.plan_summary(plan)['regions']) != {
                region.name for region in C.approved_read_regions()}:
            problems.append('the read plan changed after a differential run')
    return problems


def _self_test() -> list[str]:
    problems = contract_problems()
    if problems:
        return problems
    return []


def main(argv: list[str]) -> int:                                          # pragma: no cover
    if '--self-test' in argv:
        problems = _self_test()
        if problems:
            print('w6 contract self-test: FAILED')
            for problem in problems:
                print(f'  - {problem}')
            return 1
        print('w6 contract self-test: OK (relative-locator artifact, real differential round trip, '
              'OBSERVATION-only candidates, no authorisation effect)')
        return 0
    print(json.dumps(contract(), indent=1, sort_keys=True))
    return 0


if __name__ == '__main__':                                                 # pragma: no cover
    raise SystemExit(main(sys.argv[1:]))
