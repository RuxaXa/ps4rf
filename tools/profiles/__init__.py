"""PS4RF P4/W5 profile binding package (offline, decision-only).

Modules:

* ``schema``      - profile facts, canonical hash, validation, precondition codes, op matrix
* ``binding``     - boot binding, runtime binding, runtime probe contract (never executed here)
* ``loader``      - the only entrance for profile documents (validate + hash-check)
* ``w4_adapter``  - feeds the profile part of the W4 capability gate and nothing else
"""

from tools.profiles.schema import (  # noqa: F401
    SCHEMA_ID, ProfileVerdict, canonical_profile_sha256, empty_profile, evidence_backed,
    operation_matrix, profile_preconditions, unresolved_facts, validate_profile,
)

__all__ = [
    'SCHEMA_ID', 'ProfileVerdict', 'canonical_profile_sha256', 'empty_profile',
    'evidence_backed', 'operation_matrix', 'profile_preconditions', 'unresolved_facts',
    'validate_profile',
]
