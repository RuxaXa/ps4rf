"""PS4RF P4/W6 differential harness (offline, analysis only).

* ``normalize``   - canonical forms, hashes, determinism and fail-closed input rules
* ``schema``      - classifications, confidence, finding/candidate/report validation
* ``inventory``   - offline artifact inventories (zip bundle, ELF, raw blob, inventory)
* ``compare``     - identity/profile/artifact/operation/external comparators + run orchestration
* ``candidates``  - OBSERVATION-only candidate generation with the review/verification path
* ``cli``         - ``diff profiles|artifacts|operations`` and ``report``

W6 is analysis, not authorization: nothing here enables, wires, or raises a capability.
"""

from tools.differential import candidates, compare, inventory, normalize, schema  # noqa: F401

__all__ = ['normalize', 'schema', 'inventory', 'compare', 'candidates']
