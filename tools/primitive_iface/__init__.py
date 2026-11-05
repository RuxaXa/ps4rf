"""P4/W3 primitive interface freeze: host-side schema, validator and stub.

Normative artifacts
-------------------
* ``schema.py``   - the operation table (single source of truth for the surface)
* ``validate.py`` - fail-closed envelope/argument/result validation
* ``stub.py``     - host-side stub provider (unprivileged operations implemented,
                    gated operations refused with ``OPERATION_DEFERRED``)

Prose contract: ``docs/P4-PRIMITIVE-INTERFACES.md``.
"""
