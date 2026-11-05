"""PS4RF P4/W7 provider wiring: router matrix, provider interface, evidence, dispatch.

The package connects the frozen core (registry, resources, membership) with the W3
primitive interface, the W4 capability gate, the W5 profile binding and the W6
differential findings into one dispatch path:

* :mod:`tools.dispatch.matrix`    - exactly one route per registered operation
* :mod:`tools.dispatch.providers` - the provider interface (validated context in,
                                    structured result out) and the provider states
* :mod:`tools.dispatch.resources` - the per-request view of the central ResourceManager
* :mod:`tools.dispatch.evidence`  - invocation evidence for every attempt
* :mod:`tools.dispatch.dispatch`  - the normative chain and the ONE provider entry site

W7 builds the way, not the primitive: the stub route is wired, all 14 privileged
operations and the host-chain operation stay ``DEFERRED``, so even a fully satisfied gate
answers ``OPERATION_DEFERRED`` with ``provider_entry = false``.
"""

from __future__ import annotations

import importlib.util
import pathlib
import sys

REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

__all__ = ['matrix', 'providers', 'resources', 'evidence', 'dispatch', 'self_test']


def _run_module_self_tests() -> list[str]:
    """Run every module self-test in this package and collect the failures."""
    failures: list[str] = []
    for name in ('matrix', 'evidence', 'providers', 'resources', 'dispatch'):
        path = pathlib.Path(__file__).resolve().parent / f'{name}.py'
        spec = importlib.util.spec_from_file_location(f'dispatch_{name}_selftest', path)
        if spec is None or spec.loader is None:  # pragma: no cover - defensive
            failures.append(f'{name}: cannot load module')
            continue
        module = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = module
        spec.loader.exec_module(module)
        failures.extend(f'{name}: {item}' for item in module._self_test())  # noqa: SLF001
    return failures


def self_test() -> list[str]:
    return _run_module_self_tests()


if __name__ == '__main__':  # pragma: no cover - manual entry
    problems = self_test()
    for problem in problems:
        print(f'  - {problem}')
    raise SystemExit(1 if problems else 0)
