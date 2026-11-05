"""Platform-independent local enumeration adapter (tools/recon/unix_privesc).

Offline, pure-data layer: it parses hash-bound collector documents and
classifies the captured categories per target platform (Linux | FreeBSD/OrbisOS
| unknown). Linux- and OrbisOS/FreeBSD-specific checks can be derived from it
later; PS4-specific checks are owned by PS4RF surface/experiment modules.

The mock generator in ``mock/collector_mock.py`` is inert and deterministic.
"""
