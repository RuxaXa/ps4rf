"""PEASS-ng / linPEAS tool adapter for PS4RF (P4).

Offline-first: everything is exercised against the synthetic scan mock in
``tools/recon/peass/mock`` -- no target contact, no network, no real PEASS-ng
installation. The adapter ingests linPEAS-style scan output; PS4/OrbisOS
compatibility is policy-gated (LINUX targets only) and every finding is an
OBSERVATION requiring verification -- see ``tools/recon/peass/README.md``.
"""
