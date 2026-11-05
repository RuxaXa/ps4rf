"""PS4RF knowledge adapters: external security knowledge as pure data.

Knowledge adapters under this package translate operator-provided external
corpora into deterministic, hash-bound indexes and emit candidate records
only. They spawn no processes, access no network, load no code dynamically
and run nothing from a corpus; every emitted candidate requires PS4RF-side
verification before any use.
"""
