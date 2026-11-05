"""PS4RF experiment layer (W17).

Hypotheses are expressed as PS4RF operations, not as new payloads:

  * bounded snapshot  -> ``kernel.snapshot`` (recipe read: RVA_READ + FOLLOW_ONCE)
  * experiment trigger -> ``ioctl.invoke`` (allow-listed device + command policy)

The two experiments (Q6 shared-window aliasing, OWN-1 stale translation) are
state machines over those two primitives; their classification ladders are the
ones proven by the standalone payloads Q6LIVE/OWN1LIVE, which now serve as
offline oracles (``tests/test_experiment_parity.py``).

No addresses, RVAs or device paths live in this package: values come from
fixtures under ``tests/fixtures/experiments/`` (provenance recorded there).
"""
