# A1-07 — controlled comparison: seeding vs. budget

**Question the audit left open:** is the graph's blind spot the *seeding* (walking out from
findings only) or the *budget* (96 functions, depth 2)?

**Setup.** One scan artefact (`cli scan --fw 13.52`, 2053 scanned functions, 608 finding
functions), four builds, identical ownership and entry metadata (the same arguments
`cli semgraph` uses — a build without `ownership`/`entry_meta` produces graphs in which every
chain is `possible`, which is a useful negative control and an easy way to fake a measurement).
Chains recomputed per build with the same facts document.

| configuration | seeds | dropped | nodes | fn→fn edges | proved | possible | xsub | alts | max hops |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| centred 96/2 (frozen default) | 96 / 1442 | 1346 | 1814 | 8999 | **211** | 159 | **24** | 313 | 5 |
| whole-program **96/2** | 96 / 2053 | 1957 | 1849 | 9060 | **213** | 157 | **25** | 313 | 5 |
| centred **2000/64** | 1442 / 1442 | 0 | 2584 | 18791 | **255** | 115 | **37** | 436 | 6 |
| whole-program **2000/64** | 2000 / 2053 | 53 | 3088 | 18988 | **254** | 116 | **33** | 409 | 6 |

## Attribution

* **Seeding at constant budget (96/2):** +2 proved chains, +1 cross-subsystem, +61
  function-to-function edges. Real but small.
* **Budget at constant seeding (centred, 2000/64):** +44 proved chains, +13 cross-subsystem,
  +9792 function-to-function edges, +123 published alternatives.
* **Both together:** +43 proved, +9 cross-subsystem, +9989 edges.

**The improvement reported earlier was the budget, not the seeding.** My previous message
attributed the 43 `possible → proved` upgrades and the 9 extra cross-subsystem chains to
whole-program seeding. This controlled run shows that finding-centred mode at the same budget
does slightly *better* (255 vs 254 proved; 37 vs 33 cross-subsystem), because it spends the
whole budget on functions that already carry a finding instead of spending 694 of 2000 slots
on functions that do not. The correction is recorded here rather than quietly restated.

What the seeding actually buys is not evidence strength but **coverage of the space between
findings**: 1279 function nodes and 7080 edge tuples that the finding-centred graph does not
have at all. That matters for a *route* through a wrapper, and it is invisible in the chain
counts of this scan because the budget-2000 finding-centred build already includes the
intermediate functions that carry findings.


## Chain-level inspection: what "proved" actually carries

Identity matters here. Keying a chain by `(detector, function, bug_class, entry)` produced a
nonsense comparison — 34 primitives appeared simultaneously new and vanished, because which
entry wins depends on the path selection. Keyed by the **primitive** and scored by its best
chain, the two builds line up exactly: 370 primitives in both, 0 only-in-base, 0 only-in-wp,
43 upgraded `possible → proved`, 9 new cross-subsystem, 0 downgraded.

**Hop shapes of the 43 upgrades** — every one starts with a proved entry-table hop and then
two to five call/tail-jump hops:

| hop shape | count |
| --- | --- |
| `reaches, calls, calls` | 16 |
| `reaches, calls, calls, calls, calls` | 9 |
| `reaches, calls, calls, calls` | 7 |
| `reaches, calls, tail-jumps, calls, calls, calls` | 5 |
| `reaches, calls, calls, calls, calls, calls` | 5 |
| `reaches, calls, tail-jumps, calls, calls` | 1 |

No upgraded chain contains a `transfers-reference` hop, so none of them makes an object-flow
claim. The chains are reachability arguments, and the D2 chain below rests on the detector's
own `same_object` premise rather than on a proved transfer.

**Requirements at the moment of the upgrade** — this is the part that must not be glossed:

* 42 of 43: `REQ_ENTRY_REACHABLE` CLEARED, `REQ_UNPRIV_ENTRY` **OPEN**,
  `REQ_TWO_CONTEXTS` **OPEN**, `REQ_WIDEN` **OPEN**.
* 1 of 43 (`D2_double_release` @ `0x3ff560` via `sysent[22]`): additionally
  `REQ_NO_NULL_RESET` CLEARED, but `REQ_SPRAY` and `REQ_UNPRIV_ENTRY` remain **OPEN**.

So the upgrade buys exactly one thing: a witnessed control-flow route from a resolved entry to
the function. It does not buy authorization, a second context, or a usable race window. Stated
as a number across the whole artefact: **254 of 254 `proved` chains in the whole-program build
carry `REQ_UNPRIV_ENTRY: OPEN`.** Zero chains exist in which a proved path also clears the
privilege requirement. `proved` therefore means "the code is reachable", and the matrix entry
for A1-01 must not be read as anything stronger.

Two representatives with their witnesses:

* `D3_lock_coverage` @ `0x11d7e0` (`RACE_UNLOCKED_SHARED_WRITE`) via `sysent[335]`:
  `entry:sysent[335] --sy_call--> 0x11ed60 --call @0x11ee32--> 0x11d1a0
  --call @0x11d1d0--> 0x11d7e0`. Three proved hops, three alternatives published.
* `D2_double_release` @ `0x3ff560` (`OWNERSHIP_DOUBLE_FREE`) via `sysent[22]`:
  `0x152800 --@0x152944--> 0x16a590 --@0x16a5df--> 0x3ff560`. Three proved hops.

**The 9 new cross-subsystem chains** are one detector class: all `D3_lock_coverage`
`RACE_UNLOCKED_SHARED_WRITE`, `cross_subsystem = 1`, 4–6 hops, each with `REQ_UNPRIV_ENTRY`,
`REQ_TWO_CONTEXTS` and `REQ_WIDEN` OPEN. A cross-subsystem route is not evidence of a
cross-subsystem *bug*; it means the reachability argument now passes through a subsystem
boundary, which is what makes it worth a human look.

Consistency check that did pass: in both builds, `proved_hops == hop_count` for every chain
reported as `proved`, i.e. no chain claims `proved` while carrying an unproved hop.

## The 53 roots the budget left out

* 53 of 2053 scanned roots are not seeded.
* **2 of them are syscall handlers**: `sysent[693]` @ `0x7ce8ac` and `sysent[696]` @ `0x7ce968`.
* The dropped range is `0x70e0e0 … 0x7ce968`; the scanned range ends at `0x7ce968`, so the
  budget truncated the *top* of the text section. Truncating by ascending address is arbitrary
  with respect to relevance, and here it silently removed two entrypoints.

**Fixed rather than documented:** whole-program seeding now orders roots by priority —
resolved entry handlers first, then functions carrying a finding, then everything else — and
publishes `root_priority` in `expansion`. Rebuilt at the same 2000/64 budget: still 2000 of
2053 seeded, still 53 dropped, but **0 of them are syscall handlers** and the dropped set now
starts at `0x5ff830` instead of the top of the text section (3102 nodes, 21381 edges, i.e.
the same graph plus the two recovered entrypoints). The regression test
`test_a_budget_that_bites_drops_the_least_relevant_roots` pins the ordering.

## What this does not say

* A `proved` hop means a witnessed control-flow or entry edge, not an exploitable primitive.
  Every one of the 370 chains carries `REQ_UNPRIV_ENTRY`-class requirements that the chain
  status does not settle; see the chain-level inspection.
* 53 of 2053 roots fall outside the whole-program budget, and the budget truncates by
  ascending RVA, i.e. the highest-addressed functions are dropped regardless of relevance.
  That is an ordering defect in the truncation policy, not a property of the image.
* Both high-budget builds are ~2-4 minutes per graph on this machine; the frozen default
  stays at 96/2 for that reason as much as for comparability.
