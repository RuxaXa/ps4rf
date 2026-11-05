# P4-W13-C1 — Bounded Region Request Plumbing (offline build, new payload)

Status: **offline green, superseded in one point by WIRE-CATALOG R2 (W13-C2).** The *request
model* of section 2 — the trigger reading its arguments flat from the request body — is obsolete:
the live finding showed the arguments live under `body.arguments`, and the frozen catalog's
`addr`/`size` argument set was replaced by the bounded triplet. See
`docs/P4-W13C2-WIRE-CATALOG-R2.md`; everything else in this document (separation of §70 approval
and release, verification chain, W4/W5/W7 gates, one-shot semantics) still holds.

This wave changes the *read trigger* of the `kernel.read` provider and nothing else. The §70 approval / W13 release separation, the verification evidence
chain, the W4/W5/W7 gates and the one-shot semantics stay exactly as they are.

## 1. Why

The first live W13 research read was refused, correctly and fail-closed: the host trust chain was
intact (§70 approval, release, one-shot, exactly one provider entry, `requests: 0`) but the
*payload* chose the region itself. `ps4rf_kread_probe_request()` returned the first
`STRICT_FINGERPRINT` row of the compile-time table — `image_elf`, index 0, offset 0, 16 bytes — so
the released `amd_iommu` window could never be honoured and the returned event failed the released
window contract (`KREADLIVE_REGION_MISMATCH` → `KREADLIVE_EVENT_CONTRACT`). The release gate was
never the limit; a fixed probe inside the payload was.

## 2. The request model (normative)

The host may send *exactly three integers* and nothing else:

```
{"region_index": <row of the compiled table>, "offset": <bounded>, "length": <1..4096>}
```

* `region_index` names a row of the compile-time generated region table
  (`native/target/ps4rf_kread_regions.h`, generated from `tools/profiles/regions.py`). The host
  derives it from the normative compiled table (`regions.compiled_region_index`) and the release
  pins it; the payload echoes it back and the host re-checks it.
* **Never** in the request: a runtime VA, a kernel VA, a pointer, an arbitrary address, a free RVA
  as a raw number. The parser reads no other key of the request object.
* The payload resolves `region_index → compiled_region_table[index] → compile-time RVA/base →
  checked offset → checked length → internal runtime address`. The host never controls a kernel
  address.

Resolution, all of it inside `ps4rf_kread_run()` and re-checked by the callback, still *before*
`kexec`:

| rule | refusal |
| --- | --- |
| `region_index < compiled_region_count` | `KREAD_REGION_INDEX_INVALID` |
| the row's identity is fingerprintable or structural (never an UNRESOLVED row) | `KREAD_REGION_INDEX_INVALID` |
| `length` in `1..PS4RF_KREAD_MAX_LEN` (4096) | `REQUEST_REFUSED` |
| `offset + length` contained in the row, checked add (no wraparound) | `REQUEST_REFUSED` |

A field that is missing, not an integer, negative or wider than 32 bits is passed as a sentinel
(`PS4RF_KREAD_INDEX_NONE`, `PS4RF_KREAD_OFFSET_NONE`, `PS4RF_KREAD_LENGTH_NONE`) — the value the
provider's own bounds rules must refuse. Nothing is repaired, nothing is defaulted, and there is no
default region: the payload has no probe left.

## 3. Where it lives

* `native/target/ps4rf_agent.c` — the parser (strict, total, sentinels) and the fixed hook: the
  trigger is the `kernel.read` *request* and the call site is
  `ps4rf_kread_run(&g_kread_info, kread_index, kread_offset, kread_length)`. The frozen router
  still answers the operation itself as **deferred privilege** (`OPERATION_DEFERRED`), so the read
  never becomes a wired provider; the host asserts that answer.
* `native/target/ps4rf_kread.c` — `ps4rf_kread_run()` owns the vocabulary above, the one-shot guard
  (set before the single `kexec`) and the event; `ps4rf_kread_probe_request()` is deleted.
* `tools/hostctl/kreadlive.py` — `TRIGGER_OPERATION = 'kernel.read'`, `wire_request_for(window)`
  (the compact request, built **before** the provider entry), the index re-check against the
  released window, `KREADLIVE_REGION_INDEX_MISMATCH`, `KREADLIVE_REGION_NOT_COMPILED`,
  `KREADLIVE_TRIGGER_NOT_DEFERRED`.
* `tools/research/release.py` — the release pins `window.region_index` (cross-checked against the
  compiled table, `W13_RELEASE_INDEX_MISMATCH`) and an optional `payload` binding
  (`W13_RELEASE_PAYLOAD_MISMATCH`): a release for one build never authorises another.

## 4. Gate (build-time, `native/target/build_manifest.py`)

Beyond the existing kread gates (exactly one `kexec` site, guard set before it, no kernel writes,
no arbitrary calls, fixed wire sources) the build now proves:

* the trigger is the `kernel.read` request; the parsed key list is *exactly*
  `[region_index, offset, length]`;
* no address-shaped key is parsed (`address`, `rva`, `runtime_va`, `pointer`, …), the three fields
  are integers, the sentinels exist for the unreadable case;
* each parsed value appears exactly three times (declaration, strict assignment, call) — a fourth
  use is a value on its way somewhere else;
* the module keeps the index bounds check, the row identity check, the length bound, the
  containment check, the checked add, the compile-time table lookup and the rva/VA composition from
  the table row; the host-input key names never appear in the module.

Seven required mutants were built in hard-linked scratch trees (never writing through a link into
the repository); **all seven fail the build**:

| mutant | result |
| --- | --- |
| index bounds check removed | build FAIL |
| containment removed | build FAIL |
| length bound removed | build FAIL |
| raw address field added to the request | build FAIL |
| region index used directly as an address | build FAIL |
| compile-time table lookup bypassed | build FAIL |
| one-shot guard removed | build FAIL |

## 5. Offline regressions

`tests/harness/kread_offline.c` (production path, simulated leaves) gained the C1 cases and now
carries the case's own row identity in every observation: `N` index at table end, `N2`
`0xffffffff`, `O` the released `amd_iommu` row read end to end, `P` offset at row end, `Q`
offset+length one byte over. Existing cases cover `length 0`, `length 4097`, integer overflow and
the boundary read at the region end.

`tests/test_w13_release_separation.py`, `tests/test_w13_release_window.py` and
`tests/test_kreadlive.py` cover the host side: the released row with the matching index reads; a
payload that served row 0 while the release names row 1 is refused (the first live failure,
replayed offline, one provider entry, no read evidence); a payload that reports the wrong index for
the right region is refused; a release with a hand-picked index, a release without an index and a
release bound to another payload are all refused; an unmappable window is refused before the
provider entry with the release untouched.

`x_rehearsal_w13c1.py` (scratch) runs the whole offline chain with the new trust objects and
reports `all_green`.

## 6. New payload identity

The old payload is historical evidence and is not overwritten. The C1 build
(`PS4RF_TARGET_KREAD=1 sh native/target/build_ps4.sh …`, built twice and compared):

* BIN `2a767a88cb6f18eab6dfb881977deff2cdb483c6e3bd2aa19783d8c815bc7e87`
* ELF `a4f987e19386f9a01e309d961bfe04282aef5838be395082a05419e92f2168b2`
* build id `2e6a2d68b3c828855fe4dd4519bdbf7a`, label `ps4rfd-live-w13c1` (the W12 label
  `ps4rfd-live-w12` is retired with the old payload; the build id and the artefact hashes are the
  identity every check compares)

The released window is unchanged: `amd_iommu`, index 1, offset 0, length 16, expected bytes
`414d4420494f4d4d5500696f6d6d7520`, expected SHA256
`0e5db66bb6e045a242282881beb9525d80f00efdccd3586da7d2692e74d4cc5f`.

New trust objects (transcribed offline, bound to the new build):

* §70 approval `§70-W13C1-READ-1-20261006T1510Z`
* W13 release `W13-C1-READ-1-NEW-PAYLOAD`

The consumed `W13-READ-1-LIVE-APPROVAL` is never reused; every release carries a unique
`release_id` and is spent at the provider entry.

## 7. W14 preparation (not implemented here)

The shape introduced by C1 is the shape a resident agent needs later, so nothing here has to be
undone for it:

```
session request → validated (region_index, offset, length) → bounded provider → result
```

W14 would keep that path and add: a persistent agent, several bounded reads per session, and an
explicit multi-read policy. **None of it is built now**: no resident agent, no agent update, no
multi-read, no new provider, no pointer follow.
