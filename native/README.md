# native/ -- PS4RF agent core (P4/W2)

Native userland skeleton of the PS4RF agent plus the offline parity harness. This
is the C counterpart of the frozen Python reference (`core/rpc/handshake.py`,
`core/rpc/wire.py`, `core/canonical.py`); every byte it produces is compared
against the two golden catalogs.

Scope (W2): startup, connect-out transport, AGENT HELLO, HELLO_ACK parsing,
transcript, HKDF, AUTH, AUTH_ACK validation, directional AEAD channels, wire
framing v1, sequence handling, request receive loop (`session.ping`,
`session.bye`), clean disconnect, fatal protocol failure path.

Out of scope: research primitives, kernel interaction, EVENT/READY frames
(reserved, W0/D12), live console execution, SDK helpers (W0/D1 "D first").

## Layout

```
src/sha256.{c,h}              SHA-256, HMAC-SHA256, HKDF-SHA256
src/chacha20poly1305.{c,h}    ChaCha20-Poly1305 AEAD (RFC 8439)
src/jcs.{c,h}                 JSON parser + RFC 8785 canonicalization + ES6 numbers
src/ps4rf_protocol.{c,h}      handshake, AAD, nonces, channels, wire framing v1
src/ps4rfd_main.c             the agent binary (connect-out skeleton)
src/parity_harness.c          offline harness: vectors -> native -> byte compare
tests/                        unit tests for the primitives (self-contained)
build_manifest.py             emits build/toolchain-manifest.json from the real build
```

## Build

```
cd native
make              # build/ps4rfd.elf (ET_DYN), build/ps4rfd.bin, build/ps4rf_parity
make repro        # builds twice in separate trees and compares hashes
make manifest     # build/toolchain-manifest.json, validated by tools/toolchain
```

Flags are pinned in the `Makefile` (no build id, no absolute source paths) so the
same source tree produces byte-identical artifacts. `build/ps4rfd.elf` is the
reproducible build artifact and `build/ps4rfd.bin` the flat delivery payload,
both hashed (W0/D2); the ELF type is verified to be `ET_DYN`.

## Verify

```
cd native
make check        # parity harness against both catalogs + the W2 negative catalog
make self-test    # agent skeleton against an in-process host stub (no network)
```

`make check` runs stages canonicalization, transcript, hkdf, aad, nonce, aead,
frame_header, wire_frame and handshake. A mismatch prints the vector id, the
stage, expected/actual hex, both lengths and the first differing offset. It exits
non-zero on any failure.

`make self-test` uses TEST-ONLY session material from the vectors and never opens
a network socket; the connect-out path is `ps4rfd --connect HOST:PORT --psk-hex …`.

## Host build vs. console target

W2 builds the protocol core for the build host (Linux x86_64, `gcc`) because W2 is
an offline parity milestone: the same code must first be proven byte-identical to
the reference. The console target build (FreeBSD/OrbisOS) needs a cross toolchain
and, if any helper is needed at all, the SDK decision from W0/D1 -- that
requirement is documented in the toolchain manifest (`sdk.used: false`) and stays
open until a real native primitive needs SDK symbols.
