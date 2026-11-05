/*
 * sha256.h -- PS4RF native agent: SHA-256, HMAC-SHA256, HKDF-SHA256 (C99).
 *
 * Self-contained, no external dependencies. See sha256.c for the
 * FIPS 180-4 / RFC 2104 / RFC 5869 implementation.
 */

#ifndef PS4RF_SHA256_H
#define PS4RF_SHA256_H

#include <stddef.h>
#include <stdint.h>

/* One-shot SHA-256. Writes the 32-byte digest to `out`. */
void ps4rf_sha256(const void *data, size_t len, uint8_t out[32]);

/* One-shot HMAC-SHA256 (RFC 2104). Keys longer than the 64-byte block are
 * hashed first. Both key_len and msg_len may be zero. */
void ps4rf_hmac_sha256(const void *key, size_t key_len,
                       const void *msg, size_t msg_len, uint8_t out[32]);

/* RFC 5869 HKDF-SHA256 (extract-then-expand). Returns 0 on success; -1 on
 * invalid arguments (out == NULL, out_len == 0, a NULL data pointer with a
 * non-zero length, or out_len > 255*32 = 8160).
 *
 * out_len == 4 is used by the protocol for nonce prefixes; out_len up to
 * 32+ bytes works for the handshake keys. */
int ps4rf_hkdf_sha256(const void *ikm, size_t ikm_len,
                      const void *salt, size_t salt_len,
                      const void *info, size_t info_len,
                      void *out, size_t out_len);

#endif /* PS4RF_SHA256_H */
