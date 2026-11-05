/* chacha20poly1305.h — PS4RF native agent: ChaCha20-Poly1305 AEAD (RFC 8439).
 *
 * Self-contained C99, no external dependencies. Sealed output layout is
 * ciphertext || 16-byte tag, byte-for-byte compatible with the Python
 * 'cryptography' ChaCha20Poly1305 primitive used by the PS4RF core.
 */
#ifndef PS4RF_CHACHA20POLY1305_H
#define PS4RF_CHACHA20POLY1305_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* AEAD seal: writes ciphertext||tag (pt_len+16 bytes) into ct_out. Returns 0 on success, -1 on invalid arguments
   (null pointers, ct_len_io too small, pt_len > 2^32, etc.). On success *ct_len_io is set to pt_len+16. */
int ps4rf_aead_seal(const uint8_t key[32], const uint8_t nonce[12], const void *aad, size_t aad_len,
                    const void *pt, size_t pt_len, void *ct_out, size_t *ct_len_io);
/* AEAD open: verifies the tag in constant time; writes plaintext (ct_len-16 bytes). Returns 0 on success and
   sets *pt_len_io to ct_len-16; returns -1 on authentication failure OR invalid arguments OR bad ct_len (<16). */
int ps4rf_aead_open(const uint8_t key[32], const uint8_t nonce[12], const void *aad, size_t aad_len,
                    const void *ct, size_t ct_len, void *pt_out, size_t *pt_len_io);

#ifdef __cplusplus
}
#endif

#endif /* PS4RF_CHACHA20POLY1305_H */
