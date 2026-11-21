#ifndef MICBRIDGE_CRYPTO_H
#define MICBRIDGE_CRYPTO_H
#include <stddef.h>
#include <stdint.h>

void *mb_spake_new(int receiver);
int mb_spake_start(void *ctx, const uint8_t pin[4], uint8_t message[32]);
int mb_spake_finish(void *ctx, const uint8_t message[32], uint8_t secret[64]);
void mb_spake_free(void *ctx);
// Returns the DER certificate length, or zero on failure. The P-256 private key
// uses the uncompressed point followed by the scalar (Security.framework format).
size_t mb_make_identity(uint8_t key[97], uint8_t *certificate, size_t capacity);
#ifdef __APPLE__
#include <Security/Security.h>
int mb_channel_binding(sec_protocol_metadata_t metadata, uint8_t out[32]);
#endif
#endif
