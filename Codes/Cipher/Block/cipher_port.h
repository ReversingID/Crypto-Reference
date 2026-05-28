/*
    Cipher port (linker contract for mode.c)
    Archive of Reversing.ID

    Each algorithm code.c implements these symbols when built with main.c and mode.c.
    Link exactly one cipher object file per build.
*/
#ifndef CIPHER_PORT_H
#define CIPHER_PORT_H

#include <stdint.h>

#define CIPHER_CTX_MAX 640

// Common block and key size, consensus for this repo
extern const uint32_t CIPHER_BLOCK_BYTES;
extern const uint32_t CIPHER_KEY_BYTES;

void cipher_ctx_init(uint8_t *ctx, const uint8_t *key);
void cipher_encrypt_block(uint8_t *ctx, uint8_t *block);
void cipher_decrypt_block(uint8_t *ctx, uint8_t *block);

#endif
