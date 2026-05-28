/*
    Block cipher modes of operation
    Archive of Reversing.ID

    Single source of truth for mode prototypes. Implementations live in mode.c.
*/
#ifndef BLOCK_MODE_H
#define BLOCK_MODE_H

#include <stdint.h>

typedef enum {
    MODE_ECB,
    MODE_CBC,
    MODE_CFB,
    MODE_CTR,
    MODE_OFB,
    MODE_PCBC
} cipher_mode_t;

/* -- Electronic Codebook (ECB) -- */
void encrypt_ecb(uint8_t *data, uint32_t length, uint8_t *key);
void decrypt_ecb(uint8_t *data, uint32_t length, uint8_t *key);

/* -- Cipher Block Chaining (CBC) -- */
void encrypt_cbc(uint8_t *data, uint32_t length, uint8_t *key, uint8_t *iv);
void decrypt_cbc(uint8_t *data, uint32_t length, uint8_t *key, uint8_t *iv);

/* -- Cipher Feedback (CFB) -- */
void encrypt_cfb(uint8_t *data, uint32_t length, uint8_t *key, uint8_t *iv);
void decrypt_cfb(uint8_t *data, uint32_t length, uint8_t *key, uint8_t *iv);

/* -- Counter (CTR) -- */
void encrypt_ctr(uint8_t *data, uint32_t length, uint8_t *key, uint8_t *nonce);
void decrypt_ctr(uint8_t *data, uint32_t length, uint8_t *key, uint8_t *nonce);

/* -- Output Feedback (OFB) -- */
void encrypt_ofb(uint8_t *data, uint32_t length, uint8_t *key, uint8_t *iv);
void decrypt_ofb(uint8_t *data, uint32_t length, uint8_t *key, uint8_t *iv);

/* -- Propagating Cipher Block Chaining (PCBC) -- */
void encrypt_pcbc(uint8_t *data, uint32_t length, uint8_t *key, uint8_t *iv);
void decrypt_pcbc(uint8_t *data, uint32_t length, uint8_t *key, uint8_t *iv);

void encrypt(cipher_mode_t mode, uint8_t *data, uint32_t length, uint8_t *key, uint8_t *iv);
void decrypt(cipher_mode_t mode, uint8_t *data, uint32_t length, uint8_t *key, uint8_t *iv);

#endif
