/*
    Block cipher modes of operation
    Archive of Reversing.ID

    Shared ECB, CBC, CFB, CTR, OFB, and PCBC over the cipher port in each code.c.

Compile:
    (msvc, from Codes/Cipher/Block/)
    $ cl /I. main.c mode.c <CipherDir>/code.c

    (gcc, from Codes/Cipher/Block/)
    $ gcc -I. -o test main.c mode.c <CipherDir>/code.c
*/
#include "mode.h"
#include "cipher_port.h"
#include <string.h>

#define BLOCK_BUF_MAX 16


/* --- Helper Functions --- */
static void
xor_bytes(uint8_t *dst, const uint8_t *src1, const uint8_t *src2, uint32_t n)
{
    uint32_t i;
    for (i = 0; i < n; i++)
        dst[i] = src1[i] ^ src2[i];
}


/* --- Electronic Codebook (ECB) --- */
void
encrypt_ecb(uint8_t *data, uint32_t length, uint8_t *key)
{
    uint32_t i;
    uint8_t  ctx[CIPHER_CTX_MAX];

    cipher_ctx_init(ctx, key);

    for (i = 0; i < length; i += CIPHER_BLOCK_BYTES)
        cipher_encrypt_block(ctx, &data[i]);
}

void
decrypt_ecb(uint8_t *data, uint32_t length, uint8_t *key)
{
    uint32_t i;
    uint8_t  ctx[CIPHER_CTX_MAX];

    cipher_ctx_init(ctx, key);

    for (i = 0; i < length; i += CIPHER_BLOCK_BYTES)
        cipher_decrypt_block(ctx, &data[i]);
}

/* --- Cipher Block Chaining (CBC) --- */
void
encrypt_cbc(uint8_t *data, uint32_t length, uint8_t *key, uint8_t *iv)
{
    uint32_t  i;
    uint8_t   ctx[CIPHER_CTX_MAX];
    uint8_t  *prev_block = iv;

    cipher_ctx_init(ctx, key);

    for (i = 0; i < length; i += CIPHER_BLOCK_BYTES)
    {
        xor_bytes(&data[i], &data[i], prev_block, CIPHER_BLOCK_BYTES);
        cipher_encrypt_block(ctx, &data[i]);
        prev_block = &data[i];
    }
}

void
decrypt_cbc(uint8_t *data, uint32_t length, uint8_t *key, uint8_t *iv)
{
    uint32_t i;
    uint8_t  ctx[CIPHER_CTX_MAX];
    uint8_t  prev_block[BLOCK_BUF_MAX];
    uint8_t  ctext_block[BLOCK_BUF_MAX];

    cipher_ctx_init(ctx, key);
    memcpy(prev_block, iv, CIPHER_BLOCK_BYTES);

    for (i = 0; i < length; i += CIPHER_BLOCK_BYTES)
    {
        memcpy(ctext_block, &data[i], CIPHER_BLOCK_BYTES);
        cipher_decrypt_block(ctx, &data[i]);
        xor_bytes(&data[i], &data[i], prev_block, CIPHER_BLOCK_BYTES);
        memcpy(prev_block, ctext_block, CIPHER_BLOCK_BYTES);
    }
}

/* --- Cipher Feedback (CFB) --- */
void
encrypt_cfb(uint8_t *data, uint32_t length, uint8_t *key, uint8_t *iv)
{
    uint32_t i;
    uint8_t  ctx[CIPHER_CTX_MAX];
    uint8_t  prev_block[BLOCK_BUF_MAX];

    cipher_ctx_init(ctx, key);
    memcpy(prev_block, iv, CIPHER_BLOCK_BYTES);

    for (i = 0; i < length; i += CIPHER_BLOCK_BYTES)
    {
        cipher_encrypt_block(ctx, prev_block);
        xor_bytes(&data[i], &data[i], prev_block, CIPHER_BLOCK_BYTES);
        memcpy(prev_block, &data[i], CIPHER_BLOCK_BYTES);
    }
}

void
decrypt_cfb(uint8_t *data, uint32_t length, uint8_t *key, uint8_t *iv)
{
    uint32_t i;
    uint8_t  ctx[CIPHER_CTX_MAX];
    uint8_t  prev_block[BLOCK_BUF_MAX];
    uint8_t  ctext_block[BLOCK_BUF_MAX];

    cipher_ctx_init(ctx, key);
    memcpy(prev_block, iv, CIPHER_BLOCK_BYTES);

    for (i = 0; i < length; i += CIPHER_BLOCK_BYTES)
    {
        memcpy(ctext_block, &data[i], CIPHER_BLOCK_BYTES);
        cipher_encrypt_block(ctx, prev_block);
        xor_bytes(&data[i], &data[i], prev_block, CIPHER_BLOCK_BYTES);
        memcpy(prev_block, ctext_block, CIPHER_BLOCK_BYTES);
    }
}

/* --- Counter (CTR) --- */
void
encrypt_ctr(uint8_t *data, uint32_t length, uint8_t *key, uint8_t *nonce)
{
    uint32_t   i;
    uint8_t    ctx[CIPHER_CTX_MAX];
    uint8_t    local_nonce[BLOCK_BUF_MAX];
    uint32_t  *nonce_counter;

    cipher_ctx_init(ctx, key);
    memcpy(local_nonce, nonce, CIPHER_BLOCK_BYTES);
    nonce_counter = (uint32_t *)&local_nonce[CIPHER_BLOCK_BYTES - 4];

    for (i = 0; i < length; i += CIPHER_BLOCK_BYTES)
    {
        cipher_encrypt_block(ctx, local_nonce);
        xor_bytes(&data[i], &data[i], local_nonce, CIPHER_BLOCK_BYTES);
        (*nonce_counter)++;
    }
}

void
decrypt_ctr(uint8_t *data, uint32_t length, uint8_t *key, uint8_t *nonce)
{
    encrypt_ctr(data, length, key, nonce);
}

/* --- Output Feedback (OFB) --- */
void
encrypt_ofb(uint8_t *data, uint32_t length, uint8_t *key, uint8_t *iv)
{
    uint32_t i;
    uint8_t  ctx[CIPHER_CTX_MAX];
    uint8_t  prev_block[BLOCK_BUF_MAX];

    cipher_ctx_init(ctx, key);
    memcpy(prev_block, iv, CIPHER_BLOCK_BYTES);

    for (i = 0; i < length; i += CIPHER_BLOCK_BYTES)
    {
        cipher_encrypt_block(ctx, prev_block);
        xor_bytes(&data[i], &data[i], prev_block, CIPHER_BLOCK_BYTES);
    }
}

void
decrypt_ofb(uint8_t *data, uint32_t length, uint8_t *key, uint8_t *iv)
{
    encrypt_ofb(data, length, key, iv);
}

/* --- Propagating Cipher Block Chaining (PCBC) --- */
void
encrypt_pcbc(uint8_t *data, uint32_t length, uint8_t *key, uint8_t *iv)
{
    uint32_t i;
    uint8_t  ctx[CIPHER_CTX_MAX];
    uint8_t  prev_block[BLOCK_BUF_MAX];
    uint8_t  ptext_block[BLOCK_BUF_MAX];

    cipher_ctx_init(ctx, key);
    memcpy(prev_block, iv, CIPHER_BLOCK_BYTES);

    for (i = 0; i < length; i += CIPHER_BLOCK_BYTES)
    {
        memcpy(ptext_block, &data[i], CIPHER_BLOCK_BYTES);
        xor_bytes(&data[i], &data[i], prev_block, CIPHER_BLOCK_BYTES);
        cipher_encrypt_block(ctx, &data[i]);
        xor_bytes(prev_block, ptext_block, &data[i], CIPHER_BLOCK_BYTES);
    }
}

void
decrypt_pcbc(uint8_t *data, uint32_t length, uint8_t *key, uint8_t *iv)
{
    uint32_t i;
    uint8_t  ctx[CIPHER_CTX_MAX];
    uint8_t  prev_block[BLOCK_BUF_MAX];
    uint8_t  ctext_block[BLOCK_BUF_MAX];

    cipher_ctx_init(ctx, key);
    memcpy(prev_block, iv, CIPHER_BLOCK_BYTES);

    for (i = 0; i < length; i += CIPHER_BLOCK_BYTES)
    {
        memcpy(ctext_block, &data[i], CIPHER_BLOCK_BYTES);
        cipher_decrypt_block(ctx, &data[i]);
        xor_bytes(&data[i], &data[i], prev_block, CIPHER_BLOCK_BYTES);
        xor_bytes(prev_block, ctext_block, &data[i], CIPHER_BLOCK_BYTES);
    }
}


/* -- Encryption/Decryption Entry Point -- */
void
encrypt(cipher_mode_t mode, uint8_t *data, uint32_t length, uint8_t *key, uint8_t *iv)
{
    switch (mode)
    {
    case MODE_ECB:
        encrypt_ecb(data, length, key);
        break;
    case MODE_CBC:
        encrypt_cbc(data, length, key, iv);
        break;
    case MODE_CFB:
        encrypt_cfb(data, length, key, iv);
        break;
    case MODE_CTR:
        encrypt_ctr(data, length, key, iv);
        break;
    case MODE_OFB:
        encrypt_ofb(data, length, key, iv);
        break;
    case MODE_PCBC:
        encrypt_pcbc(data, length, key, iv);
        break;
    }
}

void
decrypt(cipher_mode_t mode, uint8_t *data, uint32_t length, uint8_t *key, uint8_t *iv)
{
    switch (mode)
    {
    case MODE_ECB:
        decrypt_ecb(data, length, key);
        break;
    case MODE_CBC:
        decrypt_cbc(data, length, key, iv);
        break;
    case MODE_CFB:
        decrypt_cfb(data, length, key, iv);
        break;
    case MODE_CTR:
        decrypt_ctr(data, length, key, iv);
        break;
    case MODE_OFB:
        decrypt_ofb(data, length, key, iv);
        break;
    case MODE_PCBC:
        decrypt_pcbc(data, length, key, iv);
        break;
    }
}
