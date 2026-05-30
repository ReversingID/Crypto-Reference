/*
    SkipJack by NSA
    Archive of Reversing.ID
    Block Cipher

Compile:
    (msvc, from Codes/Cipher/Block/)
    $ cl /I. main.c mode.c SkipJack/code.c

    (gcc, from Codes/Cipher/Block/)
    $ gcc -I. -o test main.c mode.c SkipJack/code.c

    Modes of operation are in mode.c (not in this file).

Assemble:
    (gcc)
    $ gcc -m32 -S -masm=intel -o SkipJack/code.asm SkipJack/code.c

    (msvc)
    $ cl /c /FaSkipJack/code.asm SkipJack/code.c
*/
#include <stdint.h>
#include <string.h>
#include "../byteorder.h"

/* ************************* CONFIGURATION & SEED ************************* */
#define BLOCKSIZE   64
#define BLOCKSIZEB  8
#define KEYSIZE     80
#define KEYSIZEB    10
#define ROUNDS      32

static const uint8_t F_TABLE[256] = {
    0xa3, 0xd7, 0x09, 0x83, 0xf8, 0x48, 0xf6, 0xf4, 0xb3, 0x21, 0x15, 0x78, 0x99, 0xb1, 0xaf, 0xf9,
    0xe7, 0x2d, 0x4d, 0x8a, 0xce, 0x4c, 0xca, 0x2e, 0x52, 0x95, 0xd9, 0x1e, 0x4e, 0x38, 0x44, 0x28,
    0x0a, 0xdf, 0x02, 0xa0, 0x17, 0xf1, 0x60, 0x68, 0x12, 0xb7, 0x7a, 0xc3, 0xe9, 0xfa, 0x3d, 0x53,
    0x96, 0x84, 0x6b, 0xba, 0xf2, 0x63, 0x9a, 0x19, 0x7c, 0xae, 0xe5, 0xf5, 0xf7, 0x16, 0x6a, 0xa2,
    0x39, 0xb6, 0x7b, 0x0f, 0xc1, 0x93, 0x81, 0x1b, 0xee, 0xb4, 0x1a, 0xea, 0xd0, 0x91, 0x2f, 0xb8,
    0x55, 0xb9, 0xda, 0x85, 0x3f, 0x41, 0xbf, 0xe0, 0x5a, 0x58, 0x80, 0x5f, 0x66, 0x0b, 0xd8, 0x90,
    0x35, 0xd5, 0xc0, 0xa7, 0x33, 0x06, 0x65, 0x69, 0x45, 0x00, 0x94, 0x56, 0x6d, 0x98, 0x9b, 0x76,
    0x97, 0xfc, 0xb2, 0xc2, 0xb0, 0xfe, 0xdb, 0x20, 0xe1, 0xeb, 0xd6, 0xe4, 0xdd, 0x47, 0x4a, 0x1d,
    0x42, 0xed, 0x9e, 0x6e, 0x49, 0x3c, 0xcd, 0x43, 0x27, 0xd2, 0x07, 0xd4, 0xde, 0xc7, 0x67, 0x18,
    0x89, 0xcb, 0x30, 0x1f, 0x8d, 0xc6, 0x8f, 0xaa, 0xc8, 0x74, 0xdc, 0xc9, 0x5d, 0x5c, 0x31, 0xa4,
    0x70, 0x88, 0x61, 0x2c, 0x9f, 0x0d, 0x2b, 0x87, 0x50, 0x82, 0x54, 0x64, 0x26, 0x7d, 0x03, 0x40,
    0x34, 0x4b, 0x1c, 0x73, 0xd1, 0xc4, 0xfd, 0x3b, 0xcc, 0xfb, 0x7f, 0xab, 0xe6, 0x3e, 0x5b, 0xa5,
    0xad, 0x04, 0x23, 0x9c, 0x14, 0x51, 0x22, 0xf0, 0x29, 0x79, 0x71, 0x7e, 0xff, 0x8c, 0x0e, 0xe2,
    0x0c, 0xef, 0xbc, 0x72, 0x75, 0x6f, 0x37, 0xa1, 0xec, 0xd3, 0x8e, 0x62, 0x8b, 0x86, 0x10, 0xe8,
    0x08, 0x77, 0x11, 0xbe, 0x92, 0x4f, 0x24, 0xc5, 0x32, 0x36, 0x9d, 0xcf, 0xf3, 0xa6, 0xbb, 0xac,
    0x5e, 0x6c, 0xa9, 0x13, 0x57, 0x25, 0xb5, 0xe3, 0xbd, 0xa8, 0x3a, 0x01, 0x05, 0x59, 0x2a, 0x46
};


/* ********************* INTERNAL FUNCTIONS PROTOTYPE ********************* */
void block_encrypt(uint8_t *data, const uint8_t *key);
void block_decrypt(uint8_t *data, const uint8_t *key);


/* *************************** HELPER FUNCTIONS *************************** */
static void
load_block(const uint8_t *data, uint16_t *w1, uint16_t *w2, uint16_t *w3, uint16_t *w4)
{
    *w1 = load16_be(data + 0);
    *w2 = load16_be(data + 2);
    *w3 = load16_be(data + 4);
    *w4 = load16_be(data + 6);
}

static void
store_block(uint8_t *data, uint16_t w1, uint16_t w2, uint16_t w3, uint16_t w4)
{
    store16_be(data + 0, w1);
    store16_be(data + 2, w2);
    store16_be(data + 4, w3);
    store16_be(data + 6, w4);
}

static uint16_t
G_perm(int step, uint16_t w, const uint8_t *cv)
{
    uint8_t g1 = (uint8_t)(w >> 8);
    uint8_t g2 = (uint8_t)(w & 0xff);
    uint8_t g3, g4, g5, g6;

    g3 = F_TABLE[g2 ^ cv[(4 * step + 0) % 10]] ^ g1;
    g4 = F_TABLE[g3 ^ cv[(4 * step + 1) % 10]] ^ g2;
    g5 = F_TABLE[g4 ^ cv[(4 * step + 2) % 10]] ^ g3;
    g6 = F_TABLE[g5 ^ cv[(4 * step + 3) % 10]] ^ g4;

    return (uint16_t)(((uint16_t)g5 << 8) | g6);
}

static uint16_t
G_inv(int step, uint16_t w, const uint8_t *cv)
{
    uint8_t g5 = (uint8_t)(w >> 8);
    uint8_t g6 = (uint8_t)(w & 0xff);
    uint8_t g4, g3, g2, g1;

    g4 = F_TABLE[g5 ^ cv[(4 * step + 3) % 10]] ^ g6;
    g3 = F_TABLE[g4 ^ cv[(4 * step + 2) % 10]] ^ g5;
    g2 = F_TABLE[g3 ^ cv[(4 * step + 1) % 10]] ^ g4;
    g1 = F_TABLE[g2 ^ cv[(4 * step + 0) % 10]] ^ g3;

    return (uint16_t)(((uint16_t)g1 << 8) | g2);
}

static void
rule_a_enc(uint16_t *w1, uint16_t *w2, uint16_t *w3, uint16_t *w4,
           int step, uint16_t counter, const uint8_t *cv)
{
    uint16_t g = G_perm(step, *w1, cv);
    uint16_t new_w1 = g ^ *w4 ^ counter;
    uint16_t new_w2 = g;
    uint16_t new_w3 = *w2;
    uint16_t new_w4 = *w3;

    *w1 = new_w1;
    *w2 = new_w2;
    *w3 = new_w3;
    *w4 = new_w4;
}

static void
rule_b_enc(uint16_t *w1, uint16_t *w2, uint16_t *w3, uint16_t *w4,
           int step, uint16_t counter, const uint8_t *cv)
{
    uint16_t g = G_perm(step, *w1, cv);
    uint16_t new_w1 = *w4;
    uint16_t new_w2 = g;
    uint16_t new_w3 = *w1 ^ *w2 ^ counter;
    uint16_t new_w4 = *w3;

    *w1 = new_w1;
    *w2 = new_w2;
    *w3 = new_w3;
    *w4 = new_w4;
}

static void
rule_a_dec(uint16_t *w1, uint16_t *w2, uint16_t *w3, uint16_t *w4,
           int step, uint16_t counter, const uint8_t *cv)
{
    uint16_t old_w1 = *w1;
    uint16_t old_w2 = *w2;
    uint16_t ginv = G_inv(step, *w2, cv);

    *w1 = ginv;
    *w2 = *w3;
    *w3 = *w4;
    *w4 = old_w1 ^ old_w2 ^ counter;
}

static void
rule_b_dec(uint16_t *w1, uint16_t *w2, uint16_t *w3, uint16_t *w4,
           int step, uint16_t counter, const uint8_t *cv)
{
    uint16_t old_w1 = *w1;
    uint16_t ginv = G_inv(step, *w2, cv);

    *w1 = ginv;
    *w2 = ginv ^ *w3 ^ counter;
    *w3 = *w4;
    *w4 = old_w1;
}


/* ************************ CRYPTOGRAPHY ALGORITHM ************************ */
/*
    Enkripsi sebuah block dengan SkipJack.
    Block terdiri dari empat word 16-bit (64-bit total).
*/
void
block_encrypt(uint8_t *data, const uint8_t *key)
{
    uint16_t w1, w2, w3, w4;
    int      step;

    load_block(data, &w1, &w2, &w3, &w4);

    for (step = 0; step < ROUNDS; step++)
    {
        uint16_t counter = (uint16_t)(step + 1);

        if (step < 8 || (step >= 16 && step < 24))
            rule_a_enc(&w1, &w2, &w3, &w4, step, counter, key);
        else
            rule_b_enc(&w1, &w2, &w3, &w4, step, counter, key);
    }

    store_block(data, w1, w2, w3, w4);
}

/*
    Dekripsi sebuah block dengan SkipJack.
    Block terdiri dari empat word 16-bit (64-bit total).
*/
void
block_decrypt(uint8_t *data, const uint8_t *key)
{
    uint16_t w1, w2, w3, w4;
    int      step;

    load_block(data, &w1, &w2, &w3, &w4);

    for (step = ROUNDS - 1; step >= 0; step--)
    {
        uint16_t counter = (uint16_t)(step + 1);

        if (step >= 24 || (step >= 8 && step < 16))
            rule_b_dec(&w1, &w2, &w3, &w4, step, counter, key);
        else
            rule_a_dec(&w1, &w2, &w3, &w4, step, counter, key);
    }

    store_block(data, w1, w2, w3, w4);
}


/* cipher port for mode.c */
#include "cipher_port.h"

const uint32_t CIPHER_BLOCK_BYTES = BLOCKSIZEB;
const uint32_t CIPHER_KEY_BYTES   = KEYSIZEB;

void
cipher_ctx_init(uint8_t *ctx, const uint8_t *key)
{
    memcpy(ctx, key, KEYSIZEB);
}

void
cipher_encrypt_block(uint8_t *ctx, uint8_t *block)
{
    block_encrypt(block, ctx);
}

void
cipher_decrypt_block(uint8_t *ctx, uint8_t *block)
{
    block_decrypt(block, ctx);
}
