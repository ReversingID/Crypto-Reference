/*
    PRESENT by Orange Labs, Ruhr University Bochum, Technical University of Denmark
    Archive of Reversing.ID
    Block Cipher

Compile:
    (msvc, from Codes/Cipher/Block/)
    $ cl /I. main.c mode.c PRESENT/code.c

    (gcc, from Codes/Cipher/Block/)
    $ gcc -I. -o test main.c mode.c PRESENT/code.c

    Modes of operation are in mode.c (not in this file).

Assemble:
    (gcc)
    $ gcc -m32 -S -masm=intel -o PRESENT/code.asm PRESENT/code.c

    (msvc)
    $ cl /c /FaPRESENT/code.asm PRESENT/code.c

Note:
    PRESENT-128 (64-bit block, 31 rounds, 128-bit key).
    Spec also defines 80-bit keys; this build uses 128-bit only.
*/
#include <stdint.h>
#include <string.h>
#include "../byteorder.h"

/* ************************* CONFIGURATION & SEED ************************* */
#define BLOCKSIZE       64
#define BLOCKSIZEB      8
#define KEYSIZE         128
#define KEYSIZEB        16
#define ROUNDS          31
#define ROUNDKEYS       (ROUNDS + 1)

static const uint8_t SBOX[16] = {
    0xC, 0x5, 0x6, 0xB, 0x9, 0x0, 0xA, 0xD,
    0x3, 0xE, 0xF, 0x8, 0x4, 0x7, 0x1, 0x2
};

static const uint8_t SBOX_INV[16] = {
    0x5, 0xE, 0xF, 0x8, 0xC, 0x1, 0x2, 0xD,
    0xB, 0x4, 0x6, 0x3, 0x0, 0x7, 0x9, 0xA
};

static const uint8_t PBOX[64] = {
     0, 16, 32, 48,  1, 17, 33, 49,
     2, 18, 34, 50,  3, 19, 35, 51,
     4, 20, 36, 52,  5, 21, 37, 53,
     6, 22, 38, 54,  7, 23, 39, 55,
     8, 24, 40, 56,  9, 25, 41, 57,
    10, 26, 42, 58, 11, 27, 43, 59,
    12, 28, 44, 60, 13, 29, 45, 61,
    14, 30, 46, 62, 15, 31, 47, 63
};

static const uint8_t PBOX_INV[64] = {
     0,  4,  8, 12, 16, 20, 24, 28,
    32, 36, 40, 44, 48, 52, 56, 60,
     1,  5,  9, 13, 17, 21, 25, 29,
    33, 37, 41, 45, 49, 53, 57, 61,
     2,  6, 10, 14, 18, 22, 26, 30,
    34, 38, 42, 46, 50, 54, 58, 62,
     3,  7, 11, 15, 19, 23, 27, 31,
    35, 39, 43, 47, 51, 55, 59, 63
};

typedef struct
{
    uint64_t rk[ROUNDKEYS];
} present_t;


/* ********************* INTERNAL FUNCTIONS PROTOTYPE ********************* */
void block_encrypt(present_t *config, uint8_t val[BLOCKSIZEB]);
void block_decrypt(present_t *config, uint8_t val[BLOCKSIZEB]);
void key_setup(present_t *config, const uint8_t *secret);

static uint64_t sbox_layer(uint64_t state);
static uint64_t sbox_layer_inv(uint64_t state);
static uint64_t p_layer(uint64_t state);
static uint64_t p_layer_inv(uint64_t state);
static void rotl128_61(uint64_t *k_hi, uint64_t *k_lo);
static void key128_sbox(uint64_t *k_hi);
static void xor_round_counter(uint64_t *k_hi, uint64_t *k_lo, int round);


/* *************************** HELPER FUNCTIONS *************************** */
static uint64_t
sbox_layer(uint64_t state)
{
    uint64_t out = 0;
    int      i;

    for (i = 0; i < 16; i++)
    {
        uint8_t nibble = (uint8_t)((state >> (i * 4)) & 0xF);
        out |= (uint64_t)SBOX[nibble] << (i * 4);
    }

    return out;
}

static uint64_t
sbox_layer_inv(uint64_t state)
{
    uint64_t out = 0;
    int      i;

    for (i = 0; i < 16; i++)
    {
        uint8_t nibble = (uint8_t)((state >> (i * 4)) & 0xF);
        out |= (uint64_t)SBOX_INV[nibble] << (i * 4);
    }

    return out;
}

static uint64_t
p_layer(uint64_t state)
{
    uint64_t out = 0;
    int      i;

    for (i = 0; i < 64; i++)
        out |= ((state >> i) & 1ULL) << PBOX[i];

    return out;
}

static uint64_t
p_layer_inv(uint64_t state)
{
    uint64_t out = 0;
    int      i;

    for (i = 0; i < 64; i++)
        out |= ((state >> i) & 1ULL) << PBOX_INV[i];

    return out;
}

static void
rotl128_61(uint64_t *k_hi, uint64_t *k_lo)
{
    uint64_t hi = *k_hi;
    uint64_t lo = *k_lo;
    uint64_t new_hi;
    uint64_t new_lo;

    new_hi = (hi << 61) | (lo >> 3);
    new_lo = (lo << 61) | (hi >> 3);
    *k_hi = new_hi;
    *k_lo = new_lo;
}

static void
key128_sbox(uint64_t *k_hi)
{
    uint64_t hi = *k_hi;
    uint8_t  n0;
    uint8_t  n1;

    n0 = SBOX[(hi >> 60) & 0xF];
    n1 = SBOX[(hi >> 56) & 0xF];
    hi = (hi & 0x00FFFFFFFFFFFFFFULL) |
         ((uint64_t)n0 << 60) |
         ((uint64_t)n1 << 56);
    *k_hi = hi;
}

static void
xor_round_counter(uint64_t *k_hi, uint64_t *k_lo, int round)
{
    *k_lo ^= (uint64_t)(round & 3) << 62;
    *k_hi ^= (uint64_t)(round >> 2);
}


/* ************************ CRYPTOGRAPHY ALGORITHM ************************ */
/*
    Enkripsi sebuah block dengan PRESENT.
    Pastikan konfigurasi telah dilakukan dengan memanggil key_setup()
*/
void
block_encrypt(present_t *config, uint8_t val[BLOCKSIZEB])
{
    uint64_t state;
    int      r;

    state = load64_be(val);

    for (r = 0; r < ROUNDS; r++)
    {
        state ^= config->rk[r];
        state  = sbox_layer(state);
        state  = p_layer(state);
    }

    state ^= config->rk[ROUNDKEYS - 1];

    store64_be(val, state);
}

/*
    Dekripsi sebuah block dengan PRESENT.
    Pastikan konfigurasi telah dilakukan dengan memanggil key_setup()
*/
void
block_decrypt(present_t *config, uint8_t val[BLOCKSIZEB])
{
    uint64_t state;
    int      i;

    state = load64_be(val);

    for (i = 0; i < ROUNDS; i++)
    {
        state ^= config->rk[ROUNDKEYS - 1 - i];
        state  = p_layer_inv(state);
        state  = sbox_layer_inv(state);
    }

    state ^= config->rk[0];

    store64_be(val, state);
}


/* **************** INTERNAL FUNCTIONS IMPLEMENTATION ******************* */
void
key_setup(present_t *config, const uint8_t *secret)
{
    uint64_t k_hi;
    uint64_t k_lo;
    int      i;

    k_hi = load64_be(secret);
    k_lo = load64_be(secret + 8);

    for (i = 1; i <= ROUNDKEYS; i++)
    {
        config->rk[i - 1] = k_hi;
        rotl128_61(&k_hi, &k_lo);
        key128_sbox(&k_hi);
        xor_round_counter(&k_hi, &k_lo, i);
    }
}


/* cipher port for mode.c */
#include "cipher_port.h"

const uint32_t CIPHER_BLOCK_BYTES = BLOCKSIZEB;
const uint32_t CIPHER_KEY_BYTES   = KEYSIZEB;

void
cipher_ctx_init(uint8_t *ctx, const uint8_t *key)
{
    key_setup((present_t *)ctx, key);
}

void
cipher_encrypt_block(uint8_t *ctx, uint8_t *block)
{
    block_encrypt((present_t *)ctx, block);
}

void
cipher_decrypt_block(uint8_t *ctx, uint8_t *block)
{
    block_decrypt((present_t *)ctx, block);
}
