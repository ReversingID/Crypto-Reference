/*
    Madryga by W. E. Madryga
    Archive of Reversing.ID
    Block Cipher

Compile:
    (msvc, from Codes/Cipher/Block/)
    $ cl /I. main.c mode.c Madryga/code.c

    (gcc, from Codes/Cipher/Block/)
    $ gcc -I. -o test main.c mode.c Madryga/code.c

    Modes of operation are in mode.c (not in this file).

Assemble:
    (gcc)
    $ gcc -m32 -S -masm=intel -o Madryga/code.asm Madryga/code.c

    (msvc)
    $ cl /c /FaMadryga/code.asm Madryga/code.c
*/
#include <stdint.h>
#include <string.h>

/* ************************ CONFIGURATION & SEED ************************ */
#define BLOCKSIZE   64
#define BLOCKSIZEB  8
#define KEYSIZE     64
#define KEYSIZEB    8
#define ROUNDS      8

static const uint8_t RANDOM_CONSTANT[KEYSIZEB] = {
    0x0f, 0x1e, 0x2d, 0x3c, 0x4b, 0x5a, 0x69, 0x78
};


/* ********************* INTERNAL FUNCTIONS PROTOTYPE ********************* */
void block_encrypt(uint8_t *data, const uint8_t *key);
void block_decrypt(uint8_t *data, const uint8_t *key);


/* *************************** HELPER FUNCTIONS *************************** */
static uint64_t
load_be64(const uint8_t *p)
{
    return ((uint64_t)p[0] << 56) | ((uint64_t)p[1] << 48) |
           ((uint64_t)p[2] << 40) | ((uint64_t)p[3] << 32) |
           ((uint64_t)p[4] << 24) | ((uint64_t)p[5] << 16) |
           ((uint64_t)p[6] <<  8) |  (uint64_t)p[7];
}

static void
store_be64(uint8_t *p, uint64_t v)
{
    p[0] = (uint8_t)(v >> 56);
    p[1] = (uint8_t)(v >> 48);
    p[2] = (uint8_t)(v >> 40);
    p[3] = (uint8_t)(v >> 32);
    p[4] = (uint8_t)(v >> 24);
    p[5] = (uint8_t)(v >> 16);
    p[6] = (uint8_t)(v >>  8);
    p[7] = (uint8_t)(v);
}

static uint16_t
rotl16(uint16_t v, unsigned r)
{
    r &= 15;
    return (uint16_t)((v << r) | (v >> (16 - r)));
}

static uint16_t
rotr16(uint16_t v, unsigned r)
{
    r &= 15;
    return (uint16_t)((v >> r) | (v << (16 - r)));
}

static void
rotate_key_left_3(uint8_t key[KEYSIZEB])
{
    uint64_t k = load_be64(key);

    k = (k << 3) | (k >> 61);
    store_be64(key, k);
}

static void
rotate_key_right_3(uint8_t key[KEYSIZEB])
{
    uint64_t k = load_be64(key);

    k = (k >> 3) | (k << 61);
    store_be64(key, k);
}

static void
xor_constant(uint8_t key[KEYSIZEB])
{
    size_t i;

    for (i = 0; i < KEYSIZEB; i++)
        key[i] ^= RANDOM_CONSTANT[i];
}

static void
prep_working_key(uint8_t wkey[KEYSIZEB], const uint8_t *key)
{
    memcpy(wkey, key, KEYSIZEB);
    xor_constant(wkey);
    rotate_key_left_3(wkey);
}

static void
inner_encrypt(uint8_t block[BLOCKSIZEB], uint8_t wkey[KEYSIZEB])
{
    size_t k;

    for (k = 0; k < BLOCKSIZEB; k++)
    {
        size_t   pos = (BLOCKSIZEB - 2 + k) % BLOCKSIZEB;
        size_t   b   = (pos + 1) % BLOCKSIZEB;
        size_t   c   = (pos + 2) % BLOCKSIZEB;
        uint8_t  a   = block[pos];
        uint8_t  bb  = block[b];
        uint8_t  cc  = block[c];
        unsigned r   = cc & 0x07;
        uint16_t pair;

        cc ^= wkey[KEYSIZEB - 1];

        pair = ((uint16_t)a << 8) | bb;
        pair = rotl16(pair, r);
        block[pos] = (uint8_t)(pair >> 8);
        block[b]   = (uint8_t)(pair & 0xff);
        block[c]   = cc;

        rotate_key_left_3(wkey);
    }
}

static void
inner_decrypt(uint8_t block[BLOCKSIZEB], uint8_t wkey[KEYSIZEB])
{
    size_t k;
    size_t i;

    for (i = 1; i < BLOCKSIZEB; i++)
        rotate_key_left_3(wkey);

    for (k = 0; k < BLOCKSIZEB; k++)
    {
        size_t   pos = (BLOCKSIZEB - 3 - k + BLOCKSIZEB) % BLOCKSIZEB;
        size_t   b   = (pos + 1) % BLOCKSIZEB;
        size_t   c   = (pos + 2) % BLOCKSIZEB;
        uint8_t  a   = block[pos];
        uint8_t  bb  = block[b];
        uint8_t  cc  = block[c];
        unsigned r;
        uint16_t pair;

        r = (cc ^ wkey[KEYSIZEB - 1]) & 0x07;

        pair = ((uint16_t)a << 8) | bb;
        pair = rotr16(pair, r);
        block[pos] = (uint8_t)(pair >> 8);
        block[b]   = (uint8_t)(pair & 0xff);

        cc ^= wkey[KEYSIZEB - 1];
        block[c] = cc;

        rotate_key_right_3(wkey);
    }
}


/* ************************ CRYPTOGRAPHY ALGORITHM ************************ */
/*
    Enkripsi sebuah block dengan Madryga.
*/
void
block_encrypt(uint8_t *val, const uint8_t *key)
{
    uint8_t wkey[KEYSIZEB];
    size_t  r;

    for (r = 0; r < ROUNDS; r++)
    {
        prep_working_key(wkey, key);
        inner_encrypt(val, wkey);
    }
}

/*
    Dekripsi sebuah block dengan Madryga.
*/
void
block_decrypt(uint8_t *val, const uint8_t *key)
{
    uint8_t wkey[KEYSIZEB];
    size_t  r;

    for (r = 0; r < ROUNDS; r++)
    {
        prep_working_key(wkey, key);
        inner_decrypt(val, wkey);
    }
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
