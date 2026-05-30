/*
    KLEIN by Zheng Gong, Svetla Nikova, Yee Wei Law
    Archive of Reversing.ID
    Block Cipher

Compile:
    (msvc, from Codes/Cipher/Block/)
    $ cl /I. main.c mode.c KLEIN/code.c

    (gcc, from Codes/Cipher/Block/)
    $ gcc -I. -o test main.c mode.c KLEIN/code.c

    Modes of operation are in mode.c (not in this file).

Assemble:
    (gcc)
    $ gcc -m32 -S -masm=intel -o KLEIN/code.asm KLEIN/code.c

    (msvc)
    $ cl /c /FaKLEIN/code.asm KLEIN/code.c

Note:
    KLEIN-64 (64-bit block, 12 rounds, 64-bit key).
    Spec also defines KLEIN-80/96; this build uses 64-bit only.
*/
#include <stdint.h>
#include <string.h>

/* ************************* CONFIGURATION & SEED ************************* */
#define BLOCKSIZE       64
#define BLOCKSIZEB      8
#define KEYSIZE         64
#define KEYSIZEB        8
#define ROUNDS          12
#define ROUNDKEYS       (ROUNDS + 1)

static const uint8_t SBOX[16] = {
    0x7, 0x4, 0xA, 0x9, 0x1, 0xF, 0xB, 0x0,
    0xC, 0x3, 0x2, 0x6, 0x8, 0xE, 0xD, 0x5
};

typedef struct
{
    uint8_t rk[ROUNDKEYS][BLOCKSIZEB];
} klein_t;


/* ********************* INTERNAL FUNCTIONS PROTOTYPE ********************* */
void block_encrypt(klein_t *config, uint8_t val[BLOCKSIZEB]);
void block_decrypt(klein_t *config, uint8_t val[BLOCKSIZEB]);
void key_setup(klein_t *config, const uint8_t *secret);

static uint8_t  sub_byte(uint8_t b);
static void     sub_nibbles(uint8_t state[BLOCKSIZEB]);
static void     rotate_nibbles(uint8_t state[BLOCKSIZEB]);
static void     mix_nibbles(uint8_t state[BLOCKSIZEB]);
static void     mix_rotate_inv(uint8_t state[BLOCKSIZEB]);
static void     klein_key_schedule(uint8_t rk[BLOCKSIZEB], int round);
static void     xor_block(uint8_t dst[BLOCKSIZEB], const uint8_t src[BLOCKSIZEB]);
static uint8_t  klein_xtime(uint8_t x);


/* *************************** HELPER FUNCTIONS *************************** */
static uint8_t
sub_byte(uint8_t b)
{
    return (uint8_t)((SBOX[b >> 4] << 4) | SBOX[b & 0x0F]);
}

static void
xor_block(uint8_t dst[BLOCKSIZEB], const uint8_t src[BLOCKSIZEB])
{
    int i;

    for (i = 0; i < BLOCKSIZEB; i++)
        dst[i] ^= src[i];
}

static void
sub_nibbles(uint8_t state[BLOCKSIZEB])
{
    int i;

    for (i = 0; i < BLOCKSIZEB; i++)
        state[i] = sub_byte(state[i]);
}

static void
rotate_nibbles(uint8_t state[BLOCKSIZEB])
{
    uint8_t t0 = state[0];
    uint8_t t1 = state[1];

    state[0] = state[2];
    state[1] = state[3];
    state[2] = state[4];
    state[3] = state[5];
    state[4] = state[6];
    state[5] = state[7];
    state[6] = t0;
    state[7] = t1;
}

static uint8_t
klein_xtime(uint8_t x)
{
    return (uint8_t)((x << 1) ^ ((x & 0x80U) ? 0x1BU : 0U));
}

static void
mix_half(uint8_t col[4])
{
    uint8_t u;
    uint8_t v;
    uint8_t t0 = col[0];
    uint8_t t1 = col[1];
    uint8_t t2 = col[2];
    uint8_t t3 = col[3];

    u = (uint8_t)(t0 ^ t1 ^ t2 ^ t3);

    v = (uint8_t)(t0 ^ t1);
    v = klein_xtime(v);
    col[0] = (uint8_t)(t0 ^ v ^ u);

    v = (uint8_t)(t1 ^ t2);
    v = klein_xtime(v);
    col[1] = (uint8_t)(t1 ^ v ^ u);

    v = (uint8_t)(t2 ^ t3);
    v = klein_xtime(v);
    col[2] = (uint8_t)(t2 ^ v ^ u);

    v = (uint8_t)(t3 ^ t0);
    v = klein_xtime(v);
    col[3] = (uint8_t)(t3 ^ v ^ u);
}

static void
mix_nibbles(uint8_t state[BLOCKSIZEB])
{
    mix_half(state);
    mix_half(state + 4);
}

static void
mix_rotate_inv(uint8_t state[BLOCKSIZEB])
{
    uint8_t temp[BLOCKSIZEB];
    uint8_t u;
    uint8_t v;

    memcpy(temp, state, BLOCKSIZEB);

    u = klein_xtime(klein_xtime((uint8_t)(temp[0] ^ temp[2])));
    v = klein_xtime(klein_xtime((uint8_t)(temp[1] ^ temp[3])));
    temp[0] ^= u;
    temp[1] ^= v;
    temp[2] ^= u;
    temp[3] ^= v;

    u = klein_xtime(klein_xtime((uint8_t)(temp[4] ^ temp[6])));
    v = klein_xtime(klein_xtime((uint8_t)(temp[5] ^ temp[7])));
    temp[4] ^= u;
    temp[5] ^= v;
    temp[6] ^= u;
    temp[7] ^= v;

    u = (uint8_t)(temp[0] ^ temp[1] ^ temp[2] ^ temp[3]);
    v = (uint8_t)(temp[0] ^ temp[1]);
    v = klein_xtime(v);
    state[2] = (uint8_t)(temp[0] ^ v ^ u);

    v = (uint8_t)(temp[1] ^ temp[2]);
    v = klein_xtime(v);
    state[3] = (uint8_t)(temp[1] ^ v ^ u);

    v = (uint8_t)(temp[2] ^ temp[3]);
    v = klein_xtime(v);
    state[4] = (uint8_t)(temp[2] ^ v ^ u);

    v = (uint8_t)(temp[3] ^ temp[0]);
    v = klein_xtime(v);
    state[5] = (uint8_t)(temp[3] ^ v ^ u);

    u = (uint8_t)(temp[4] ^ temp[5] ^ temp[6] ^ temp[7]);
    v = (uint8_t)(temp[4] ^ temp[5]);
    v = klein_xtime(v);
    state[6] = (uint8_t)(temp[4] ^ v ^ u);

    v = (uint8_t)(temp[5] ^ temp[6]);
    v = klein_xtime(v);
    state[7] = (uint8_t)(temp[5] ^ v ^ u);

    v = (uint8_t)(temp[6] ^ temp[7]);
    v = klein_xtime(v);
    state[0] = (uint8_t)(temp[6] ^ v ^ u);

    v = (uint8_t)(temp[7] ^ temp[4]);
    v = klein_xtime(v);
    state[1] = (uint8_t)(temp[7] ^ v ^ u);
}

static void
klein_key_schedule(uint8_t rk[BLOCKSIZEB], int round)
{
    uint8_t temp[5];
    uint8_t old[BLOCKSIZEB];
    int     i;

    for (i = 0; i < 5; i++)
        temp[i] = rk[i];
    memcpy(old, rk, BLOCKSIZEB);

    rk[0] = old[5];
    rk[1] = old[6];
    rk[2] = (uint8_t)(old[7] ^ round);
    rk[3] = old[4];
    rk[4] = (uint8_t)(temp[1] ^ old[5]);
    rk[5] = sub_byte((uint8_t)(temp[2] ^ old[6]));
    rk[6] = sub_byte((uint8_t)(temp[3] ^ old[7]));
    rk[7] = (uint8_t)(temp[0] ^ temp[4]);
}


/* ************************ CRYPTOGRAPHY ALGORITHM ************************ */
void
block_encrypt(klein_t *config, uint8_t val[BLOCKSIZEB])
{
    int r;

    for (r = 0; r < ROUNDS; r++)
    {
        xor_block(val, config->rk[r]);
        sub_nibbles(val);
        rotate_nibbles(val);
        mix_nibbles(val);
    }

    xor_block(val, config->rk[ROUNDS]);
}

void
block_decrypt(klein_t *config, uint8_t val[BLOCKSIZEB])
{
    /*
    The design of decryption actually should have following steps 
    for each round transformations:
        - InvMixNibbles
        - InvRotateNibbles
        - InvSubNibbles
        - AddRoundKey

    However, since RotateNibbles and MixNibbles commute exceptionally well
    and KLEIN's S-Box is an involution (it is its own inverse) so sub_nibbles
    handles both encryption and decryption.

    Therefor combination of InvMixNibbles and InvRotateNibbles into mix_rotate_inv
    give the same result, allowing to bypass writing separate inverse S-box.
    */
    int r;

    xor_block(val, config->rk[ROUNDS]);

    for (r = ROUNDS - 1; r >= 0; r--)
    {
        mix_rotate_inv(val);
        sub_nibbles(val);
        xor_block(val, config->rk[r]);
    }
}


/* **************** INTERNAL FUNCTIONS IMPLEMENTATION ******************* */
void
key_setup(klein_t *config, const uint8_t *secret)
{
    int i;

    memcpy(config->rk[0], secret, KEYSIZEB);

    for (i = 0; i < ROUNDS; i++)
    {
        memcpy(config->rk[i + 1], config->rk[i], KEYSIZEB);
        klein_key_schedule(config->rk[i + 1], i + 1);
    }
}


/* cipher port for mode.c */
#include "cipher_port.h"

const uint32_t CIPHER_BLOCK_BYTES = BLOCKSIZEB;
const uint32_t CIPHER_KEY_BYTES   = KEYSIZEB;

void
cipher_ctx_init(uint8_t *ctx, const uint8_t *key)
{
    key_setup((klein_t *)ctx, key);
}

void
cipher_encrypt_block(uint8_t *ctx, uint8_t *block)
{
    block_encrypt((klein_t *)ctx, block);
}

void
cipher_decrypt_block(uint8_t *ctx, uint8_t *block)
{
    block_decrypt((klein_t *)ctx, block);
}
