/*
    DFC by Gilbert, Girault, Hoogvorst, Noilhan, Pornin, Poupard, Stern, Vaudenay
    Archive of Reversing.ID
    Block Cipher

Compile:
    (msvc, from Codes/Cipher/Block/)
    $ cl /I. main.c mode.c DFC/code.c

    (gcc, from Codes/Cipher/Block/)
    $ gcc -I. -o test main.c mode.c DFC/code.c

    Modes of operation are in mode.c (not in this file).

Assemble:
    (gcc)
    $ gcc -m32 -S -masm=intel -o DFC/code.asm DFC/code.c

    (msvc)
    $ cl /c /FaDFC/code.asm DFC/code.c

Note:
    DFC (128-bit block, 8 rounds, 128-bit key).
    Spec also defines 192- and 256-bit keys; this build uses 128-bit only.
    Based on the 1998 version of DFC for AES submission.
*/
#include <stdint.h>
#include <string.h>
#include "../byteorder.h"

/* ************************* CONFIGURATION & SEED ************************* */
#define BLOCKSIZE       128
#define BLOCKSIZEB      16
#define KEYSIZE         128
#define KEYSIZEB        16
#define ROUNDS          8
#define EF_ROUNDS       4

/*
    Round table RT[64], KC, KD from the first 2144 bits of e.
    KA2..KA4, KB2..KB4, KS from trunc640(EES) = first 640 bits of EES.
 */
static const uint32_t RT[64] = {
    0xb7e15162u, 0x8aed2a6au, 0xbf715880u, 0x9cf4f3c7u,
    0x62e7160fu, 0x38b4da56u, 0xa784d904u, 0x5190cfefu,
    0x324e7738u, 0x926cfbe5u, 0xf4bf8d8du, 0x8c31d763u,
    0xda06c80au, 0xbb1185ebu, 0x4f7c7b57u, 0x57f59584u,
    0x90cfd47du, 0x7c19bb42u, 0x158d9554u, 0xf7b46bceu,
    0xd55c4d79u, 0xfd5f24d6u, 0x613c31c3u, 0x839a2ddfu,
    0x8a9a276bu, 0xcfbfa1c8u, 0x77c56284u, 0xdab79cd4u,
    0xc2b3293du, 0x20e9e5eau, 0xf02ac60au, 0xcc93ed87u,
    0x4422a52eu, 0xcb238feeu, 0xe5ab6addu, 0x835fd1a0u,
    0x753d0a8fu, 0x78e537d2u, 0xb95bb79du, 0x8dcaec64u,
    0x2c1e9f23u, 0xb829b5c2u, 0x780bf387u, 0x37df8bb3u,
    0x00d01334u, 0xa0d0bd86u, 0x45cbfa73u, 0xa6160ffeu,
    0x393c48cbu, 0xbbca060fu, 0x0ff8ec6du, 0x31beb5ccu,
    0xeed7f2f0u, 0xbb088017u, 0x163bc60du, 0xf45a0ecbu,
    0x1bcd289bu, 0x06cbbfeau, 0x21ad08e1u, 0x847f3f73u,
    0x78d56cedu, 0x94640d6eu, 0xf0d3d37bu, 0xe67008e1u
};

static const uint32_t KC = 0xeb64749au;
static const uint64_t KD = UINT64_C(0x86d1bf275b9b241d);

static const uint64_t KA[3] = {
    UINT64_C(0xb7e151628aed2a6a),
    UINT64_C(0xbf7158809cf4f3c7),
    UINT64_C(0x62e7160f38b4da56)
};

static const uint64_t KB[3] = {
    UINT64_C(0xa784d9045190cfef),
    UINT64_C(0x324e7738926cfbe5),
    UINT64_C(0xf4bf8d8d8c31d763)
};

static const uint8_t KS_PAD[KEYSIZEB] = {
    0xda, 0x06, 0xc8, 0x0a, 0xbb, 0x11, 0x85, 0xeb,
    0x4f, 0x7c, 0x7b, 0x57, 0x57, 0xf5, 0x95, 0x84
};

typedef struct
{
    uint64_t rk[ROUNDS][2];
} dfc_t;


/* ********************* INTERNAL FUNCTIONS PROTOTYPE ********************* */
void block_encrypt(dfc_t *config, uint8_t val[BLOCKSIZEB]);
void block_decrypt(dfc_t *config, uint8_t val[BLOCKSIZEB]);
void key_setup(dfc_t *config, const uint8_t *key);


/* *************************** HELPER FUNCTIONS *************************** */
static uint64_t
mul_add_mod(uint64_t a, uint64_t x, uint64_t b)
{
#if defined(__SIZEOF_INT128__)
    const __uint128_t M = (((__uint128_t)1) << 64) + 13;
    __uint128_t       p = (__uint128_t)a * x + b;

    return (uint64_t)(p % M);
#else
    uint64_t hi;
    uint64_t lo;
    uint64_t a_lo;
    uint64_t a_hi;
    uint64_t x_lo;
    uint64_t x_hi;
    __uint128_t p0;
    __uint128_t p1;
    __uint128_t p2;
    __uint128_t sum;
    __uint128_t acc;
    __uint128_t r;

    a_lo = a & 0xffffffffu;
    a_hi = a >> 32;
    x_lo = x & 0xffffffffu;
    x_hi = x >> 32;

    p0 = (__uint128_t)a_lo * x_lo;
    p1 = (__uint128_t)a_lo * x_hi;
    p2 = (__uint128_t)a_hi * x_lo;
    sum = p0 + ((p1 + p2) << 32) + ((__uint128_t)(a_hi * x_hi) << 64) + b;

    acc = sum;
    while (acc >> 64)
    {
        lo = (uint64_t)acc;
        hi = (uint64_t)(acc >> 64);
        acc = (__uint128_t)lo + (__uint128_t)13 * hi;
    }

    r = acc;
    if (r >= (((__uint128_t)1) << 64) + 13)
        r -= (((__uint128_t)1) << 64) + 13;

    return (uint64_t)r;
#endif
}

static uint64_t
cp_perm(uint64_t y)
{
    uint32_t yl;
    uint32_t yr;
    uint32_t left;
    uint32_t right;
    uint64_t t;

    yl = (uint32_t)(y >> 32);
    yr = (uint32_t)y;
    left  = yr ^ RT[yl >> 26];
    right = yl ^ KC;
    t = ((uint64_t)left << 32) | (uint64_t)right;
    return t + KD;
}

static uint64_t
round_function(uint64_t a, uint64_t b, uint64_t x)
{
    return cp_perm(mul_add_mod(a, x, b));
}

static void
feistel_enc(const uint64_t params[][2], unsigned rounds, uint64_t x0, uint64_t x1,
             uint64_t *out_hi, uint64_t *out_lo)
{
    unsigned i;
    uint64_t prev;
    uint64_t cur;
    uint64_t next;
    uint64_t f;

    prev = x0;
    cur  = x1;

    for (i = 0; i < rounds; i++)
    {
        f = round_function(params[i][0], params[i][1], cur);
        next = f ^ prev;
        prev = cur;
        cur  = next;
    }

    *out_hi = cur;
    *out_lo = prev;
}

static void
build_ef_params(uint64_t ef[EF_ROUNDS][2], const uint64_t oap[EF_ROUNDS], const uint64_t obp[EF_ROUNDS])
{
    unsigned i;

    for (i = 0; i < EF_ROUNDS; i++)
    {
        ef[i][0] = oap[i];
        ef[i][1] = obp[i];
    }
}

static void
expand_key(dfc_t *config, const uint8_t *key)
{
    uint8_t    pk[32];
    uint32_t   pk32[8];
    uint64_t   oap[EF_ROUNDS];
    uint64_t   obp[EF_ROUNDS];
    uint64_t   eap[EF_ROUNDS];
    uint64_t   ebp[EF_ROUNDS];
    uint64_t   ef1[EF_ROUNDS][2];
    uint64_t   ef2[EF_ROUNDS][2];
    uint64_t   rk_prev_hi;
    uint64_t   rk_prev_lo;
    uint64_t   rk_hi;
    uint64_t   rk_lo;
    unsigned   i;
    unsigned   r;

    memcpy(pk, key, KEYSIZEB);
    memcpy(pk + KEYSIZEB, KS_PAD, KEYSIZEB);

    for (i = 0; i < 8; i++)
        pk32[i] = load32_be(pk + 4 * i);

    oap[0] = ((uint64_t)pk32[0] << 32) | pk32[7];
    obp[0] = ((uint64_t)pk32[4] << 32) | pk32[3];
    eap[0] = ((uint64_t)pk32[1] << 32) | pk32[6];
    ebp[0] = ((uint64_t)pk32[5] << 32) | pk32[2];

    for (i = 1; i < EF_ROUNDS; i++)
    {
        oap[i] = oap[0] ^ KA[i - 1];
        obp[i] = obp[0] ^ KB[i - 1];
        eap[i] = eap[0] ^ KA[i - 1];
        ebp[i] = ebp[0] ^ KB[i - 1];
    }

    build_ef_params(ef1, oap, obp);
    build_ef_params(ef2, eap, ebp);

    rk_prev_hi = 0;
    rk_prev_lo = 0;

    for (r = 0; r < ROUNDS; r++)
    {
        if ((r & 1u) == 0)
            feistel_enc(ef1, EF_ROUNDS, rk_prev_hi, rk_prev_lo, &rk_hi, &rk_lo);
        else
            feistel_enc(ef2, EF_ROUNDS, rk_prev_hi, rk_prev_lo, &rk_hi, &rk_lo);

        config->rk[r][0] = rk_hi;
        config->rk[r][1] = rk_lo;
        rk_prev_hi = rk_hi;
        rk_prev_lo = rk_lo;
    }
}


/* ************************ CRYPTOGRAPHY ALGORITHM ************************ */
void
block_encrypt(dfc_t *config, uint8_t val[BLOCKSIZEB])
{
    uint64_t x0;
    uint64_t x1;
    uint64_t out_hi;
    uint64_t out_lo;

    x0 = load64_be(val);
    x1 = load64_be(val + 8);
    feistel_enc(config->rk, ROUNDS, x0, x1, &out_hi, &out_lo);
    store64_be(val, out_hi);
    store64_be(val + 8, out_lo);
}

void
block_decrypt(dfc_t *config, uint8_t val[BLOCKSIZEB])
{
    uint64_t rev[ROUNDS][2];
    uint64_t x0;
    uint64_t x1;
    uint64_t out_hi;
    uint64_t out_lo;
    unsigned i;

    for (i = 0; i < ROUNDS; i++)
    {
        rev[i][0] = config->rk[ROUNDS - 1 - i][0];
        rev[i][1] = config->rk[ROUNDS - 1 - i][1];
    }

    x0 = load64_be(val);
    x1 = load64_be(val + 8);
    feistel_enc(rev, ROUNDS, x0, x1, &out_hi, &out_lo);
    store64_be(val, out_hi);
    store64_be(val + 8, out_lo);
}

void
key_setup(dfc_t *config, const uint8_t *key)
{
    expand_key(config, key);
}


/* cipher port for mode.c */
#include "cipher_port.h"

const uint32_t CIPHER_BLOCK_BYTES = BLOCKSIZEB;
const uint32_t CIPHER_KEY_BYTES   = KEYSIZEB;

void
cipher_ctx_init(uint8_t *ctx, const uint8_t *key)
{
    key_setup((dfc_t *)ctx, key);
}

void
cipher_encrypt_block(uint8_t *ctx, uint8_t *block)
{
    block_encrypt((dfc_t *)ctx, block);
}

void
cipher_decrypt_block(uint8_t *ctx, uint8_t *block)
{
    block_decrypt((dfc_t *)ctx, block);
}
