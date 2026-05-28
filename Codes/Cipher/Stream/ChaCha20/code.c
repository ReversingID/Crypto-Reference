/*
    ChaCha20
    Archive of Reversing.ID
    Stream Cipher

Compile:
    (msvc, from Codes/Cipher/Stream/)
    $ cl /I. main.c ChaCha20/code.c

    (gcc, from Codes/Cipher/Stream/)
    $ gcc -I. -o test main.c ChaCha20/code.c

    Demo harness is in main.c (not in this file).

Assemble:
    (gcc)
    $ gcc -m32 -S -masm=intel -o ChaCha20/code.asm ChaCha20/code.c

    (msvc)
    $ cl /c /FaChaCha20/code.asm ChaCha20/code.c

Note:
    Implementation of ChaCha20 stream cipher with IETF variant (96-bite nonce + 32-bit counter)
*/

#include <stdint.h>
#include <string.h>

/* ************************ CONFIGURATION & SEED ************************ */
#ifdef _MSC_VER
    #pragma intrinsic(_lrotr,_lrotl)
    #define rotr(x,n)   _lrotr(x,n)
    #define rotl(x,n)   _lrotl(x,n)
#else
    #define rotr(x,n)   (((x) >> ((int)(n))) | ((x) << (32 - (int)(n))))
    #define rotl(x,n)   (((x) << ((int)(n))) | ((x) >> (32 - (int)(n))))
#endif

#define bswap32(x)      (rotl(x,8) & 0x00FF00FF | rotr(x, 8) & 0xFF00FF00)

#if !defined(LITTLE_ENDIAN) && !defined(BIG_ENDIAN)
    #ifdef _MSC_VER
        #define LITTLE_ENDIAN
    #elif defined(__BYTE_ORDER__) && (__BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__)
        #define LITTLE_ENDIAN
    #elif defined(__BYTE_ORDER__) && (__BYTE_ORDER__ == __ORDER_BIG_ENDIAN__)
        #define BIG_ENDIAN
    #elif defined(__LITTLE_ENDIAN__)
        #define LITTLE_ENDIAN
    #else
        #define BIG_ENDIAN
    #endif
#endif

#ifdef LITTLE_ENDIAN
    #define load32_le(p) \
        (((uint32_t)(p)[0]) | ((uint32_t)(p)[1] << 8) | \
         ((uint32_t)(p)[2] << 16) | ((uint32_t)(p)[3] << 24))
    #define store32_le(p, v) do { \
        (p)[0] = (uint8_t)(v); \
        (p)[1] = (uint8_t)((v) >> 8); \
        (p)[2] = (uint8_t)((v) >> 16); \
        (p)[3] = (uint8_t)((v) >> 24); \
    } while (0)
#else
    #define load32_le(p)  bswap32(((uint32_t)(p)[0] << 24) | ((uint32_t)(p)[1] << 16) | \
                                   ((uint32_t)(p)[2] << 8) | (uint32_t)(p)[3])
    #define store32_le(p, v) do { \
        uint32_t _t = bswap32(v); \
        (p)[0] = (uint8_t)(_t >> 24); \
        (p)[1] = (uint8_t)(_t >> 16); \
        (p)[2] = (uint8_t)(_t >> 8); \
        (p)[3] = (uint8_t)(_t); \
    } while (0)
#endif

typedef struct chacha20_t {
    uint32_t counter;
    uint32_t base_counter;
    uint32_t index;
    uint8_t  key[32];
    uint8_t  nonce[12];
    uint8_t  states[64];
} chacha20_t;


/* ********************* INTERNAL FUNCTIONS PROTOTYPE ********************* */
static void stream_crypt(chacha20_t *config, uint8_t *data, uint32_t length);
static void key_setup(
    chacha20_t *config, 
    const uint8_t *key, 
    const uint8_t *nonce, 
    uint32_t counter
);

static void quarter_round(uint32_t *a, uint32_t *b, uint32_t *c, uint32_t *d);
static void double_round(uint32_t x[16]);
static void block(chacha20_t *config);


/* ************************ CRYPTOGRAPHY ALGORITHM ************************ */
static void
stream_crypt(chacha20_t *config, uint8_t *data, uint32_t length)
{
    uint32_t i;
    uint32_t idx = config->index;

    for (i = 0; i < length; i++)
    {
        if ((i + idx) % 64 == 0)
        {
            config->counter = config->base_counter + (uint32_t)((i + idx) / 64);
            block(config);
        }

        data[i] ^= config->states[(i + idx) % 64];
    }

    config->index = (length + idx) % 64;
}

static void
key_setup(chacha20_t *config, const uint8_t *key, const uint8_t *nonce, uint32_t counter)
{
    memcpy(config->key, key, 32);
    memcpy(config->nonce, nonce, 12);

    config->base_counter = counter;
    config->counter = counter;

    config->index = 0;

    memset(config->states, 0, sizeof(config->states));

    block(config);
}


/* ******************* INTERNAL FUNCTIONS IMPLEMENTATION ******************* */
static void
quarter_round(uint32_t *a, uint32_t *b, uint32_t *c, uint32_t *d)
{
    *a += *b; *d ^= *a; *d = rotl(*d, 16);
    *c += *d; *b ^= *c; *b = rotl(*b, 12);
    *a += *b; *d ^= *a; *d = rotl(*d,  8);
    *c += *d; *b ^= *c; *b = rotl(*b,  7);
}

static void
double_round(uint32_t x[16])
{
    quarter_round(&x[0], &x[4], &x[8],  &x[12]);
    quarter_round(&x[1], &x[5], &x[9],  &x[13]);
    quarter_round(&x[2], &x[6], &x[10], &x[14]);
    quarter_round(&x[3], &x[7], &x[11], &x[15]);

    quarter_round(&x[0], &x[5], &x[10], &x[15]);
    quarter_round(&x[1], &x[6], &x[11], &x[12]);
    quarter_round(&x[2], &x[7], &x[8],  &x[13]);
    quarter_round(&x[3], &x[4], &x[9],  &x[14]);
}

static void
block(chacha20_t *config)
{
    static const uint8_t sigma[16] = {
        'e', 'x', 'p', 'a', 'n', 'd', ' ', '3',
        '2', '-', 'b', 'y', 't', 'e', ' ', 'k'
    };

    uint32_t x[16];
    uint32_t z[16];
    uint32_t i;

    /* constants */
    for (i = 0; i < 4; i++)
        x[i] = load32_le(sigma + (i * 4));

    /* key */
    for (i = 0; i < 8; i++)
        x[4 + i] = load32_le(config->key + (i * 4));

    /* counter */
    x[12] = config->counter;

    /* nonce */
    x[13] = load32_le(config->nonce + 0);
    x[14] = load32_le(config->nonce + 4);
    x[15] = load32_le(config->nonce + 8);

    /* working state */
    for (i = 0; i < 16; i++)
        z[i] = x[i];

    /* 20 rounds */
    for (i = 0; i < 10; i++)
        double_round(z);

    /* add original state */
    for (i = 0; i < 16; i++)
        store32_le(config->states + (i * 4), z[i] + x[i]);
}


/* stream port for main.c */
#include "stream_port.h"

const uint32_t STREAM_KEY_BYTES     = 32;
const uint32_t STREAM_NONCE_BYTES   = 12;
const uint32_t STREAM_COUNTER_BYTES =  4;

/*
 * stream_port contract
 *
 * Variant : IETF ChaCha20 (RFC 8439) — 256-bit key, 96-bit nonce, 32-bit block counter.
 *
 * STREAM_KEY_BYTES     = 32  — key[0..31], 256-bit ChaCha key.
 * STREAM_NONCE_BYTES   = 12  — nonce[0..11], 96-bit nonce (little-endian in state).
 * STREAM_COUNTER_BYTES =  4  — counter[0..3], initial block counter (load32_le).
 *
 * Block counter increments internally in stream_crypt(). Encrypt and decrypt must
 * use the same key, nonce, and counter for round-trip.
 *
 * stream_decrypt : same mapping as stream_encrypt.
 */

void
stream_encrypt(
    uint8_t *data, 
    size_t  length, 
    const uint8_t *key,
    const uint8_t *nonce, 
    const uint8_t *counter      // should treat as uint32_t
)
{
    chacha20_t config;
    key_setup(&config, key, nonce, load32_le(counter));
    stream_crypt(&config, data, (uint32_t)length);
}

void
stream_decrypt(
    uint8_t *data, 
    size_t length, 
    const uint8_t *key,
    const uint8_t *nonce, 
    const uint8_t *counter      // should treat as uint32_t
)
{
    chacha20_t config;
    key_setup(&config, key, nonce, load32_le(counter));
    stream_crypt(&config, data, (uint32_t)length);
}
