/*
    Salsa20 
    Archive of Reversing.ID
    Stream Cipher

Compile:
    (msvc, from Codes/Cipher/Stream/)
    $ cl /I. main.c Salsa20/code.c

    (gcc, from Codes/Cipher/Stream/)
    $ gcc -I. -o test main.c Salsa20/code.c

    Demo harness is in main.c (not in this file).

Assemble:
    (gcc)
    $ gcc -m32 -S -masm=intel -o Salsa20/code.asm Salsa20/code.c

    (msvc)
    $ cl /c /FaSalsa20/code.asm Salsa20/code.c
*/

#include <stdint.h>
#include <string.h>
#include <stdlib.h>

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
        #define LITTLE_ENDIAN
    #elif defined(LITTLE_ENDIAN)
        #define LITTLE_ENDIAN
    #else 
        #define BIG_ENDIAN
    #endif
#endif

#ifdef LITTLE_ENDIAN
    #define convert(x)  (x)
#else 
    #define convert(x)  bswap32(x)
#endif

struct salsa20_t;

typedef void (*expand_t)(struct salsa20_t*);

typedef struct salsa20_t {
    uint32_t index;         // index in keystream 
    uint8_t  nonce[16];     // nonce
    uint8_t  key[32];       // key with maximum storage
    uint8_t  states[64];    // keystream
    expand_t expand;        // expand function
} salsa20_t;


/* ********************* INTERNAL FUNCTIONS PROTOTYPE ********************* */
void stream_crypt(salsa20_t * config, uint8_t * data, uint32_t length);
void key_setup(salsa20_t * config, uint8_t * key, uint32_t keybits, uint8_t nonce[16]);

void expand16(salsa20_t * config);
void expand32(salsa20_t * config);

void quarter_round(uint32_t * y0, uint32_t * y1, uint32_t * y2, uint32_t * y3);
void row_round(uint32_t val[16]);
void column_round(uint32_t val[16]);
void double_round(uint32_t x[16]);
void hash(uint8_t data[64]);


/* ************************ CRYPTOGRAPHY ALGORITHM ************************ */
void 
stream_crypt(salsa20_t * config, uint8_t * data, uint32_t length)
{
    uint32_t    i, t;
    uint32_t    idx = config->index;
    uint32_t  * nonce = (uint32_t*)config->nonce;

    for (i = 0; i < length; i++)
    {
        /*
            if we've used entire keystream block or just begin new block boundary
            produce keystream block
        */ 
        if ((i + idx) % 64 == 0)
        {
            t = (i + idx) / 64;
            nonce[2] = convert(t);
            config->expand(config);
        }

        data[i] ^= config->states[(i + idx) % 64];
    }

    config->index = (length + idx) % 64;
}

void 
key_setup(salsa20_t * config, uint8_t * key, uint32_t keybits, uint8_t nonce[16])
{
    uint32_t i;
    uint32_t * p_nonce = (uint32_t*)config->nonce;

    config->expand = (keybits == 256 ? expand32 : expand16);

    memcpy(config->key, key, (keybits == 256 ? 32 : 16));
    memcpy(config->nonce, nonce, 8);
    memset(config->nonce + 8, 0, 8);
    memset(config->states, 0, 64);

    config->expand(config);
}


/* ******************* INTERNAL FUNCTIONS IMPLEMENTATION ******************* */
void 
quarter_round(uint32_t * y0, uint32_t * y1, uint32_t * y2, uint32_t * y3)
{
    *y1 ^= rotl(*y0 + *y3,  7);
    *y2 ^= rotl(*y1 + *y0,  9);
    *y3 ^= rotl(*y2 + *y1, 13);
    *y0 ^= rotl(*y3 + *y2, 18);
}

void 
row_round(uint32_t val[16])
{
    quarter_round(&val[ 0], &val[ 1], &val[ 2], &val[ 3]);
    quarter_round(&val[ 5], &val[ 6], &val[ 7], &val[ 4]);
    quarter_round(&val[10], &val[11], &val[ 8], &val[ 9]);
    quarter_round(&val[15], &val[12], &val[13], &val[14]);
}

void 
column_round(uint32_t val[16])
{
    quarter_round(&val[ 0], &val[ 4], &val[ 8], &val[12]);
    quarter_round(&val[ 5], &val[ 9], &val[13], &val[ 1]);
    quarter_round(&val[10], &val[14], &val[ 2], &val[ 6]);
    quarter_round(&val[15], &val[ 3], &val[ 7], &val[11]);
}

void 
double_round(uint32_t val[16])
{
    column_round(val);
    row_round(val);
}

void 
hash(uint8_t seq[64])
{
    uint32_t * p_seq = (uint32_t *)seq;
    uint32_t   i;
    uint32_t   x[16], z[16];

    for (i = 0; i < 16; i++)
        x[i] = z[i] = convert(p_seq[i]);

    for (i = 0; i < 10; i++)
        double_round(z);

    for (i = 0; i < 16; i++)
    {
        z[i] += x[i];
        p_seq[i] = convert(z[i]);
    }
}

void 
expand16(salsa20_t * config)
{
    uint32_t i, j;
    uint8_t  t[4][4] = {
        { 'e', 'x', 'p', 'a' },
        { 'n', 'd', ' ', '1' },
        { '6', '-', 'b', 'y' },
        { 't', 'e', ' ', 'k' }
    };

    uint8_t * key = config->key;
    uint8_t * nonce = config->nonce;
    uint8_t * keystream = config->states;

    // copy all of 'tau' into the correct spots in keystream
    for (i = 0; i < 64; i += 20)
        for (j = 0; j < 4; j++)
            keystream[i + j] = t[i / 20][j];
    
    // copy the key and nonce into the keystream
    for (i = 0; i < 16; i++)
    {
        keystream[i +  4] = key[i];
        keystream[i + 44] = key[i];
        keystream[i + 24] = nonce[i];
    }

    hash(keystream);
}

void 
expand32(salsa20_t * config)
{
    uint32_t i, j;
    uint8_t  t[4][4] = {
        { 'e', 'x', 'p', 'a' },
        { 'n', 'd', ' ', '3' },
        { '2', '-', 'b', 'y' },
        { 't', 'e', ' ', 'k' }
    };

    uint8_t * key = config->key;
    uint8_t * nonce = config->nonce;
    uint8_t * keystream = config->states;

    // copy all of 'tau' into the correct spots in keystream
    for (i = 0; i < 64; i += 20)
        for (j = 0; j < 4; j++)
            keystream[(i + j) % 64] = t[i / 20][j];
    
    // copy the key and nonce into the keystream
    for (i = 0; i < 16; i++)
    {
        keystream[i +  4] = key[i     ];
        keystream[i + 44] = key[i + 16];
        keystream[i + 24] = nonce[i];
    }

    hash(keystream);
}


/* stream port for main.c */
#include "stream_port.h"

const uint32_t STREAM_KEY_BYTES   = 32;
const uint32_t STREAM_NONCE_BYTES = 16;

void
stream_encrypt(uint8_t *data, size_t length, const uint8_t *key, const uint8_t *nonce)
{
    salsa20_t config;
    key_setup(&config, (uint8_t *)key, 256, (uint8_t *)nonce);
    stream_crypt(&config, data, length);
}

void
stream_decrypt(uint8_t *data, size_t length, const uint8_t *key, const uint8_t *nonce)
{
    salsa20_t config;
    key_setup(&config, (uint8_t *)key, 256, (uint8_t *)nonce);
    stream_crypt(&config, data, length);
}

