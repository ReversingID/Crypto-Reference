/*
    LEA by Deukjo Hong, Jung-Keun Lee, Dong-Chan Kim, Daesung Kwon, Kwon Ho Ryu, Dong-Geon Lee
    Archive of Reversing.ID
    Block Cipher

Compile:
    (msvc, from Codes/Cipher/Block/)
    $ cl /I. main.c mode.c LEA/code.c

    (gcc, from Codes/Cipher/Block/)
    $ gcc -I. -o test main.c mode.c LEA/code.c

    Modes of operation are in mode.c (not in this file).

Assemble:
    (gcc)
    $ gcc -m32 -S -masm=intel -o LEA/code.asm LEA/code.c

    (msvc)
    $ cl /c /FaLEA/code.asm LEA/code.c
*/
#include <stdint.h>
#include <string.h>

/* ************************* CONFIGURATION & SEED ************************* */
#define BLOCKSIZE       128
#define BLOCKSIZEB      16
#define KEYSIZE         128
#define KEYSIZEB        16

#ifdef _MSC_VER
    #include <stdlib.h>
    #pragma intrinsic(_lrotr,_lrotl)
    #define rotr(x,n)   _lrotr(x,n)
    #define rotl(x,n)   _lrotl(x,n)
#else 
    #define rotr(x,n)   (((x) >> ((int)(n))) | ((x) << (32 - (int)(n))))
    #define rotl(x,n)   (((x) << ((int)(n))) | ((x) >> (32 - (int)(n))))
#endif


const uint32_t delta[8] = {
    0xc3efe9db, 0x44626b02, 0x79e27c8a, 0x78df30ec,
    0x715ea49e, 0xc785da0a, 0xe04ef22a, 0xe5c40957
};


/* context and configuration */
typedef struct 
{
    uint32_t bits;
    uint32_t rounds;
    uint32_t rkeys[256];
} lea_t;


/* ********************* INTERNAL FUNCTIONS PROTOTYPE ********************* */
void block_encrypt(lea_t * config, uint8_t * val);
void block_decrypt(lea_t * config, uint8_t * val);
void key_setup(lea_t * config, uint8_t * secret, uint32_t bits);


/* ************************ CRYPTOGRAPHY ALGORITHM ************************ */
/* 
    Enkripsi sebuah block dengan LEA. 
    Pastikan konfigurasi telah dilakukan dengan memanggil key_setup()
*/
void 
block_encrypt(lea_t * config, uint8_t * val)
{
    // block: 32 * 4 = 128 bit
    uint32_t * rkeys  = config->rkeys;
    uint32_t   rounds = config->rounds;
    uint32_t   current[4], next[4];
    size_t     idx;

    memcpy(current, val, 16);

    for (idx = 0; idx < rounds; idx++)
    {
        next[0] = rotl((current[0] ^ rkeys[idx * 6    ]) + (current[1] ^ rkeys[idx * 6 + 1]), 9);
		next[1] = rotr((current[1] ^ rkeys[idx * 6 + 2]) + (current[2] ^ rkeys[idx * 6 + 3]), 5);
		next[2] = rotr((current[2] ^ rkeys[idx * 6 + 4]) + (current[3] ^ rkeys[idx * 6 + 5]), 3);
		next[3] = current[0];

        memcpy(current, next, 16);
    }

    memcpy(val, next, 16);
}

/* 
    Dekripsi sebuah block dengan LEA. 
    Pastikan konfigurasi telah dilakukan dengan memanggil key_setup()
*/
void 
block_decrypt(lea_t * config, uint8_t * val)
{
    // block: 32 * 4 = 128 bit
    uint32_t * rkeys  = config->rkeys;
    uint32_t   rounds = config->rounds;
    uint32_t   current[4], next[4];
    size_t     idx;

    memcpy(current, val, 16);

    for (idx = 0; idx < rounds; idx++)
    {
        next[0] = current[3];
        next[1] = (rotr(current[0], 9) - (next[0] ^ rkeys[((rounds - idx - 1) * 6)    ])) ^ rkeys[((rounds - idx - 1) * 6) + 1];
		next[2] = (rotl(current[1], 5) - (next[1] ^ rkeys[((rounds - idx - 1) * 6) + 2])) ^ rkeys[((rounds - idx - 1) * 6) + 3];
		next[3] = (rotl(current[2], 3) - (next[2] ^ rkeys[((rounds - idx - 1) * 6) + 4])) ^ rkeys[((rounds - idx - 1) * 6) + 5];

        memcpy(current, next, 16);
    }

    memcpy(val, current, 16);
}


/* ******************* INTERNAL FUNCTIONS IMPLEMENTATION ******************* */
void 
key_setup(lea_t * config, uint8_t * secret, uint32_t bits)
{
    uint32_t   T[8];
    size_t     idx;

    config->bits = bits;
    memcpy(T, secret, config->bits / 8);
    memset(config->rkeys, 0, sizeof(config->rkeys));

    // generate round keys
    if (config->bits == 128)
    {
        config->rounds = 24;
        for (idx = 0; idx < config->rounds; idx++)
        {
            T[0] = rotl(T[0] + rotl(idx    , delta[idx % 4]),  1);
            T[1] = rotl(T[1] + rotl(idx + 1, delta[idx % 4]),  3);
            T[2] = rotl(T[2] + rotl(idx + 2, delta[idx % 4]),  6);
            T[3] = rotl(T[3] + rotl(idx + 3, delta[idx % 4]), 11);

            config->rkeys[idx * 6    ] = T[0];
            config->rkeys[idx * 6 + 1] = T[1];
            config->rkeys[idx * 6 + 2] = T[2];
            config->rkeys[idx * 6 + 3] = T[1];
            config->rkeys[idx * 6 + 4] = T[3];
            config->rkeys[idx * 6 + 5] = T[1];
        }
    }
    else if (config->bits == 192)
    {
        config->rounds = 28;
        for (idx = 0; idx < config->rounds; idx ++)
        {
            T[0] = rotl(T[0] + rotl(idx    , delta[idx % 6]),  1);
            T[1] = rotl(T[1] + rotl(idx + 1, delta[idx % 6]),  3);
            T[2] = rotl(T[2] + rotl(idx + 2, delta[idx % 6]),  6);
            T[3] = rotl(T[3] + rotl(idx + 3, delta[idx % 6]), 11);
            T[4] = rotl(T[4] + rotl(idx + 4, delta[idx % 6]), 13);
            T[5] = rotl(T[5] + rotl(idx + 5, delta[idx % 6]), 17);
            
            config->rkeys[idx * 6    ] = T[0];
            config->rkeys[idx * 6 + 1] = T[1];
            config->rkeys[idx * 6 + 2] = T[2];
            config->rkeys[idx * 6 + 3] = T[3];
            config->rkeys[idx * 6 + 4] = T[4];
            config->rkeys[idx * 6 + 5] = T[5];
        
        }
    }
    else if (config->bits == 256)
    {
        config->rounds = 32;
        for (idx = 0; idx < config->rounds; idx++)
        {
            T[(6 * idx    ) % 8] =rotl(T[(6 * idx    ) % 8] + rotl(idx    , delta[idx % 8]),  1);
            T[(6 * idx + 1) % 8] =rotl(T[(6 * idx + 1) % 8] + rotl(idx + 1, delta[idx % 8]),  3);
            T[(6 * idx + 2) % 8] =rotl(T[(6 * idx + 2) % 8] + rotl(idx + 2, delta[idx % 8]),  6);
            T[(6 * idx + 3) % 8] =rotl(T[(6 * idx + 3) % 8] + rotl(idx + 3, delta[idx % 8]), 11);
            T[(6 * idx + 4) % 8] =rotl(T[(6 * idx + 4) % 8] + rotl(idx + 4, delta[idx % 8]), 13);
            T[(6 * idx + 5) % 8] =rotl(T[(6 * idx + 5) % 8] + rotl(idx + 5, delta[idx % 8]), 17);
            
            config->rkeys[idx * 6    ] = T[(idx * 6    ) % 8];
            config->rkeys[idx * 6 + 1] = T[(idx * 6 + 1) % 8];
            config->rkeys[idx * 6 + 2] = T[(idx * 6 + 2) % 8];
            config->rkeys[idx * 6 + 3] = T[(idx * 6 + 3) % 8];
            config->rkeys[idx * 6 + 4] = T[(idx * 6 + 4) % 8];
            config->rkeys[idx * 6 + 5] = T[(idx * 6 + 5) % 8];
        }
    }
}
/* cipher port for mode.c */
#include "cipher_port.h"

const uint32_t CIPHER_BLOCK_BYTES = BLOCKSIZEB;
const uint32_t CIPHER_KEY_BYTES   = KEYSIZEB;

void
cipher_ctx_init(uint8_t *ctx, const uint8_t *key)
{
    key_setup((lea_t *)ctx, (uint8_t *)key, KEYSIZE);
}

void
cipher_encrypt_block(uint8_t *ctx, uint8_t *block)
{
    block_encrypt((lea_t *)ctx, block);
}

void
cipher_decrypt_block(uint8_t *ctx, uint8_t *block)
{
    block_decrypt((lea_t *)ctx, block);
}
