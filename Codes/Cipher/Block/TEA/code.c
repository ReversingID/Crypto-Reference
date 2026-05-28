/*
    Tiny Encryption Algorithm (TEA)
    Archive of Reversing.ID
    Block Cipher

Compile:
    (msvc, from Codes/Cipher/Block/)
    $ cl /I. main.c mode.c TEA/code.c

    (gcc, from Codes/Cipher/Block/)
    $ gcc -I. -o test main.c mode.c TEA/code.c

    Modes of operation are in mode.c (not in this file).

Assemble:
    (gcc)
    $ gcc -m32 -S -masm=intel -o TEA/code.asm TEA/code.c

    (msvc)
    $ cl /c /FaTEA/code.asm TEA/code.c
*/
#include <stdint.h>
#include <string.h>

/* ************************* CONFIGURATION & SEED ************************* */
#define BLOCKSIZE   64
#define BLOCKSIZEB  8
#define KEYSIZE     64
#define KEYSIZEB    8
#define ROUNDS      32

#ifdef _MSC_VER
    #include <stdlib.h>
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
    #else 
        #define BIG_ENDIAN
    #endif
#endif

#ifdef LITTLE_ENDIAN
    #define convert(x)   bswap32(x)
#else
    #define convert(x)   (x)
#endif


/* ********************* INTERNAL FUNCTIONS PROTOTYPE ********************* */
void block_encrypt (uint8_t * val, uint8_t * key);
void block_decrypt (uint8_t * val, uint8_t * key);


/* ************************ CRYPTOGRAPHY ALGORITHM ************************ */
/*
    Enkripsi sebuah block dengan TEA.
    Sebuah block didefinisikan sebagai dua buah bilangan 32-bit atau 
    setara dengan 64-bit data.
*/
void 
block_encrypt (uint8_t * val, uint8_t * key)
{
    uint32_t v0, v1, k0, k1, k2, k3;
    uint32_t delta = 0x9E3779B9, sum = 0, i;

    uint32_t * p_val = (uint32_t*)val;
    uint32_t * p_key = (uint32_t*)key;

    v0 = convert(p_val[0]);
    v1 = convert(p_val[1]);
    k0 = convert(p_key[0]);
    k1 = convert(p_key[1]);
    k2 = convert(p_key[2]);
    k3 = convert(p_key[3]);

    // Round: 32
    for (i =  0; i < ROUNDS; i++)
    {
        // Round-Function
        sum += delta;
        v0  += ((v1 << 4) + k0) ^ (v1 + sum) ^ ((v1 >> 5) + k1);
        v1  += ((v0 << 4) + k2) ^ (v0 + sum) ^ ((v0 >> 5) + k3);
    }

    p_val[0] = convert(v0);
    p_val[1] = convert(v1);
}


/*
    Dekripsi sebuah block dengan TEA.
    Sebuah block didefinisikan sebagai dua buah bilangan 32-bit atau 
    setara dengan 64-bit data.
*/
void 
block_decrypt(uint8_t * val, uint8_t * key)
{
    uint32_t v0, v1, k0, k1, k2, k3;
    uint32_t delta = 0x9E3779B9, sum = 0xC6EF3720, i;

    uint32_t * p_val = (uint32_t*)val;
    uint32_t * p_key = (uint32_t*)key;

    v0 = convert(p_val[0]);
    v1 = convert(p_val[1]);
    k0 = convert(p_key[0]);
    k1 = convert(p_key[1]);
    k2 = convert(p_key[2]);
    k3 = convert(p_key[3]);
    
    // Round: 32
    for (i =  0; i < ROUNDS; i++)
    {
        // Inverse Round-Function
        v1  -= ((v0 << 4) + k2) ^ (v0 + sum) ^ ((v0 >> 5) + k3);
        v0  -= ((v1 << 4) + k0) ^ (v1 + sum) ^ ((v1 >> 5) + k1);
        sum -= delta;
    }

    p_val[0] = convert(v0);
    p_val[1] = convert(v1);
}


/* cipher port for mode.c */
#include "cipher_port.h"

const uint32_t CIPHER_BLOCK_BYTES = BLOCKSIZEB;
const uint32_t CIPHER_KEY_BYTES   = KEYSIZEB;

void cipher_ctx_init(uint8_t *ctx, const uint8_t *key)
{
    memcpy(ctx, key, KEYSIZEB);
}

void cipher_encrypt_block(uint8_t *ctx, uint8_t *block)
{
    block_encrypt(block, ctx);
}

void cipher_decrypt_block(uint8_t *ctx, uint8_t *block)
{
    block_decrypt(block, ctx);
}
