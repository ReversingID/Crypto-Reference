/*
    Khufu
    Archive of Reversing.ID
    Block Cipher

Compile:
    (msvc, from Codes/Cipher/Block/)
    $ cl /I. main.c mode.c Khufu/code.c

    (gcc, from Codes/Cipher/Block/)
    $ gcc -I. -o test main.c mode.c Khufu/code.c

    Modes of operation are in mode.c (not in this file).

Assemble:
    (gcc)
    $ gcc -m32 -S -masm=intel -o Khufu/code.asm Khufu/code.c

    (msvc)
    $ cl /c /FaKhufu/code.asm Khufu/code.c
*/
#include <stdint.h>
#include <string.h>

/* ************************* CONFIGURATION & SEED ************************* */
#define BLOCKSIZE       64
#define BLOCKSIZEB      8
#define KEYSIZE         512
#define KEYSIZEB        64
#define ROUNDS          16

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
void block_encrypt(uint8_t * data, uint8_t key[KEYSIZEB]);
void block_decrypt(uint8_t * data, uint8_t key[KEYSIZEB]);

void gen_sbox(uint8_t * sbox, uint8_t * key, uint32_t round);


/* ************************ CRYPTOGRAPHY ALGORITHM ************************ */
/* 
    Enkripsi sebuah block dengan Khufu. 
    Pastikan konfigurasi telah dilakukan dengan memanggil key_setup()
*/
void 
block_encrypt(uint8_t * data, uint8_t key[KEYSIZEB])
{
    uint32_t  * p_data = (uint32_t*)data;
    uint32_t  * p_key  = (uint32_t*)key;
    uint8_t     sbox[256];

    uint32_t    left  = convert(p_data[0]),
                right = convert(p_data[1]),
                temp, round;

    left  ^= convert(p_key[0]);
    right ^= convert(p_key[1]);

    for (round = 0; round < ROUNDS; round++)
    {
        gen_sbox(sbox, key, round);
        
        temp  = left;
        left  = right ^ sbox[left & 0xFF];
        right = rotr(temp, 8);

        temp  = left;
        left  = right;
        right = temp;
    }

    left  ^= convert(p_key[2]);
    right ^= convert(p_key[3]);

    p_data[0] = convert(left);
    p_data[1] = convert(right);
}

/* 
    Dekripsi sebuah block dengan Khufu. 
    Pastikan konfigurasi telah dilakukan dengan memanggil key_setup()
*/
void 
block_decrypt(uint8_t * data, uint8_t key[KEYSIZEB])
{
    uint32_t  * p_data = (uint32_t*)data;
    uint32_t  * p_key  = (uint32_t*)key;
    uint8_t     sbox[256];

    uint32_t    left  = convert(p_data[0]),
                right = convert(p_data[1]),
                temp;
    int32_t     round;

    left  ^= convert(p_key[2]);
    right ^= convert(p_key[3]);

    for (round = ROUNDS - 1; round >= 0; round--)
    {
        gen_sbox(sbox, key, round);

        temp  = right;
        right = left ^ sbox[right & 0xFF];
        left  = rotl(temp, 8);

        temp  = left;
        left  = right;
        right = temp;
    }

    left  ^= convert(p_key[0]);
    right ^= convert(p_key[1]);

    p_data[0] = convert(left);
    p_data[1] = convert(right);
}


/* ******************* INTERNAL FUNCTIONS IMPLEMENTATION ******************* */
void 
gen_sbox(uint8_t * sbox,uint8_t * key, uint32_t round)
{
    uint32_t i;

    for (i = 0; i < 256; i++)
    {
        sbox[i] = 
            (key[(round * 8 + i    ) % KEYSIZEB] << 24) ^
            (key[(round * 8 + i + 1) % KEYSIZEB] << 16) ^
            (key[(round * 8 + i + 2) % KEYSIZEB] << 8) ^
            (key[(round * 8 + i + 3) % KEYSIZEB]);
    }
}
#include "cipher_port.h"
const uint32_t CIPHER_BLOCK_BYTES = BLOCKSIZEB;
const uint32_t CIPHER_KEY_BYTES   = KEYSIZEB;
void cipher_ctx_init(uint8_t *ctx, const uint8_t *key) { memcpy(ctx, key, KEYSIZEB); }
void cipher_encrypt_block(uint8_t *ctx, uint8_t *block) { block_encrypt(block, (uint8_t *)ctx); }
void cipher_decrypt_block(uint8_t *ctx, uint8_t *block) { block_decrypt(block, (uint8_t *)ctx); }
