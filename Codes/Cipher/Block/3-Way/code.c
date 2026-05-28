/*
    3-Way by John Daemen
    Archive of Reversing.ID
    Block Cipher

Compile:
    (msvc, from Codes/Cipher/Block/)
    $ cl /I. main.c mode.c 3-Way/code.c

    (gcc, from Codes/Cipher/Block/)
    $ gcc -I. -o test main.c mode.c 3-Way/code.c

    Modes of operation are in mode.c (not in this file).

Assemble:
    (gcc)
    $ gcc -m32 -S -masm=intel -o 3-Way/code.asm 3-Way/code.c

    (msvc)
    $ cl /c /Fa3-Way/code.asm 3-Way/code.c
*/
#include <stdint.h>
#include <string.h>

/* ************************* CONFIGURATION & SEED ************************* */
#define BLOCKSIZE       96
#define BLOCKSIZEB      12
#define KEYSIZE         96
#define KEYSIZEB        12
#define ROUNDS          11

#define STRT_E          0x0b0b      /* constant for first encryption round */ 
#define STRT_D          0xb1b1      /* constant for first decryption round */

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
    #define convert(x) bswap32(x)
#else 
    #define convert(x) (x)
#endif


/* ********************* INTERNAL FUNCTIONS PROTOTYPE ********************* */
void block_encrypt(uint8_t * data, uint8_t * key);
void block_decrypt(uint8_t * data, uint8_t * key);

void mu(uint32_t * data);
void gamma(uint32_t * data);
void theta(uint32_t * data);
void rho(uint32_t * data);

void pi_1(uint32_t * data);
void pi_2(uint32_t * data);

void rndcon_gen(uint32_t start, uint32_t *rtab);


/* ************************ CRYPTOGRAPHY ALGORITHM ************************ */
/* 
    Enkripsi sebuah block dengan 3-Way. 
    Data direpresentasikan sebagai 3 integer 32-bit.
*/
void 
block_encrypt(uint8_t * data, uint8_t * key)
{
    uint32_t i;
    uint32_t rcon[ROUNDS + 1];
    uint32_t _data[3], _key[3];

    uint32_t * p_data = (uint32_t*)data;
    uint32_t * p_key  = (uint32_t*)key;

    for (i = 0; i < 3; i++)
    {
        _data[i] = convert(p_data[i]);
        _key[i]  = convert(p_key[i]);
    }

    rndcon_gen(STRT_E, rcon);
    for (i = 0; i < ROUNDS; i++)
    {
        _data[0] ^= _key[0] ^ (rcon[i] << 16);
        _data[1] ^= _key[1];
        _data[2] ^= _key[2] ^ rcon[i];
        rho(_data);
    }

    _data[0] ^= _key[0] ^ (rcon[ROUNDS] << 16);
    _data[1] ^= _key[1];
    _data[2] ^= _key[2] ^ rcon[ROUNDS];
    theta(_data);

    for (i = 0; i < 3; i++)
        p_data[i] = convert(_data[i]);
}


/* 
    Dekripsi sebuah block dengan 3-Way. 
    Pastikan konfigurasi telah dilakukan dengan memanggil key_setup()
*/
void 
block_decrypt(uint8_t * data, uint8_t * key)
{
    uint32_t i;
    uint32_t rcon[ROUNDS + 1];
    uint32_t _data[3], _key[3];

    uint32_t * p_data = (uint32_t*)data;
    uint32_t * p_key  = (uint32_t*)key;

    for (i = 0; i < 3; i++)
    {
        _data[i] = convert(p_data[i]);
        _key[i]  = convert(p_key[i]);
    }

    theta(_key);
    mu(_key);
    mu(_data);

    rndcon_gen(STRT_D, rcon);
    for (i = 0; i < ROUNDS; i++)
    {
        _data[0] ^= _key[0] ^ (rcon[i] << 16);
        _data[1] ^= _key[1];
        _data[2] ^= _key[2] ^ rcon[i];
        rho(_data);
    }

    _data[0] ^= _key[0] ^ (rcon[ROUNDS] << 16);
    _data[1] ^= _key[1];
    _data[2] ^= _key[2] ^ rcon[ROUNDS];
    theta(_data);
    mu(_data);

    for (i = 0; i < 3; i++)
        p_data[i] = convert(_data[i]);
}


/* ******************* INTERNAL FUNCTIONS IMPLEMENTATION ******************* */
void mu(uint32_t * data)
{
    uint32_t i, temp[3];

	temp[0] = temp[1] = temp[2] = 0;
	for (i = 0; i < 32; i++) {
		temp[0] <<= 1;
		temp[1] <<= 1;
		temp[2] <<= 1;

		if (data[0] & 1)
			temp[2] |= 1;
		if (data[1] & 1)
			temp[1] |= 1;
		if (data[2] & 1)
			temp[0] |= 1;

		data[0] >>= 1;
		data[1] >>= 1;
		data[2] >>= 1;
	}

	data[0] = temp[0];
	data[1] = temp[1];
	data[2] = temp[2];
}

void gamma(uint32_t * data)
{
    uint32_t temp[3];

    temp[0] = data[0] ^ (data[1] | (~data[2]));
    temp[1] = data[1] ^ (data[2] | (~data[0]));
    temp[2] = data[2] ^ (data[0] | (~data[1]));

    data[0] = temp[0];
    data[1] = temp[1];
    data[2] = temp[2];
}

void theta(uint32_t * data)
{
    uint32_t temp[3];

    temp[0] =
	     data[0] ^ 
        (data[0] >> 16) ^ (data[1] << 16) ^ (data[1] >> 16) ^ (data[2] << 16) ^
	    (data[1] >> 24) ^ (data[2] <<  8) ^ (data[2] >>  8) ^ (data[0] << 24) ^ 
        (data[2] >> 16) ^ (data[0] << 16) ^ (data[2] >> 24) ^ (data[0] << 8);
	temp[1] =
	     data[1] ^ 
        (data[1] >> 16) ^ (data[2] << 16) ^ (data[2] >> 16) ^ (data[0] << 16) ^
	    (data[2] >> 24) ^ (data[0] <<  8) ^ (data[0] >>  8) ^ (data[1] << 24) ^ 
        (data[0] >> 16) ^ (data[1] << 16) ^ (data[0] >> 24) ^ (data[1] << 8);
	temp[2] =
	     data[2] ^ 
        (data[2] >> 16) ^ (data[0] << 16) ^ (data[0] >> 16) ^ (data[1] << 16) ^
	    (data[0] >> 24) ^ (data[1] <<  8) ^ (data[1] >>  8) ^ (data[2] << 24) ^ 
        (data[1] >> 16) ^ (data[2] << 16) ^ (data[1] >> 24) ^ (data[2] << 8);

	data[0] = temp[0];
	data[1] = temp[1];
	data[2] = temp[2];
}

void rho(uint32_t * data)
{
    theta(data);
	pi_1(data);
	gamma(data);
	pi_2(data);
}

void pi_1(uint32_t * data)
{
    data[0] = (data[0] >> 10) ^ (data[0] << 22);
	data[2] = (data[2] <<  1) ^ (data[2] >> 31);
}

void pi_2(uint32_t * data)
{
    data[0] = (data[0] <<  1) ^ (data[0] >> 31);
	data[2] = (data[2] >> 10) ^ (data[2] << 22);
}

void rndcon_gen(uint32_t start, uint32_t *rtab)
{
    uint32_t i;

    for (i = 0; i <= ROUNDS; i++)
    {
        rtab[i] = start;
        start <<= 1;
        if (start & 0x10000)
            start ^= 0x11011;
    }
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
