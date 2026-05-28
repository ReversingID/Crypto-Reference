/*
    RC4 or ARC4
    Archive of Reversing.ID
    Stream Cipher

Compile:
    (msvc, from Codes/Cipher/Stream/)
    $ cl /I. main.c RC4/code.c

    (gcc, from Codes/Cipher/Stream/)
    $ gcc -I. -o test main.c RC4/code.c

    Demo harness is in main.c (not in this file).

Assemble:
    (gcc)
    $ gcc -m32 -S -masm=intel -o RC4/code.asm RC4/code.c

    (msvc)
    $ cl /c /FaRC4/code.asm RC4/code.c
*/

#include <stdint.h>
#include <string.h>
#include <stdlib.h>

/* ************************ CONFIGURATION & SEED ************************ */
#define swap(x, y)      tmp = x; x = y; y = tmp;

typedef struct
{      
   uint8_t state[256];       
   uint8_t i, j;
} rc4_t;


/* ********************* INTERNAL FUNCTIONS PROTOTYPE ********************* */
void stream_crypt(rc4_t * config, uint8_t * data, size_t length);
void key_setup(rc4_t * config, const uint8_t * key, size_t length);


/* ************************ CRYPTOGRAPHY ALGORITHM ************************ */
void 
stream_crypt(rc4_t * config, uint8_t * data, size_t length)
{
    register uint32_t tmp, ctr, i, j;
    uint8_t * state = config->state;

    i = config->i;
    j = config->j;

    for (ctr = 0; ctr < length; ctr++)
    {
        i++;

        i &= 0xFF;
        j += state[i];
        j &= 0xFF;

        swap(state[i], state[j]);
        data[ctr] ^= state[(state[i] + tmp) & 0xff];
    }

    config->i = i;
    config->j = j;
}

void 
key_setup(rc4_t * config, const uint8_t * key, size_t length)
{
    register uint32_t tmp, i, j;
    uint8_t * state = config->state;

    for (i = 0; i < 256; i++)
        state[i] = i;

    config->i = config->j = 0;

    for (j = i = 0; i < 256; i++)
    {
        j += state[i] + key[i % length];
        j &= 0xff;
        swap(state[i], state[j]);
    }
}


/* stream port for main.c */
#include "stream_port.h"

const uint32_t STREAM_KEY_BYTES   = 32;
const uint32_t STREAM_NONCE_BYTES = 0;

void
stream_encrypt(uint8_t *data, size_t length, const uint8_t *key, const uint8_t *nonce)
{
    rc4_t config;
    key_setup(&config, key, STREAM_KEY_BYTES);
    stream_crypt(&config, data, length);
}

void
stream_decrypt(uint8_t *data, size_t length, const uint8_t *key, const uint8_t *nonce)
{
    rc4_t config;
    key_setup(&config, key, STREAM_KEY_BYTES);
    stream_crypt(&config, data, length);
}

