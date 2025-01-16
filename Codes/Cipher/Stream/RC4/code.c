/*
    RC4 or ARC4
    Archive of Reversing.ID
    Stream Cipher

Compile:
    (msvc)
    $ cl code.c

Assemble:
    (gcc)
    $ gcc -m32 -S -masm=intel -o code.asm code.c

    (msvc)
    $ cl /c /FaBBS.asm code.c
*/

#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

/* ************************ CONFIGURATION & SEED ************************ */
#define swap(x, y)      tmp = x; x = y; y = tmp;

typedef struct arcfour_key
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

/* ******************* INTERNAL FUNCTIONS IMPLEMENTATION ******************* */
/*
    Turunkan kunci berdasarkan kunci dan IV    
*/
void key_setup(rc4_t * config, const uint8_t * key, size_t length)
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


/* ************************ WRAPPER ************************ */
void rc4_encrypt(uint8_t * data, size_t length, const uint8_t * key, size_t key_length)
{
    rc4_t config;
    key_setup(&config, key, key_length);
    stream_crypt(&config, data, length);
}

void rc4_decrypt(uint8_t * data, size_t length, const uint8_t * key, size_t key_length)
{
    rc4_t config;
    key_setup(&config, key, key_length);
    stream_crypt(&config, data, length);
}


/* ************************ CONTOH PENGGUNAAN ************************ */
#include "../testutil.h"

int main(int argc, char* argv[])
{
    int  i, length;
    char data[] = "Reversing.ID - Reverse Engineering Community";
    char encbuffer[64];
    char decbuffer[64]; 

    /* 
    secret key: 32-bytes 
    Meskipun key didefinisikan sebagai 32-byte karakter, hanya 8 karakter saja yang
    digunakan, karena bits dikonfigurasi sebagai 64-bit (8-byte).
    */
    uint8_t key[32] =
            { 0x52, 0x45, 0x56, 0x45, 0x52, 0x53, 0x49, 0x4E, 0x47, 0x2E, 0x49, 0x44, 
    /* ASCII:   R     E     V     E     R     S     I     N     G     .     I     D  */
              0x53, 0x45, 0x43, 0x52, 0x45, 0x54, 0x20, 0x4b, 0x45, 0x59, 0x31, 0x32,
            /*  S     E     C     R     E     T           K     E     Y     1     2  */
              0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x30 };
            /*  3     4     5     6     7     8     9     0 */
    
    /*
    initialization vector: 32-bytes

    WIP: implementasi RC4 dengan IV
    */
    uint8_t iv[32] = 
            { 0x13, 0x51, 0x00, 0x30, 0xD7, 0xA4, 0xC5, 0xAE, 0xCB, 0x55, 0xA7, 0x1C,
              0x25, 0x3F, 0x41, 0x4D, 0xFC, 0x25, 0x03, 0x0D, 0x65, 0x33, 0xF6, 0x65, 
              0x2E, 0xCF, 0x37, 0xAB, 0x33, 0xF6, 0x65, 0xB3 };

    length = strlen(data);
    printf("Length: %zd - Buffer: %s\n", strlen(data), data);
    printx("Original", data, length);

    /*
    Panjang plaintext: 44
    stream cipher tidak mensyaratkan panjang data dalam kelipatan tertentu.
    */
    memset(encbuffer, 0, sizeof(encbuffer));
    memset(decbuffer, 0, sizeof(decbuffer));

    memcpy(encbuffer, data, length);
    rc4_encrypt(encbuffer, length, key, 32);
    printx("Encrypted:", encbuffer, length);

    memcpy(decbuffer, encbuffer, length);
    rc4_decrypt(decbuffer, length, key, 32);
    printx("Decrypted:", decbuffer, length);

    printf("\nFinal: %s\n", decbuffer);

    return 0;
}


