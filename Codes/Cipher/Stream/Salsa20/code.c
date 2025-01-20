/*
    Salsa20 
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


/* ******************************* HELPERS ******************************* */


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

/*
    Membangun internal states berdasarkan key
*/
void key_setup(salsa20_t * config, uint8_t * key, uint32_t keybits, uint8_t nonce[16])
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
void quarter_round(uint32_t * y0, uint32_t * y1, uint32_t * y2, uint32_t * y3)
{
    *y1 ^= rotl(*y0 + *y3,  7);
    *y2 ^= rotl(*y1 + *y0,  9);
    *y3 ^= rotl(*y2 + *y1, 13);
    *y0 ^= rotl(*y3 + *y2, 18);
}

void row_round(uint32_t val[16])
{
    quarter_round(&val[ 0], &val[ 1], &val[ 2], &val[ 3]);
    quarter_round(&val[ 5], &val[ 6], &val[ 7], &val[ 4]);
    quarter_round(&val[10], &val[11], &val[ 8], &val[ 9]);
    quarter_round(&val[15], &val[12], &val[13], &val[14]);
}

void column_round(uint32_t val[16])
{
    quarter_round(&val[ 0], &val[ 4], &val[ 8], &val[12]);
    quarter_round(&val[ 5], &val[ 9], &val[13], &val[ 1]);
    quarter_round(&val[10], &val[14], &val[ 2], &val[ 6]);
    quarter_round(&val[15], &val[ 3], &val[ 7], &val[11]);
}

void double_round(uint32_t val[16])
{
    column_round(val);
    row_round(val);
}

void hash(uint8_t seq[64])
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

void expand16(salsa20_t * config)
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

void expand32(salsa20_t * config)
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


/* *********************** HELPERS IMPLEMENTATION *********************** */


/* ************************ WRAPPER ************************ */
void salsa20_encrypt(uint8_t * data, size_t length, uint8_t * key, size_t keybits, uint8_t nonce[16])
{
    salsa20_t config;
    key_setup(&config, key, keybits, nonce);
    stream_crypt(&config, data, length);
}

void salsa20_decrypt(uint8_t * data, size_t length, uint8_t * key, size_t keybits, uint8_t nonce[16])
{
    salsa20_t config;
    key_setup(&config, key, keybits, nonce);
    stream_crypt(&config, data, length);
}


/* ************************ CONTOH PENGGUNAAN ************************ */
#include "../testutil.h"
#include <stdio.h>

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
    
    uint8_t nonce[16] = 
            { 0x13, 0x51, 0x00, 0x30, 0xD7, 0xA4, 0xC5, 0xAE, 0xCB, 0x55, 0xA7, 0x1C,
              0x25, 0x3F, 0x41, 0x4D };

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
    salsa20_encrypt(encbuffer, length, key, 256, nonce);
    printx("Encrypted:", encbuffer, length);

    memcpy(decbuffer, encbuffer, length);
    salsa20_decrypt(decbuffer, length, key, 256, nonce);
    printx("Decrypted:", decbuffer, length);

    printf("\nFinal: %s\n", decbuffer);

    return 0;
}


