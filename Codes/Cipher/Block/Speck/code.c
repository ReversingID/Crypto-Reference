/*
    Speck by Ray Beaulieu, Douglas Shors, Jason Smith, Stefan Treatman-Clark,
    Bryan Weeks, Louis Wingers (NSA)
    Archive of Reversing.ID
    Block Cipher

Compile:
    (msvc, from Codes/Cipher/Block/)
    $ cl /I. main.c mode.c Speck/code.c

    (gcc, from Codes/Cipher/Block/)
    $ gcc -I. -o test main.c mode.c Speck/code.c

    Modes of operation are in mode.c (not in this file).

Assemble:
    (gcc)
    $ gcc -m32 -S -masm=intel -o Speck/code.asm Speck/code.c

    (msvc)
    $ cl /c /FaSpeck/code.asm Speck/code.c
*/
#include <stdint.h>
#include <string.h>

/* ************************* CONFIGURATION & SEED ************************* */
#define BLOCKSIZE       128
#define BLOCKSIZEB      16
#define KEYSIZE         128
#define KEYSIZEB        16
#define ROUNDS          32

#ifdef _MSC_VER
    #include <stdlib.h>
    #pragma intrinsic(_rotr64, _rotl64)
    #define rotr64(x, n)   _rotr64(x, n)
    #define rotl64(x, n)   _rotl64(x, n)
#else
    #define rotr64(x, n)   (((x) >> ((int)(n))) | ((x) << (64 - (int)(n))))
    #define rotl64(x, n)   (((x) << ((int)(n))) | ((x) >> (64 - (int)(n))))
#endif


/* context and configuration */
typedef struct
{
    uint64_t rk[ROUNDS];
} speck_t;


/* ********************* INTERNAL FUNCTIONS PROTOTYPE ********************* */
void block_encrypt(speck_t *config, uint8_t *val);
void block_decrypt(speck_t *config, uint8_t *val);
void key_setup(speck_t *config, const uint8_t *secret);

static void round(uint64_t *x, uint64_t *y, uint64_t k);
static void round_inv(uint64_t *x, uint64_t *y, uint64_t k);


/* *************************** HELPER FUNCTIONS *************************** */
static void
round(uint64_t *x, uint64_t *y, uint64_t k)
{
    *x = rotr64(*x, 8);
    *x += *y;
    *x ^= k;
    *y = rotl64(*y, 3);
    *y ^= *x;
}

static void
round_inv(uint64_t *x, uint64_t *y, uint64_t k)
{
    *y ^= *x;
    *y = rotr64(*y, 3);
    *x ^= k;
    *x -= *y;
    *x = rotl64(*x, 8);
}


/* ************************ CRYPTOGRAPHY ALGORITHM ************************ */
/*
    Enkripsi sebuah block dengan Speck128/128.
    Pastikan konfigurasi telah dilakukan dengan memanggil key_setup()
*/
void
block_encrypt(speck_t *config, uint8_t *val)
{
    uint64_t x, y;
    size_t   idx;

    memcpy(&y, val, 8);
    memcpy(&x, val + 8, 8);

    for (idx = 0; idx < ROUNDS; idx++)
        round(&x, &y, config->rk[idx]);

    memcpy(val, &y, 8);
    memcpy(val + 8, &x, 8);
}

/*
    Dekripsi sebuah block dengan Speck128/128.
    Pastikan konfigurasi telah dilakukan dengan memanggil key_setup()
*/
void
block_decrypt(speck_t *config, uint8_t *val)
{
    uint64_t x, y;
    int      idx;

    memcpy(&y, val, 8);
    memcpy(&x, val + 8, 8);

    for (idx = ROUNDS - 1; idx >= 0; idx--)
        round_inv(&x, &y, config->rk[idx]);

    memcpy(val, &y, 8);
    memcpy(val + 8, &x, 8);
}


/* ******************* INTERNAL FUNCTIONS IMPLEMENTATION ******************* */
void
key_setup(speck_t *config, const uint8_t *secret)
{
    uint64_t a, b;
    size_t   idx;

    memcpy(&a, secret, 8);
    memcpy(&b, secret + 8, 8);

    for (idx = 0; idx < ROUNDS - 1; idx++)
    {
        config->rk[idx] = a;
        round(&b, &a, (uint64_t)idx);
    }

    config->rk[ROUNDS - 1] = a;
}


/* cipher port for mode.c */
#include "cipher_port.h"

const uint32_t CIPHER_BLOCK_BYTES = BLOCKSIZEB;
const uint32_t CIPHER_KEY_BYTES   = KEYSIZEB;

void
cipher_ctx_init(uint8_t *ctx, const uint8_t *key)
{
    key_setup((speck_t *)ctx, key);
}

void
cipher_encrypt_block(uint8_t *ctx, uint8_t *block)
{
    block_encrypt((speck_t *)ctx, block);
}

void
cipher_decrypt_block(uint8_t *ctx, uint8_t *block)
{
    block_decrypt((speck_t *)ctx, block);
}
