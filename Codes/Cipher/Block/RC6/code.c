/*
    RC6 by Ron Rivest, Matt Robshaw, Ray Sidney, Yiqun Lisa Yin
    Archive of Reversing.ID
    Block Cipher

Compile:
    (msvc, from Codes/Cipher/Block/)
    $ cl /I. main.c mode.c RC6/code.c

    (gcc, from Codes/Cipher/Block/)
    $ gcc -I. -o test main.c mode.c RC6/code.c

    Modes of operation are in mode.c (not in this file).

Assemble:
    (gcc)
    $ gcc -m32 -S -masm=intel -o RC6/code.asm RC6/code.c

    (msvc)
    $ cl /c /FaRC6/code.asm RC6/code.c

Note:
    RC6-32/20/16 (128-bit block, 20 rounds, 128-bit key).
    Spec also defines 192- and 256-bit keys; this build uses 128-bit only.
*/
#include <stdint.h>
#include <string.h>

/* ************************* CONFIGURATION & SEED ************************* */
#define BLOCKSIZE       128
#define BLOCKSIZEB      16
#define KEYSIZE         128
#define KEYSIZEB        16
#define ROUNDS          20
#define T_SUBKEYS       (2 * ROUNDS + 4)

#ifdef _MSC_VER
    #pragma intrinsic(_lrotr,_lrotl)
    #define rotr(x,n)   _lrotr(x,n)
    #define rotl(x,n)   _lrotl(x,n)
#else
    #define rotr(x,n)   (((x) >> ((int)(n))) | ((x) << (32 - (int)(n))))
    #define rotl(x,n)   (((x) << ((int)(n))) | ((x) >> (32 - (int)(n))))
#endif

#define P32 0xb7e15163
#define Q32 0x9e3779b9

#define RC6_F(x)    ((uint32_t)((x) * (2u * (x) + 1u)))
#define RC6_QUAD(x) rotl(RC6_F(x), 5)

typedef struct
{
    uint32_t S[T_SUBKEYS];
} rc6_t;


/* ********************* INTERNAL FUNCTIONS PROTOTYPE ********************* */
void block_encrypt(rc6_t *config, uint8_t val[BLOCKSIZEB]);
void block_decrypt(rc6_t *config, uint8_t val[BLOCKSIZEB]);
void key_setup(rc6_t *config, const uint8_t *key);


/* ************************ CRYPTOGRAPHY ALGORITHM ************************ */
/*
    Enkripsi sebuah block dengan RC6.
    Pastikan konfigurasi telah dilakukan dengan memanggil key_setup()
*/
void
block_encrypt(rc6_t *config, uint8_t val[BLOCKSIZEB])
{
    uint32_t   A, B, C, D, t, u;
    uint32_t   i;
    uint32_t   w[4];
    uint32_t * S = config->S;

    memcpy(w, val, BLOCKSIZEB);
    A = w[0];
    B = w[1];
    C = w[2];
    D = w[3];

    B += S[0];
    D += S[1];

    for (i = 1; i <= ROUNDS; i++)
    {
        t = RC6_QUAD(B);
        u = RC6_QUAD(D);
        A = rotl(A ^ t, u & 31u) + S[2 * i];
        C = rotl(C ^ u, t & 31u) + S[2 * i + 1];
        t = A;
        A = B;
        B = C;
        C = D;
        D = t;
    }

    A += S[2 * ROUNDS + 2];
    C += S[2 * ROUNDS + 3];

    w[0] = A;
    w[1] = B;
    w[2] = C;
    w[3] = D;
    memcpy(val, w, BLOCKSIZEB);
}

/*
    Dekripsi sebuah block dengan RC6.
    Pastikan konfigurasi telah dilakukan dengan memanggil key_setup()
*/
void
block_decrypt(rc6_t *config, uint8_t val[BLOCKSIZEB])
{
    uint32_t   A, B, C, D, t, u;
    uint32_t   i;
    uint32_t   w[4];
    uint32_t * S = config->S;

    memcpy(w, val, BLOCKSIZEB);
    A = w[0];
    B = w[1];
    C = w[2];
    D = w[3];

    A -= S[2 * ROUNDS + 2];
    C -= S[2 * ROUNDS + 3];

    for (i = ROUNDS; i >= 1; i--)
    {
        t = D;
        D = C;
        C = B;
        B = A;
        A = t;

        t = RC6_QUAD(B);
        u = RC6_QUAD(D);
        C -= S[2 * i + 1];
        C = rotr(C, t & 31u) ^ u;
        A -= S[2 * i];
        A = rotr(A, u & 31u) ^ t;
    }

    B -= S[0];
    D -= S[1];

    w[0] = A;
    w[1] = B;
    w[2] = C;
    w[3] = D;
    memcpy(val, w, BLOCKSIZEB);
}


/* ******************* INTERNAL FUNCTIONS IMPLEMENTATION ******************* */
void
key_setup(rc6_t *config, const uint8_t *key)
{
    uint32_t   L[4];
    uint32_t   A, B;
    uint32_t   i, j, k, v;
    uint32_t   c = 4;
    uint32_t   t = T_SUBKEYS;
    uint32_t * S = config->S;

    memcpy(L, key, KEYSIZEB);

    S[0] = P32;
    for (i = 1; i < t; i++)
        S[i] = S[i - 1] + Q32;

    A = B = 0;
    i = j = 0;
    v = 3 * (t > c ? t : c);

    for (k = 0; k < v; k++)
    {
        A = S[i] = rotl(S[i] + A + B, 3);
        B = L[j] = rotl(L[j] + A + B, (A + B) & 31u);
        i = (i + 1) % t;
        j = (j + 1) % c;
    }
}


/* cipher port for mode.c */
#include "cipher_port.h"

const uint32_t CIPHER_BLOCK_BYTES = BLOCKSIZEB;
const uint32_t CIPHER_KEY_BYTES   = KEYSIZEB;

void
cipher_ctx_init(uint8_t *ctx, const uint8_t *key)
{
    key_setup((rc6_t *)ctx, key);
}

void
cipher_encrypt_block(uint8_t *ctx, uint8_t *block)
{
    block_encrypt((rc6_t *)ctx, block);
}

void
cipher_decrypt_block(uint8_t *ctx, uint8_t *block)
{
    block_decrypt((rc6_t *)ctx, block);
}
