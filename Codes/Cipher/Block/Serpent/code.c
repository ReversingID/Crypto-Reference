/*
    Serpent by Ross Anderson, Eli Biham, Lars Knudsen
    Archive of Reversing.ID
    Block Cipher

Compile:
    (msvc, from Codes/Cipher/Block/)
    $ cl /I. main.c mode.c Serpent/code.c

    (gcc, from Codes/Cipher/Block/)
    $ gcc -I. -o test main.c mode.c Serpent/code.c

    Modes of operation are in mode.c (not in this file).

Assemble:
    (gcc)
    $ gcc -m32 -S -masm=intel -o Serpent/code.asm Serpent/code.c

    (msvc)
    $ cl /c /FaSerpent/code.asm Serpent/code.c

Note:
    Serpent-128 (128-bit block, 32 rounds, 128-bit key).
    Spec also defines 192- and 256-bit keys; this build uses 128-bit only.
*/
#include <stdint.h>
#include <string.h>

/* ************************* CONFIGURATION & SEED ************************* */
#define BLOCKSIZE       128
#define BLOCKSIZEB      16
#define KEYSIZE         128
#define KEYSIZEB        16
#define ROUNDS          32
#define SUBKEYS         (ROUNDS + 1)

/* Fractional part of the golden ratio, used in key expansion */
#define PHI             0x9e3779b9u

#ifdef _MSC_VER
    #pragma intrinsic(_lrotr,_lrotl)
    #define rotr(x,n)   _lrotr(x,n)
    #define rotl(x,n)   _lrotl(x,n)
#else
    #define rotr(x,n)   (((x) >> ((int)(n))) | ((x) << (32 - (int)(n))))
    #define rotl(x,n)   (((x) << ((int)(n))) | ((x) >> (32 - (int)(n))))
#endif


/*
    8 S-boxes (4-bit input -> 4-bit output).

    In each encryption round, the active S-box is S_{r mod 8}.
    S-boxes are applied in bitsliced fashion: for every bit position j (0..31),
    the 4-bit nibble (b[0][j], b[1][j], b[2][j], b[3][j]) is substituted.
*/
static const uint8_t SBOX[8][16] = {
    { 3, 8,15, 1,10, 6, 5,11,14,13, 4, 2, 7, 0, 9,12},  /* S0 */
    {15,12, 2, 7, 9, 0, 5,10, 1,11,14, 8, 6,13, 3, 4},  /* S1 */
    { 8, 6, 7, 9, 3,12,10,15,13, 1,14, 4, 0,11, 5, 2},  /* S2 */
    { 0,15,11, 8,12, 9, 6, 3,13, 1, 2, 4,10, 7, 5,14},  /* S3 */
    { 1,15, 8, 3,12, 0,11, 6, 2, 5, 4,10, 9,14, 7,13},  /* S4 */
    {15, 5, 2,11, 4,10, 9,12, 0, 3,14, 8,13, 6, 7, 1},  /* S5 */
    { 7, 2,12, 5, 8, 4, 6,11,14, 9, 1,15,13, 3,10, 0},  /* S6 */
    { 1,13,15, 0,14, 8, 2,11, 7, 4,12,10, 9, 3, 5, 6}   /* S7 */
};

static const uint8_t SBOX_INV[8][16] = {
    {13, 3,11, 0,10, 6, 5,12, 1,14, 4, 7,15, 9, 8, 2},  /* S0_inv */
    { 5, 8, 2,14,15, 6,12, 3,11, 4, 7, 9, 1,13,10, 0},  /* S1_inv */
    {12, 9,15, 4,11,14, 1, 2, 0, 3, 6,13, 5, 8,10, 7},  /* S2_inv */
    { 0, 9,10, 7,11,14, 6,13, 3, 5,12, 2, 4, 8,15, 1},  /* S3_inv */
    { 5, 0, 8, 3,10, 9, 7,14, 2,12,11, 6, 4,15,13, 1},  /* S4_inv */
    { 8,15, 2, 9, 4, 1,13,14,11, 6, 5, 3, 7,12,10, 0},  /* S5_inv */
    {15,10, 1,13, 5, 3, 6, 0, 4, 9,14, 7, 2,12, 8,11},  /* S6_inv */
    { 3, 0, 6,13, 9,14,15, 8, 5,12,11, 7,10, 1, 4, 2}   /* S7_inv */
};

typedef struct
{
    uint32_t K[SUBKEYS][4];
} serpent_t;


/* ********************* INTERNAL FUNCTIONS PROTOTYPE ********************* */
void block_encrypt(serpent_t *config, uint8_t val[BLOCKSIZEB]);
void block_decrypt(serpent_t *config, uint8_t val[BLOCKSIZEB]);
void key_setup(serpent_t *config, const uint8_t *key);

static void sbox_apply(uint32_t b[4], int s);
static void sbox_inv_apply(uint32_t b[4], int s);
static void linear_transform(uint32_t b[4]);
static void linear_transform_inv(uint32_t b[4]);


/* ************************ CRYPTOGRAPHY ALGORITHM ************************ */
/*
    Enkripsi sebuah block dengan Serpent.
    Pastikan konfigurasi telah dilakukan dengan memanggil key_setup()
*/
void
block_encrypt(serpent_t *config, uint8_t val[BLOCKSIZEB])
{
    uint32_t b[4];
    int r;

    b[0] = (uint32_t)val[ 0]        | ((uint32_t)val[ 1] <<  8)
         | ((uint32_t)val[ 2] << 16) | ((uint32_t)val[ 3] << 24);
    b[1] = (uint32_t)val[ 4]        | ((uint32_t)val[ 5] <<  8)
         | ((uint32_t)val[ 6] << 16) | ((uint32_t)val[ 7] << 24);
    b[2] = (uint32_t)val[ 8]        | ((uint32_t)val[ 9] <<  8)
         | ((uint32_t)val[10] << 16) | ((uint32_t)val[11] << 24);
    b[3] = (uint32_t)val[12]        | ((uint32_t)val[13] <<  8)
         | ((uint32_t)val[14] << 16) | ((uint32_t)val[15] << 24);

    for (r = 0; r < ROUNDS - 1; r++)
    {
        b[0] ^= config->K[r][0];
        b[1] ^= config->K[r][1];
        b[2] ^= config->K[r][2];
        b[3] ^= config->K[r][3];
        sbox_apply(b, r & 7);
        linear_transform(b);
    }

    /* Final round: S7, then key whitening instead of linear transform */
    b[0] ^= config->K[31][0];
    b[1] ^= config->K[31][1];
    b[2] ^= config->K[31][2];
    b[3] ^= config->K[31][3];
    sbox_apply(b, 7);
    b[0] ^= config->K[32][0];
    b[1] ^= config->K[32][1];
    b[2] ^= config->K[32][2];
    b[3] ^= config->K[32][3];

    val[ 0] = (uint8_t)(b[0]      ); val[ 1] = (uint8_t)(b[0] >>  8);
    val[ 2] = (uint8_t)(b[0] >> 16); val[ 3] = (uint8_t)(b[0] >> 24);
    val[ 4] = (uint8_t)(b[1]      ); val[ 5] = (uint8_t)(b[1] >>  8);
    val[ 6] = (uint8_t)(b[1] >> 16); val[ 7] = (uint8_t)(b[1] >> 24);
    val[ 8] = (uint8_t)(b[2]      ); val[ 9] = (uint8_t)(b[2] >>  8);
    val[10] = (uint8_t)(b[2] >> 16); val[11] = (uint8_t)(b[2] >> 24);
    val[12] = (uint8_t)(b[3]      ); val[13] = (uint8_t)(b[3] >>  8);
    val[14] = (uint8_t)(b[3] >> 16); val[15] = (uint8_t)(b[3] >> 24);
}

/*
    Dekripsi sebuah block dengan Serpent.
    Pastikan konfigurasi telah dilakukan dengan memanggil key_setup()
*/
void
block_decrypt(serpent_t *config, uint8_t val[BLOCKSIZEB])
{
    uint32_t b[4];
    int r;

    b[0] = (uint32_t)val[ 0]        | ((uint32_t)val[ 1] <<  8)
         | ((uint32_t)val[ 2] << 16) | ((uint32_t)val[ 3] << 24);
    b[1] = (uint32_t)val[ 4]        | ((uint32_t)val[ 5] <<  8)
         | ((uint32_t)val[ 6] << 16) | ((uint32_t)val[ 7] << 24);
    b[2] = (uint32_t)val[ 8]        | ((uint32_t)val[ 9] <<  8)
         | ((uint32_t)val[10] << 16) | ((uint32_t)val[11] << 24);
    b[3] = (uint32_t)val[12]        | ((uint32_t)val[13] <<  8)
         | ((uint32_t)val[14] << 16) | ((uint32_t)val[15] << 24);

    /* Undo final round */
    b[0] ^= config->K[32][0];
    b[1] ^= config->K[32][1];
    b[2] ^= config->K[32][2];
    b[3] ^= config->K[32][3];
    sbox_inv_apply(b, 7);
    b[0] ^= config->K[31][0];
    b[1] ^= config->K[31][1];
    b[2] ^= config->K[31][2];
    b[3] ^= config->K[31][3];

    for (r = ROUNDS - 2; r >= 0; r--)
    {
        linear_transform_inv(b);
        sbox_inv_apply(b, r & 7);
        b[0] ^= config->K[r][0];
        b[1] ^= config->K[r][1];
        b[2] ^= config->K[r][2];
        b[3] ^= config->K[r][3];
    }

    val[ 0] = (uint8_t)(b[0]      ); val[ 1] = (uint8_t)(b[0] >>  8);
    val[ 2] = (uint8_t)(b[0] >> 16); val[ 3] = (uint8_t)(b[0] >> 24);
    val[ 4] = (uint8_t)(b[1]      ); val[ 5] = (uint8_t)(b[1] >>  8);
    val[ 6] = (uint8_t)(b[1] >> 16); val[ 7] = (uint8_t)(b[1] >> 24);
    val[ 8] = (uint8_t)(b[2]      ); val[ 9] = (uint8_t)(b[2] >>  8);
    val[10] = (uint8_t)(b[2] >> 16); val[11] = (uint8_t)(b[2] >> 24);
    val[12] = (uint8_t)(b[3]      ); val[13] = (uint8_t)(b[3] >>  8);
    val[14] = (uint8_t)(b[3] >> 16); val[15] = (uint8_t)(b[3] >> 24);
}

/*
    Ekspansi kunci 128-bit menjadi 33 subkey 128-bit.

    Algoritma:
    1. Padding kunci ke 256-bit dengan append bit '1' lalu '0'
    2. Generate 132 prekey menggunakan linear recurrence dengan konstanta PHI
    3. Setiap 4 prekey berturut-turut diproses oleh S-box untuk menghasilkan subkey
*/
void
key_setup(serpent_t *config, const uint8_t *key)
{
    uint32_t w[140];   /* w[0..7]: padded key words; w[8..139]: prekeys */
    int i;

    memset(w, 0, sizeof(w));

    /* Load 128-bit key as 4 little-endian 32-bit words */
    for (i = 0; i < 4; i++)
        w[i] = (uint32_t)key[4*i    ]        | ((uint32_t)key[4*i + 1] <<  8)
             | ((uint32_t)key[4*i + 2] << 16) | ((uint32_t)key[4*i + 3] << 24);

    /* Pad to 256 bits: append '1' bit at position 128, leaving w[5..7] as zero */
    w[4] = 0x00000001u;

    /* Linear recurrence: w[i+8] = rotl(w[i] ^ w[i+3] ^ w[i+5] ^ w[i+7] ^ PHI ^ i, 11) */
    for (i = 0; i < 132; i++)
    {
        uint32_t t = w[i] ^ w[i+3] ^ w[i+5] ^ w[i+7] ^ PHI ^ (uint32_t)i;
        w[i+8] = rotl(t, 11);
    }

    /* Apply S-box (35-i) mod 8 to prekeys w[4i+8..4i+11] to produce subkey K[i] */
    for (i = 0; i <= 32; i++)
    {
        uint32_t b[4];
        b[0] = w[4*i + 8];  b[1] = w[4*i + 9];
        b[2] = w[4*i + 10]; b[3] = w[4*i + 11];
        sbox_apply(b, (35 - i) & 7);
        config->K[i][0] = b[0]; config->K[i][1] = b[1];
        config->K[i][2] = b[2]; config->K[i][3] = b[3];
    }
}


/* ******************* INTERNAL FUNCTIONS IMPLEMENTATION ******************* */
/*
    Bitsliced S-box substitution.
    The 4 words b[0..3] represent 32 parallel 4-bit nibbles where bit j of b[k]
    is the k-th bit of nibble j.  Each nibble is substituted by SBOX[s].
*/
static void
sbox_apply(uint32_t b[4], int s)
{
    uint32_t C0 = 0, C1 = 0, C2 = 0, C3 = 0;
    uint32_t B0 = b[0], B1 = b[1], B2 = b[2], B3 = b[3];
    int j;

    for (j = 0; j < 32; j++)
    {
        uint8_t nibble = (uint8_t)(((B0 >> j) & 1)       |
                                   (((B1 >> j) & 1) << 1) |
                                   (((B2 >> j) & 1) << 2) |
                                   (((B3 >> j) & 1) << 3));
        uint8_t out = SBOX[s][nibble];
        C0 |= (uint32_t)((out     ) & 1u) << j;
        C1 |= (uint32_t)((out >> 1) & 1u) << j;
        C2 |= (uint32_t)((out >> 2) & 1u) << j;
        C3 |= (uint32_t)((out >> 3) & 1u) << j;
    }

    b[0] = C0; b[1] = C1; b[2] = C2; b[3] = C3;
}

static void
sbox_inv_apply(uint32_t b[4], int s)
{
    uint32_t C0 = 0, C1 = 0, C2 = 0, C3 = 0;
    uint32_t B0 = b[0], B1 = b[1], B2 = b[2], B3 = b[3];
    int j;

    for (j = 0; j < 32; j++)
    {
        uint8_t nibble = (uint8_t)(((B0 >> j) & 1)       |
                                   (((B1 >> j) & 1) << 1) |
                                   (((B2 >> j) & 1) << 2) |
                                   (((B3 >> j) & 1) << 3));
        uint8_t out = SBOX_INV[s][nibble];
        C0 |= (uint32_t)((out     ) & 1u) << j;
        C1 |= (uint32_t)((out >> 1) & 1u) << j;
        C2 |= (uint32_t)((out >> 2) & 1u) << j;
        C3 |= (uint32_t)((out >> 3) & 1u) << j;
    }

    b[0] = C0; b[1] = C1; b[2] = C2; b[3] = C3;
}

static void
linear_transform(uint32_t b[4])
{
    uint32_t X0 = b[0], X1 = b[1], X2 = b[2], X3 = b[3];

    X0 = rotl(X0, 13);
    X2 = rotl(X2,  3);
    X1 = X1 ^ X0 ^ X2;
    X3 = X3 ^ X2 ^ (X0 << 3);
    X1 = rotl(X1,  1);
    X3 = rotl(X3,  7);
    X0 = X0 ^ X1 ^ X3;
    X2 = X2 ^ X3 ^ (X1 << 7);
    X0 = rotl(X0,  5);
    X2 = rotl(X2, 22);

    b[0] = X0; b[1] = X1; b[2] = X2; b[3] = X3;
}

static void
linear_transform_inv(uint32_t b[4])
{
    uint32_t X0 = b[0], X1 = b[1], X2 = b[2], X3 = b[3];

    X2 = rotr(X2, 22);
    X0 = rotr(X0,  5);
    X2 = X2 ^ X3 ^ (X1 << 7);
    X0 = X0 ^ X1 ^ X3;
    X3 = rotr(X3,  7);
    X1 = rotr(X1,  1);
    X3 = X3 ^ X2 ^ (X0 << 3);
    X1 = X1 ^ X0 ^ X2;
    X2 = rotr(X2,  3);
    X0 = rotr(X0, 13);

    b[0] = X0; b[1] = X1; b[2] = X2; b[3] = X3;
}


/* cipher port for mode.c */
#include "cipher_port.h"

const uint32_t CIPHER_BLOCK_BYTES = BLOCKSIZEB;
const uint32_t CIPHER_KEY_BYTES   = KEYSIZEB;

void
cipher_ctx_init(uint8_t *ctx, const uint8_t *key)
{
    key_setup((serpent_t *)ctx, key);
}

void
cipher_encrypt_block(uint8_t *ctx, uint8_t *block)
{
    block_encrypt((serpent_t *)ctx, block);
}

void
cipher_decrypt_block(uint8_t *ctx, uint8_t *block)
{
    block_decrypt((serpent_t *)ctx, block);
}
