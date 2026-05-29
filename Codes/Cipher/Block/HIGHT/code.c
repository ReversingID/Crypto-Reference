/*
    HIGHT by Deukjo Hong, Jung-Keun Lee, Dong-Chan Kim, Daesung Kwon,
    Kwon Ho Ryu, Dong-Geon Lee
    Archive of Reversing.ID
    Block Cipher

Compile:
    (msvc, from Codes/Cipher/Block/)
    $ cl /I. main.c mode.c HIGHT/code.c

    (gcc, from Codes/Cipher/Block/)
    $ gcc -I. -o test main.c mode.c HIGHT/code.c

    Modes of operation are in mode.c (not in this file).

Assemble:
    (gcc)
    $ gcc -m32 -S -masm=intel -o HIGHT/code.asm HIGHT/code.c

    (msvc)
    $ cl /c /FaHIGHT/code.asm HIGHT/code.c

Note:
    HIGHT-128 (64-bit block, 32 rounds, 128-bit key).
    ISO/IEC 18033-3 lightweight block cipher.
*/
#include <stdint.h>
#include <string.h>

/* ************************* CONFIGURATION & SEED ************************* */
#define BLOCKSIZE       64
#define BLOCKSIZEB      8
#define KEYSIZE         128
#define KEYSIZEB        16
#define ROUNDS          32

static const uint8_t DELTA[128] = {
    0x5A, 0x6D, 0x36, 0x1B, 0x0D, 0x06, 0x03, 0x41,
    0x60, 0x30, 0x18, 0x4C, 0x66, 0x33, 0x59, 0x2C,
    0x56, 0x2B, 0x15, 0x4A, 0x65, 0x72, 0x39, 0x1C,
    0x4E, 0x67, 0x73, 0x79, 0x3C, 0x5E, 0x6F, 0x37,
    0x5B, 0x2D, 0x16, 0x0B, 0x05, 0x42, 0x21, 0x50,
    0x28, 0x54, 0x2A, 0x55, 0x6A, 0x75, 0x7A, 0x7D,
    0x3E, 0x5F, 0x2F, 0x17, 0x4B, 0x25, 0x52, 0x29,
    0x14, 0x0A, 0x45, 0x62, 0x31, 0x58, 0x6C, 0x76,
    0x3B, 0x1D, 0x0E, 0x47, 0x63, 0x71, 0x78, 0x7C,
    0x7E, 0x7F, 0x3F, 0x1F, 0x0F, 0x07, 0x43, 0x61,
    0x70, 0x38, 0x5C, 0x6E, 0x77, 0x7B, 0x3D, 0x1E,
    0x4F, 0x27, 0x53, 0x69, 0x34, 0x1A, 0x4D, 0x26,
    0x13, 0x49, 0x24, 0x12, 0x09, 0x04, 0x02, 0x01,
    0x40, 0x20, 0x10, 0x08, 0x44, 0x22, 0x11, 0x48,
    0x64, 0x32, 0x19, 0x0C, 0x46, 0x23, 0x51, 0x68,
    0x74, 0x3A, 0x5D, 0x2E, 0x57, 0x6B, 0x35, 0x5A
};

typedef struct
{
    uint8_t wk[8];
    uint8_t sk[128];
} hight_t;


/* ********************* INTERNAL FUNCTIONS PROTOTYPE ********************* */
void block_encrypt(hight_t *config, uint8_t val[BLOCKSIZEB]);
void block_decrypt(hight_t *config, uint8_t val[BLOCKSIZEB]);
void key_setup(hight_t *config, const uint8_t *secret);

static uint8_t rotl8(uint8_t x, unsigned n);
static uint8_t f0(uint8_t x);
static uint8_t f1(uint8_t x);
static void    hight_enc_round(hight_t *config, uint8_t x[8], unsigned k,
                               unsigned i0, unsigned i1, unsigned i2, unsigned i3,
                               unsigned i4, unsigned i5, unsigned i6, unsigned i7);
static void    hight_dec_round(hight_t *config, uint8_t x[8], unsigned k,
                               unsigned i0, unsigned i1, unsigned i2, unsigned i3,
                               unsigned i4, unsigned i5, unsigned i6, unsigned i7);
static void    reverse_block(uint8_t val[BLOCKSIZEB]);


/* *************************** HELPER FUNCTIONS *************************** */
static uint8_t
rotl8(uint8_t x, unsigned n)
{
    n &= 7;
    return (uint8_t)((x << n) | (x >> (8 - n)));
}

static uint8_t
f0(uint8_t x)
{
    return (uint8_t)(rotl8(x, 1) ^ rotl8(x, 2) ^ rotl8(x, 7));
}

static uint8_t
f1(uint8_t x)
{
    return (uint8_t)(rotl8(x, 3) ^ rotl8(x, 4) ^ rotl8(x, 6));
}

static void
reverse_block(uint8_t val[BLOCKSIZEB])
{
    uint8_t t;
    unsigned i;

    for (i = 0; i < 4; i++)
    {
        t = val[i];
        val[i] = val[7 - i];
        val[7 - i] = t;
    }
}

static void
hight_enc_round(hight_t *config, uint8_t x[8], unsigned k,
                unsigned i0, unsigned i1, unsigned i2, unsigned i3,
                unsigned i4, unsigned i5, unsigned i6, unsigned i7)
{
    const uint8_t *sk = config->sk + (4 * k - 8);

    x[i0] = (uint8_t)(x[i0] ^ (f0(x[i1]) + sk[3]));
    x[i2] = (uint8_t)(x[i2] + (f1(x[i3]) ^ sk[2]));
    x[i4] = (uint8_t)(x[i4] ^ (f0(x[i5]) + sk[1]));
    x[i6] = (uint8_t)(x[i6] + (f1(x[i7]) ^ sk[0]));
}

static void
hight_dec_round(hight_t *config, uint8_t x[8], unsigned k,
                unsigned i0, unsigned i1, unsigned i2, unsigned i3,
                unsigned i4, unsigned i5, unsigned i6, unsigned i7)
{
    const uint8_t *sk = config->sk + (4 * k - 8);

    x[i1] = (uint8_t)(x[i1] - (f1(x[i2]) ^ sk[2]));
    x[i3] = (uint8_t)(x[i3] ^ (f0(x[i4]) + sk[1]));
    x[i5] = (uint8_t)(x[i5] - (f1(x[i6]) ^ sk[0]));
    x[i7] = (uint8_t)(x[i7] ^ (f0(x[i0]) + sk[3]));
}


/* ************************ CRYPTOGRAPHY ALGORITHM ************************ */
/*
    Enkripsi sebuah block dengan HIGHT.
    Pastikan konfigurasi telah dilakukan dengan memanggil key_setup()
*/
void
block_encrypt(hight_t *config, uint8_t val[BLOCKSIZEB])
{
    uint8_t x[8];

    /* P = P7 || P6 || ... || P0 */
    reverse_block(val);

    x[1] = val[1];
    x[3] = val[3];
    x[5] = val[5];
    x[7] = val[7];
    x[0] = (uint8_t)(val[0] + config->wk[0]);
    x[2] = (uint8_t)(val[2] ^ config->wk[1]);
    x[4] = (uint8_t)(val[4] + config->wk[2]);
    x[6] = (uint8_t)(val[6] ^ config->wk[3]);

    hight_enc_round(config, x,  2, 7, 6, 5, 4, 3, 2, 1, 0);
    hight_enc_round(config, x,  3, 6, 5, 4, 3, 2, 1, 0, 7);
    hight_enc_round(config, x,  4, 5, 4, 3, 2, 1, 0, 7, 6);
    hight_enc_round(config, x,  5, 4, 3, 2, 1, 0, 7, 6, 5);
    hight_enc_round(config, x,  6, 3, 2, 1, 0, 7, 6, 5, 4);
    hight_enc_round(config, x,  7, 2, 1, 0, 7, 6, 5, 4, 3);
    hight_enc_round(config, x,  8, 1, 0, 7, 6, 5, 4, 3, 2);
    hight_enc_round(config, x,  9, 0, 7, 6, 5, 4, 3, 2, 1);
    hight_enc_round(config, x, 10, 7, 6, 5, 4, 3, 2, 1, 0);
    hight_enc_round(config, x, 11, 6, 5, 4, 3, 2, 1, 0, 7);
    hight_enc_round(config, x, 12, 5, 4, 3, 2, 1, 0, 7, 6);
    hight_enc_round(config, x, 13, 4, 3, 2, 1, 0, 7, 6, 5);
    hight_enc_round(config, x, 14, 3, 2, 1, 0, 7, 6, 5, 4);
    hight_enc_round(config, x, 15, 2, 1, 0, 7, 6, 5, 4, 3);
    hight_enc_round(config, x, 16, 1, 0, 7, 6, 5, 4, 3, 2);
    hight_enc_round(config, x, 17, 0, 7, 6, 5, 4, 3, 2, 1);
    hight_enc_round(config, x, 18, 7, 6, 5, 4, 3, 2, 1, 0);
    hight_enc_round(config, x, 19, 6, 5, 4, 3, 2, 1, 0, 7);
    hight_enc_round(config, x, 20, 5, 4, 3, 2, 1, 0, 7, 6);
    hight_enc_round(config, x, 21, 4, 3, 2, 1, 0, 7, 6, 5);
    hight_enc_round(config, x, 22, 3, 2, 1, 0, 7, 6, 5, 4);
    hight_enc_round(config, x, 23, 2, 1, 0, 7, 6, 5, 4, 3);
    hight_enc_round(config, x, 24, 1, 0, 7, 6, 5, 4, 3, 2);
    hight_enc_round(config, x, 25, 0, 7, 6, 5, 4, 3, 2, 1);
    hight_enc_round(config, x, 26, 7, 6, 5, 4, 3, 2, 1, 0);
    hight_enc_round(config, x, 27, 6, 5, 4, 3, 2, 1, 0, 7);
    hight_enc_round(config, x, 28, 5, 4, 3, 2, 1, 0, 7, 6);
    hight_enc_round(config, x, 29, 4, 3, 2, 1, 0, 7, 6, 5);
    hight_enc_round(config, x, 30, 3, 2, 1, 0, 7, 6, 5, 4);
    hight_enc_round(config, x, 31, 2, 1, 0, 7, 6, 5, 4, 3);
    hight_enc_round(config, x, 32, 1, 0, 7, 6, 5, 4, 3, 2);
    hight_enc_round(config, x, 33, 0, 7, 6, 5, 4, 3, 2, 1);

    val[1] = x[2];
    val[3] = x[4];
    val[5] = x[6];
    val[7] = x[0];
    val[0] = (uint8_t)(x[1] + config->wk[4]);
    val[2] = (uint8_t)(x[3] ^ config->wk[5]);
    val[4] = (uint8_t)(x[5] + config->wk[6]);
    val[6] = (uint8_t)(x[7] ^ config->wk[7]);

    /* C = C7 || C6 || ... || C0 */
    reverse_block(val);
}

/*
    Dekripsi sebuah block dengan HIGHT.
    Pastikan konfigurasi telah dilakukan dengan memanggil key_setup()
*/
void
block_decrypt(hight_t *config, uint8_t val[BLOCKSIZEB])
{
    uint8_t x[8];

    reverse_block(val);

    x[2] = val[1];
    x[4] = val[3];
    x[6] = val[5];
    x[0] = val[7];
    x[1] = (uint8_t)(val[0] - config->wk[4]);
    x[3] = (uint8_t)(val[2] ^ config->wk[5]);
    x[5] = (uint8_t)(val[4] - config->wk[6]);
    x[7] = (uint8_t)(val[6] ^ config->wk[7]);

    hight_dec_round(config, x, 33, 7, 6, 5, 4, 3, 2, 1, 0);
    hight_dec_round(config, x, 32, 0, 7, 6, 5, 4, 3, 2, 1);
    hight_dec_round(config, x, 31, 1, 0, 7, 6, 5, 4, 3, 2);
    hight_dec_round(config, x, 30, 2, 1, 0, 7, 6, 5, 4, 3);
    hight_dec_round(config, x, 29, 3, 2, 1, 0, 7, 6, 5, 4);
    hight_dec_round(config, x, 28, 4, 3, 2, 1, 0, 7, 6, 5);
    hight_dec_round(config, x, 27, 5, 4, 3, 2, 1, 0, 7, 6);
    hight_dec_round(config, x, 26, 6, 5, 4, 3, 2, 1, 0, 7);
    hight_dec_round(config, x, 25, 7, 6, 5, 4, 3, 2, 1, 0);
    hight_dec_round(config, x, 24, 0, 7, 6, 5, 4, 3, 2, 1);
    hight_dec_round(config, x, 23, 1, 0, 7, 6, 5, 4, 3, 2);
    hight_dec_round(config, x, 22, 2, 1, 0, 7, 6, 5, 4, 3);
    hight_dec_round(config, x, 21, 3, 2, 1, 0, 7, 6, 5, 4);
    hight_dec_round(config, x, 20, 4, 3, 2, 1, 0, 7, 6, 5);
    hight_dec_round(config, x, 19, 5, 4, 3, 2, 1, 0, 7, 6);
    hight_dec_round(config, x, 18, 6, 5, 4, 3, 2, 1, 0, 7);
    hight_dec_round(config, x, 17, 7, 6, 5, 4, 3, 2, 1, 0);
    hight_dec_round(config, x, 16, 0, 7, 6, 5, 4, 3, 2, 1);
    hight_dec_round(config, x, 15, 1, 0, 7, 6, 5, 4, 3, 2);
    hight_dec_round(config, x, 14, 2, 1, 0, 7, 6, 5, 4, 3);
    hight_dec_round(config, x, 13, 3, 2, 1, 0, 7, 6, 5, 4);
    hight_dec_round(config, x, 12, 4, 3, 2, 1, 0, 7, 6, 5);
    hight_dec_round(config, x, 11, 5, 4, 3, 2, 1, 0, 7, 6);
    hight_dec_round(config, x, 10, 6, 5, 4, 3, 2, 1, 0, 7);
    hight_dec_round(config, x,  9, 7, 6, 5, 4, 3, 2, 1, 0);
    hight_dec_round(config, x,  8, 0, 7, 6, 5, 4, 3, 2, 1);
    hight_dec_round(config, x,  7, 1, 0, 7, 6, 5, 4, 3, 2);
    hight_dec_round(config, x,  6, 2, 1, 0, 7, 6, 5, 4, 3);
    hight_dec_round(config, x,  5, 3, 2, 1, 0, 7, 6, 5, 4);
    hight_dec_round(config, x,  4, 4, 3, 2, 1, 0, 7, 6, 5);
    hight_dec_round(config, x,  3, 5, 4, 3, 2, 1, 0, 7, 6);
    hight_dec_round(config, x,  2, 6, 5, 4, 3, 2, 1, 0, 7);

    val[1] = x[1];
    val[3] = x[3];
    val[5] = x[5];
    val[7] = x[7];
    val[0] = (uint8_t)(x[0] - config->wk[0]);
    val[2] = (uint8_t)(x[2] ^ config->wk[1]);
    val[4] = (uint8_t)(x[4] - config->wk[2]);
    val[6] = (uint8_t)(x[6] ^ config->wk[3]);

    reverse_block(val);
}


/* **************** INTERNAL FUNCTIONS IMPLEMENTATION ******************* */
static uint8_t
key_byte(const uint8_t *secret, unsigned kn)
{
    /* K = K15 || K14 || ... || K0; secret[0] is K15 */
    return secret[15 - (kn & 15)];
}

void
key_setup(hight_t *config, const uint8_t *secret)
{
    unsigned i;
    unsigned j;

    for (i = 0; i < 4; i++)
        config->wk[i] = key_byte(secret, i + 12);

    for (i = 0; i < 4; i++)
        config->wk[i + 4] = key_byte(secret, i);

    for (i = 0; i < 8; i++)
    {
        for (j = 0; j < 8; j++)
            config->sk[16 * i + j] =
                (uint8_t)(key_byte(secret, (j - i) & 7) + DELTA[16 * i + j]);

        for (j = 0; j < 8; j++)
            config->sk[16 * i + j + 8] =
                (uint8_t)(key_byte(secret, ((j - i) & 7) + 8) + DELTA[16 * i + j + 8]);
    }
}


/* cipher port for mode.c */
#include "cipher_port.h"

const uint32_t CIPHER_BLOCK_BYTES = BLOCKSIZEB;
const uint32_t CIPHER_KEY_BYTES   = KEYSIZEB;

void
cipher_ctx_init(uint8_t *ctx, const uint8_t *key)
{
    key_setup((hight_t *)ctx, key);
}

void
cipher_encrypt_block(uint8_t *ctx, uint8_t *block)
{
    block_encrypt((hight_t *)ctx, block);
}

void
cipher_decrypt_block(uint8_t *ctx, uint8_t *block)
{
    block_decrypt((hight_t *)ctx, block);
}
