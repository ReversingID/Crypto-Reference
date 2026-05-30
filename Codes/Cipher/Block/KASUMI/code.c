/*
    KASUMI by Mitsubishi Electric (3GPP)
    Archive of Reversing.ID
    Block Cipher

Compile:
    (msvc, from Codes/Cipher/Block/)
    $ cl /I. main.c mode.c KASUMI/code.c

    (gcc, from Codes/Cipher/Block/)
    $ gcc -I. -o test main.c mode.c KASUMI/code.c

    Modes of operation are in mode.c (not in this file).

Assemble:
    (gcc)
    $ gcc -m32 -S -masm=intel -o KASUMI/code.asm KASUMI/code.c

    (msvc)
    $ cl /c /FaKASUMI/code.asm KASUMI/code.c

Note:
    KASUMI (64-bit block, 8 rounds, 128-bit key). 3GPP TS 35.202.
    MISTY1 derivative; core of UMTS/GSM confidentiality (f8) and integrity (f9).
*/
#include <stdint.h>
#include <string.h>
#include "../byteorder.h"

/* ************************* CONFIGURATION & SEED ************************* */
#define BLOCKSIZE       64
#define BLOCKSIZEB      8
#define KEYSIZE         128
#define KEYSIZEB        16
#define ROUNDS          8

static const uint16_t KASUMI_C[8] = {
    0x0123, 0x4567, 0x89AB, 0xCDEF,
    0xFEDC, 0xBA98, 0x7654, 0x3210,
};

static const uint16_t S7[128] = {
    54,  50,  62,  56,  22,  34,  94,  96,  38,   6,  63,  93,   2,  18, 123,  33,
    55, 113,  39, 114,  21,  67,  65,  12,  47,  73,  46,  27,  25, 111, 124,  81,
    53,   9, 121,  79,  52,  60,  58,  48, 101, 127,  40, 120, 104,  70,  71,  43,
    20, 122,  72,  61,  23, 109,  13, 100,  77,   1,  16,   7,  82,  10, 105,  98,
   117, 116,  76,  11,  89, 106,   0, 125, 118,  99,  86,  69,  30,  57, 126,  87,
   112,  51,  17,   5,  95,  14,  90,  84,  91,   8,  35, 103,  32,  97,  28,  66,
   102,  31,  26,  45,  75,   4,  85,  92,  37,  74,  80,  49,  68,  29, 115,  44,
    64, 107, 108,  24, 110,  83,  36,  78,  42,  19,  15,  41,  88, 119,  59,   3,
};

static const uint16_t S9[512] = {
   167, 239, 161, 379, 391, 334,   9, 338,  38, 226,  48, 358, 452, 385,  90, 397,
   183, 253, 147, 331, 415, 340,  51, 362, 306, 500, 262,  82, 216, 159, 356, 177,
   175, 241, 489,  37, 206,  17,   0, 333,  44, 254, 378,  58, 143, 220,  81, 400,
    95,   3, 315, 245,  54, 235, 218, 405, 472, 264, 172, 494, 371, 290, 399,  76,
   165, 197, 395, 121, 257, 480, 423, 212, 240,  28, 462, 176, 406, 507, 288, 223,
   501, 407, 249, 265,  89, 186, 221, 428, 164,  74, 440, 196, 458, 421, 350, 163,
   232, 158, 134, 354,  13, 250, 491, 142, 191,  69, 193, 425, 152, 227, 366, 135,
   344, 300, 276, 242, 437, 320, 113, 278,  11, 243,  87, 317,  36,  93, 496,  27,
   487, 446, 482,  41,  68, 156, 457, 131, 326, 403, 339,  20,  39, 115, 442, 124,
   475, 384, 508,  53, 112, 170, 479, 151, 126, 169,  73, 268, 279, 321, 168, 364,
   363, 292,  46, 499, 393, 327, 324,  24, 456, 267, 157, 460, 488, 426, 309, 229,
   439, 506, 208, 271, 349, 401, 434, 236,  16, 209, 359,  52,  56, 120, 199, 277,
   465, 416, 252, 287, 246,   6,  83, 305, 420, 345, 153, 502,  65,  61, 244, 282,
   173, 222, 418,  67, 386, 368, 261, 101, 476, 291, 195, 430,  49,  79, 166, 330,
   280, 383, 373, 128, 382, 408, 155, 495, 367, 388, 274, 107, 459, 417,  62, 454,
   132, 225, 203, 316, 234,  14, 301,  91, 503, 286, 424, 211, 347, 307, 140, 374,
    35, 103, 125, 427,  19, 214, 453, 146, 498, 314, 444, 230, 256, 329, 198, 285,
    50, 116,  78, 410,  10, 205, 510, 171, 231,  45, 139, 467,  29,  86, 505,  32,
    72,  26, 342, 150, 313, 490, 431, 238, 411, 325, 149, 473,  40, 119, 174, 355,
   185, 233, 389,  71, 448, 273, 372,  55, 110, 178, 322,  12, 469, 392, 369, 190,
     1, 109, 375, 137, 181,  88,  75, 308, 260, 484,  98, 272, 370, 275, 412, 111,
   336, 318,   4, 504, 492, 259, 304,  77, 337, 435,  21, 357, 303, 332, 483,  18,
    47,  85,  25, 497, 474, 289, 100, 269, 296, 478, 270, 106,  31, 104, 433,  84,
   414, 486, 394,  96,  99, 154, 511, 148, 413, 361, 409, 255, 162, 215, 302, 201,
   266, 351, 343, 144, 441, 365, 108, 298, 251,  34, 182, 509, 138, 210, 335, 133,
   311, 352, 328, 141, 396, 346, 123, 319, 450, 281, 429, 228, 443, 481,  92, 404,
   485, 422, 248, 297,  23, 213, 130, 466,  22, 217, 283,  70, 294, 360, 419, 127,
   312, 377,   7, 468, 194,   2, 117, 295, 463, 258, 224, 447, 247, 187,  80, 398,
   284, 353, 105, 390, 299, 471, 470, 184,  57, 200, 348,  63, 204, 188,  33, 451,
    97,  30, 310, 219,  94, 160, 129, 493,  64, 179, 263, 102, 189, 207, 114, 402,
   438, 477, 387, 122, 192,  42, 381,   5, 145, 118, 180, 449, 293, 323, 136, 380,
    43,  66,  60, 455, 341, 445, 202, 432,   8, 237,  15, 376, 436, 464,  59, 461,
};

typedef struct
{
    uint16_t KLi1[8];
    uint16_t KLi2[8];
    uint16_t KOi1[8];
    uint16_t KOi2[8];
    uint16_t KOi3[8];
    uint16_t KIi1[8];
    uint16_t KIi2[8];
    uint16_t KIi3[8];
} kasumi_t;


/* ********************* INTERNAL FUNCTIONS PROTOTYPE ********************* */
void block_encrypt(kasumi_t *config, uint8_t val[BLOCKSIZEB]);
void block_decrypt(kasumi_t *config, uint8_t val[BLOCKSIZEB]);
void key_setup(kasumi_t *config, const uint8_t *key);

static uint16_t rol16(uint16_t x, unsigned n);
static uint16_t fi(uint16_t in, uint16_t subkey);
static uint32_t fo(uint32_t in, int round_no, const kasumi_t *config);
static uint32_t fl(uint32_t in, int round_no, const kasumi_t *config);


/* *************************** HELPER FUNCTIONS *************************** */
static uint16_t
rol16(uint16_t x, unsigned n)
{
    return (uint16_t)(((x << n) | (x >> (16 - n))) & 0xffff);
}

static uint16_t
fi(uint16_t in, uint16_t subkey)
{
    uint16_t nine;
    uint16_t seven;

    nine  = (uint16_t)((in >> 7) & 0x1ff);
    seven = (uint16_t)(in & 0x7f);

    nine  = (uint16_t)(S9[nine] ^ seven);
    seven = (uint16_t)(S7[seven] ^ (nine & 0x7f));
    seven ^= (uint16_t)(subkey >> 9);
    nine  ^= (uint16_t)(subkey & 0x1ff);
    nine  = (uint16_t)(S9[nine] ^ seven);
    seven = (uint16_t)(S7[seven] ^ (nine & 0x7f));

    return (uint16_t)((seven << 9) | nine);
}

static uint32_t
fo(uint32_t in, int round_no, const kasumi_t *config)
{
    uint16_t left;
    uint16_t right;

    left  = (uint16_t)(in >> 16);
    right = (uint16_t)(in & 0xffff);

    left ^= config->KOi1[round_no];
    left  = fi(left, config->KIi1[round_no]);
    left ^= right;

    right ^= config->KOi2[round_no];
    right  = fi(right, config->KIi2[round_no]);
    right ^= left;

    left ^= config->KOi3[round_no];
    left  = fi(left, config->KIi3[round_no]);
    left ^= right;

    return ((uint32_t)right << 16) | left;
}

static uint32_t
fl(uint32_t in, int round_no, const kasumi_t *config)
{
    uint16_t l;
    uint16_t r;
    uint16_t a;
    uint16_t b;

    l = (uint16_t)(in >> 16);
    r = (uint16_t)(in & 0xffff);

    a = (uint16_t)(l & config->KLi1[round_no]);
    r ^= rol16(a, 1);
    b = (uint16_t)(r | config->KLi2[round_no]);
    l ^= rol16(b, 1);

    return ((uint32_t)l << 16) | r;
}


/* ************************ CRYPTOGRAPHY ALGORITHM ************************ */
void
key_setup(kasumi_t *config, const uint8_t *key)
{
    uint16_t ukey[8];
    uint16_t kprime[8];
    unsigned n;

    for (n = 0; n < 8; n++)
        ukey[n] = (uint16_t)((key[n * 2] << 8) | key[n * 2 + 1]);

    for (n = 0; n < 8; n++)
        kprime[n] = (uint16_t)(ukey[n] ^ KASUMI_C[n]);

    for (n = 0; n < 8; n++)
    {
        config->KLi1[n] = rol16(ukey[n], 1);
        config->KLi2[n] = kprime[(n + 2) & 7];
        config->KOi1[n] = rol16(ukey[(n + 1) & 7], 5);
        config->KOi2[n] = rol16(ukey[(n + 5) & 7], 8);
        config->KOi3[n] = rol16(ukey[(n + 6) & 7], 13);
        config->KIi1[n] = kprime[(n + 4) & 7];
        config->KIi2[n] = kprime[(n + 3) & 7];
        config->KIi3[n] = kprime[(n + 7) & 7];
    }
}

void
block_encrypt(kasumi_t *config, uint8_t val[BLOCKSIZEB])
{
    uint32_t left;
    uint32_t right;
    uint32_t temp;
    int      n;

    left  = load32_be(val);
    right = load32_be(val + 4);

    for (n = 0; n <= 7; )
    {
        temp  = fo(fl(left, n, config), n, config);
        right ^= temp;
        n++;
        temp = fl(fo(right, n, config), n, config);
        left ^= temp;
        n++;
    }

    store32_be(val, left);
    store32_be(val + 4, right);
}

void
block_decrypt(kasumi_t *config, uint8_t val[BLOCKSIZEB])
{
    uint32_t left;
    uint32_t right;
    uint32_t temp;
    int      n;

    left  = load32_be(val);
    right = load32_be(val + 4);

    for (n = 7; n >= 0; )
    {
        temp  = fl(fo(right, n, config), n, config);
        left ^= temp;
        n--;
        temp  = fo(fl(left, n, config), n, config);
        right ^= temp;
        n--;
    }

    store32_be(val, left);
    store32_be(val + 4, right);
}


/* cipher port for mode.c */
#include "cipher_port.h"

const uint32_t CIPHER_BLOCK_BYTES = BLOCKSIZEB;
const uint32_t CIPHER_KEY_BYTES   = KEYSIZEB;

void
cipher_ctx_init(uint8_t *ctx, const uint8_t *key)
{
    key_setup((kasumi_t *)ctx, key);
}

void
cipher_encrypt_block(uint8_t *ctx, uint8_t *block)
{
    block_encrypt((kasumi_t *)ctx, block);
}

void
cipher_decrypt_block(uint8_t *ctx, uint8_t *block)
{
    block_decrypt((kasumi_t *)ctx, block);
}
