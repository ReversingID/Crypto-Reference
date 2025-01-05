/*
    Camellia by Mitsubishi Electric
    Archive of Reversing.ID
    Block Cipher

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
#include <memory.h>

/* ************************ CONFIGURATION & SEED ************************ */
#define BLOCKSIZE   128
#define BLOCKSIZEB  16
#define KEYSIZE     128
#define KEYSIZEB    16
#define SBOX1(n)    SBOX[(n)]
#define SBOX2(n)    (uint8_t) ((SBOX[(n)] >> 7 ^ SBOX[(n)] << 1) & 0xFF)
#define SBOX3(n)    (uint8_t) ((SBOX[(n)] >> 1 ^ SBOX[(n)] << 7) & 0xFF)
#define SBOX4(n)    SBOX[((n) << 1 ^ (n) >> 7) & 0xFF]

uint8_t SIGMA[48] = 
{
    0xA0, 0x9E, 0x66, 0x7F, 0x3B, 0xCC, 0x90, 0x8B,
    0xB6, 0x7A, 0xE8, 0x58, 0x4C, 0xAA, 0x73, 0xB2,
    0xC6, 0xEF, 0x37, 0x2F, 0xE9, 0x4F, 0x82, 0xBE,
    0x54, 0xFF, 0x53, 0xA5, 0xF1, 0xD3, 0x6F, 0x1C,
    0x10, 0xE5, 0x27, 0xFA, 0xDE, 0x68, 0x2D, 0x1D,
    0xB0, 0x56, 0x88, 0xC2, 0xB3, 0xE6, 0xC1, 0xFD
};

const int32_t KSFT1[26] = 
{
     0, 64,  0, 64, 15, 79,  15, 79,  30, 94, 45, 109, 45, 124, 60, 124, 
    77, 13, 94, 30, 94, 30, 111, 47, 111, 47 
};

const int32_t KIDX1[26] =
{
    0, 0, 4, 4, 0, 0, 4, 4, 4, 4, 0, 0, 4, 0, 4, 4,
    0, 0, 0, 0, 4, 4, 0, 0, 4, 4 
};

const int32_t KSFT2[34] = 
{
     0,  64,  0,  64, 15,  79, 15, 79, 30, 94, 30, 94, 45, 109,  45, 109,
    60, 124, 60, 124, 60, 124, 77, 13, 77, 13, 94, 30, 94,  30, 111,  47,
    111, 47 
};

const int32_t KIDX2[34] = 
{
     0,  0, 12, 12, 8, 8, 4, 4, 8, 8, 12, 12, 0, 0, 4, 4, 
     0,  0, 8, 8, 12, 12, 0, 0, 4, 4,  8,  8, 4, 4, 0, 0,
    12, 12 
};

const uint8_t SBOX[256] = 
{
    112, 130,  44, 236, 179,  39, 192, 229, 228, 133,  87,  53, 234,  12, 174,  65,
     35, 239, 107, 147,  69,  25, 165,  33, 237,  14,  79,  78,  29, 101, 146, 189,
    134, 184, 175, 143, 124, 235,  31, 206,  62,  48, 220,  95,  94, 197,  11,  26,
    166, 225,  57, 202, 213,  71,  93,  61, 217,   1,  90, 214,  81,  86, 108,  77,
    139,  13, 154, 102, 251, 204, 176,  45, 116,  18,  43,  32, 240, 177, 132, 153,
    223,  76, 203, 194,  52, 126, 118,   5, 109, 183, 169,  49, 209,  23,   4, 215,
     20,  88,  58,  97, 222,  27,  17,  28,  50,  15, 156,  22,  83,  24, 242,  34,
    254,  68, 207, 178, 195, 181, 122, 145,  36,   8, 232, 168,  96, 252, 105,  80,
    170, 208, 160, 125, 161, 137,  98, 151,  84,  91,  30, 149, 224, 255, 100, 210,
     16, 196,   0,  72, 163, 247, 117, 219, 138,   3, 230, 218,   9,  63, 221, 148,
    135,  92, 131,   2, 205,  74, 144,  51, 115, 103, 246, 243, 157, 127, 191, 226,
     82, 155, 216,  38, 200,  55, 198,  59, 129, 150, 111,  75,  19, 190,  99,  46,
    233, 121, 167, 140, 159, 110, 188, 142,  41, 245, 249, 182,  47, 253, 180,  89,
    120, 152,   6, 106, 231,  70, 113, 186, 212,  37, 171,  66, 136, 162, 141, 250,
    114,   7, 185,  85, 248, 238, 172,  10,  54,  73,  42, 104,  60,  56, 241, 164,
     64,  40, 211, 123, 187, 201,  67, 193,  21, 227, 173, 244, 119, 199, 128, 158
};

/* context and configuration */
typedef struct 
{
    uint32_t bits;              /* ukuran kunci dalam bits */
    uint8_t  ekeys[288];
} camellia_t;


/* ********************* INTERNAL FUNCTIONS PROTOTYPE ********************* */
void block_encrypt(camellia_t * config, uint8_t val[BLOCKSIZEB]);
void block_decrypt(camellia_t * config, uint8_t val[BLOCKSIZEB]);
void key_setup(camellia_t * config, uint8_t secret[32], uint32_t bits);

void swap_half(uint8_t x[16]);
void rot_block(uint32_t dst[2], const uint32_t src[4],  const uint32_t n);
void dword2byte(uint8_t dst[16], const uint32_t src[4]);
void byte2dword(uint32_t dst[4], const uint8_t src[16]);
void feistel(uint8_t y[8], const uint8_t x[8], const uint8_t k[8]);
void fl_layer(uint8_t x[16], const uint8_t kl[16], const uint8_t kr[16]);


/* *************************** HELPER FUNCTIONS *************************** */
void xor_block(uint8_t* dst, const uint8_t * src1, const uint8_t * src2);


/* ********************* MODE OF OPERATIONS PROTOTYPE ********************* */
/** Electronic Code Book mode **/
void camellia_encrypt_ecb(uint8_t * data, uint32_t length, uint8_t * key);
void camellia_decrypt_ecb(uint8_t * data, uint32_t length, uint8_t * key);

/** Cipher Block Chaining mode **/
void camellia_encrypt_cbc(uint8_t * data, uint32_t length, uint8_t * key, uint8_t * iv);
void camellia_decrypt_cbc(uint8_t * data, uint32_t length, uint8_t * key, uint8_t * iv);

/** Cipher Feedback mode **/
void camellia_encrypt_cfb(uint8_t * data, uint32_t length, uint8_t * key, uint8_t * iv);
void camellia_decrypt_cfb(uint8_t * data, uint32_t length, uint8_t * key, uint8_t * iv);

/** Counter mode **/
void camellia_encrypt_ctr(uint8_t * data, uint32_t length, uint8_t * key, uint8_t *nonce);
void camellia_decrypt_ctr(uint8_t * data, uint32_t length, uint8_t * key, uint8_t *nonce);

/** Output Feedback mode **/
void camellia_encrypt_ofb(uint8_t * data, uint32_t length, uint8_t * key, uint8_t * iv);
void camellia_decrypt_ofb(uint8_t * data, uint32_t length, uint8_t * key, uint8_t * iv);

/** Propagating Cipher Block Chaining mode **/
void camellia_encrypt_pcbc(uint8_t * data, uint32_t length, uint8_t * key, uint8_t * iv);
void camellia_decrypt_pcbc(uint8_t * data, uint32_t length, uint8_t * key, uint8_t * iv);


/* ************************ CRYPTOGRAPHY ALGORITHM ************************ */
/* 
    Enkripsi sebuah block dengan Camellia. 
    Pastikan konfigurasi telah dilakukan dengan memanggil camellia_setup()
*/
void 
block_encrypt(camellia_t * config, uint8_t val[BLOCKSIZEB])
{
    uint32_t i;
    uint8_t  c[BLOCKSIZEB];

    xor_block(c, val, config->ekeys);

    for (i = 0; i < 3; i++)
    {
        feistel(c + 8, c    , config->ekeys + 16 + (i << 4));
        feistel(c    , c + 8, config->ekeys + 24 + (i << 4));
    }

    fl_layer(c, config->ekeys + 64, config->ekeys + 72);

    for (i = 0; i < 3; i++)
    {
        feistel(c + 8, c    , config->ekeys + 80 + (i << 4));
        feistel(c    , c + 8, config->ekeys + 88 + (i << 4));
    }

    fl_layer(c, config->ekeys + 128, config->ekeys + 136);

    for (i = 0; i < 3; i++)
    {
        feistel(c + 8, c    , config->ekeys + 144 + (i << 4));
        feistel(c    , c + 8, config->ekeys + 152 + (i << 4));
    }

    if (config->bits == 128)
    {
        swap_half(c);
        xor_block(c, config->ekeys + 192, c);
    }
    else 
    {
        fl_layer(c, config->ekeys + 192, config->ekeys + 200);

        for (i = 0; i < 3; i++)
        {
            feistel(c + 8, c    , config->ekeys + 208 + (i << 4));
            feistel(c    , c + 8, config->ekeys + 216 + (i << 4));
        }

        swap_half(c);
        xor_block(c, config->ekeys + 256, c);
    }
    memcpy(val, c, BLOCKSIZEB);
}

/* 
    Dekripsi sebuah block dengan Camellia
    Pastikan konfigurasi telah dilakukan dengan memanggil camellia_setup()
*/
void 
block_decrypt(camellia_t * config, uint8_t val[BLOCKSIZEB])
{
    int32_t i;
    uint8_t p[BLOCKSIZEB];

    if (config->bits == 128)
    {
        xor_block(p, val, config->ekeys + 192);
    }
    else 
    {
        xor_block(p, val, config->ekeys + 256);

        for (i = 2; i >= 0; i--)
        {
            feistel(p + 8, p    , config->ekeys + 216 + (i << 4));
            feistel(p    , p + 8, config->ekeys + 208 + (i << 4));
        }

        fl_layer(p, config->ekeys + 200, config->ekeys + 192);
    }

    for (i = 2; i >= 0; i--)
    {
        feistel(p + 8, p    , config->ekeys + 152 + (i << 4));
        feistel(p    , p + 8, config->ekeys + 144 + (i << 4));
    }

    fl_layer(p, config->ekeys + 136, config->ekeys + 128);

    for (i = 2; i >= 0; i--)
    {
        feistel(p + 8, p    , config->ekeys + 88 + (i << 4));
        feistel(p    , p + 8, config->ekeys + 80 + (i << 4));
    }

    fl_layer(p, config->ekeys + 72, config->ekeys + 64);

    for (i = 2; i >= 0; i--)
    {
        feistel(p + 8, p    , config->ekeys + 24 + (i << 4));
        feistel(p    , p + 8, config->ekeys + 16 + (i << 4));
    }

    swap_half(p);
    xor_block(val, p, config->ekeys);
}


/* ******************* INTERNAL FUNCTIONS IMPLEMENTATION ******************* */
//* bagi block menjadi setengah dan pertukarkan (swap) keduanya */
void 
swap_half(uint8_t x[16])
{
    uint8_t  t;
    uint32_t i;

    for (i = 0; i < 8; i++)
    {
        t        = x[i];
        x[i]     = x[8 + i];
        x[8 + i] = t;
    }
}

/* operasi rotation terhadap block */
void 
rot_block(uint32_t dst[2], const uint32_t src[4],  const uint32_t n)
{
    uint32_t r;

    /* r < 32 */
    if (r = (n & 31))
    {
        dst[0] = (src[ (n >> 5)      & 3] << r) ^ (src[((n >> 5) + 1) & 3] >> (32 - r));
        dst[1] = (src[((n >> 5) + 1) & 3] << r) ^ (src[((n >> 5) + 2) & 3] >> (32 - r));
    }
    else 
    {
        dst[0] = src[ (n >> 5)      & 3];
        dst[1] = src[((n >> 5) + 1) & 3];
    }
}

/* mengubah block dalam preresentasi 4 x uint32_t menjadi 16 x uint8_t */
void 
dword2byte(uint8_t dst[16], const uint32_t src[4])
{
    uint32_t i;
    for (i = 0; i < 4; i++)
    {
        dst[(i << 2)    ] = (uint8_t)((src[i] >> 24) & 0xFF);
		dst[(i << 2) + 1] = (uint8_t)((src[i] >> 16) & 0xFF);
		dst[(i << 2) + 2] = (uint8_t)((src[i] >>  8) & 0xFF);
		dst[(i << 2) + 3] = (uint8_t)((src[i]      ) & 0xFF);
    }
}

/* mengubah block dalam representasi 16 x uint8_t menjadi 4 x uint32_t */
void 
byte2dword(uint32_t dst[4], const uint8_t src[16])
{
    uint32_t i;
    for (i = 0; i < 4; i++)
    {
        dst[i] = ((uint32_t) src[(i << 2)    ] << 24)
               | ((uint32_t) src[(i << 2) + 1] << 16)
               | ((uint32_t) src[(i << 2) + 2] <<  8)
               | ((uint32_t) src[(i << 2) + 3]      );
    }
}

/* 
    struktur feistel
    y' = x ^ k
    x' = x
*/
void 
feistel(uint8_t y[8], const uint8_t x[8], const uint8_t k[8])
{
    uint8_t t[8];

    t[0] = SBOX1(x[0] ^ k[0]);
    t[1] = SBOX2(x[1] ^ k[1]);
    t[2] = SBOX3(x[2] ^ k[2]);
    t[3] = SBOX4(x[3] ^ k[3]);
    t[4] = SBOX2(x[4] ^ k[4]);
    t[5] = SBOX3(x[5] ^ k[5]);
    t[6] = SBOX4(x[6] ^ k[6]);
    t[7] = SBOX1(x[7] ^ k[7]);

	y[0] ^= t[0] ^ t[2] ^ t[3] ^ t[5] ^ t[6] ^ t[7];
	y[1] ^= t[0] ^ t[1] ^ t[3] ^ t[4] ^ t[6] ^ t[7];
	y[2] ^= t[0] ^ t[1] ^ t[2] ^ t[4] ^ t[5] ^ t[7];
	y[3] ^= t[1] ^ t[2] ^ t[3] ^ t[4] ^ t[5] ^ t[6];
	y[4] ^= t[0] ^ t[1] ^ t[5] ^ t[6] ^ t[7];
	y[5] ^= t[1] ^ t[2] ^ t[4] ^ t[6] ^ t[7];
	y[6] ^= t[2] ^ t[3] ^ t[4] ^ t[5] ^ t[7];
	y[7] ^= t[0] ^ t[3] ^ t[4] ^ t[5] ^ t[6];
}

/* FL layer pada camellia */
void 
fl_layer(uint8_t x[16], const uint8_t kl[16], const uint8_t kr[16])
{
    uint32_t t[4], u[4], v[4];

    byte2dword(t,  x);
    byte2dword(u, kl);
    byte2dword(v, kr);

	t[1] ^= ((t[0] & u[0]) << 1) ^ ((t[0] & u[0]) >> 31);
	t[0] ^= t[1] | u[1];
	t[2] ^= t[3] | v[1];
	t[3] ^= ((t[2] & v[0]) << 1) ^ ((t[2] & v[0]) >> 31);

    dword2byte(x, t);
}

/* Turunkan round-key dari secret key */
void 
key_setup(camellia_t * config, uint8_t secret[32], uint32_t bits)
{
    uint8_t  t[64];
    uint32_t u[20];
    uint32_t i;

    config->bits = bits;
    switch (config->bits)
    {
        case 128:
            for (i =  0; i < 16; i++) t[i] = secret[i];
            for (i = 16; i < 32; i++) t[i] = 0;
            break;
        case 192:
            for (i =  0; i < 24; i++) t[i] = secret[i];
            for (i = 24; i < 32; i++) t[i] = secret[i - 8] ^ 0xFF;
            break;
        case 256:
            for (i = 0; i < 32; i++) t[i] = secret[i];
            break;
    }
    
    xor_block(t + 32, t     , t + 16);

    feistel(t + 40, t + 32, SIGMA    );
    feistel(t + 32, t + 40, SIGMA + 8);

    xor_block(t + 32, t + 32, t     );

    feistel(t + 40, t + 32, SIGMA + 16);
    feistel(t + 32, t + 40, SIGMA + 24);

    byte2dword(u    , t   );
    byte2dword(u + 4, t+32);

    if (config->bits == 128)
    {
        for (i = 0; i < 26; i += 2)
        {
            rot_block(u + 16, u + KIDX1[i    ], KSFT1[i    ]);
            rot_block(u + 18, u + KIDX1[i + 1], KSFT1[i + 1]);
            dword2byte(config->ekeys + (i << 3), u + 16);
        }
    }
    else 
    {
        xor_block(t + 48, t + 16, t + 32);

        feistel(t + 56, t + 48, SIGMA + 32);
        feistel(t + 48, t + 56, SIGMA + 40);

        byte2dword(u +  8, t + 16);
        byte2dword(u + 12, t + 48);

        for (i = 0; i < 34; i += 2);
        {
            rot_block(u + 16, u + KIDX2[i    ], KSFT2[i    ]);
            rot_block(u + 18, u + KIDX2[i + 1], KSFT2[i + 1]);
            dword2byte(config->ekeys + (i << 3), u + 16);
        }
    }
}


/* *************************** HELPER FUNCTIONS *************************** */
/* xor dua buah block menjadi sebuah block baru */
void 
xor_block(uint8_t * dst, const uint8_t * src1, const uint8_t * src2)
{
    uint32_t i;
    for (i = 0; i < BLOCKSIZEB; i++) 
        dst[i] = src1[i] ^ src2[i];
}


/* ******************* MODE OF OPERATIONS IMPLEMENTATION ******************* */
/*
    Enkripsi block data dengan mode ECB.
    Enkripsi diberlakukan secara independen tanpa ada hubungan dengan block
    sebelum dan berikutnya.
    Pastikan jumlah block valid.
*/
void camellia_encrypt_ecb(uint8_t * data, uint32_t length, uint8_t * key)
{
    uint32_t   i;
    camellia_t config;

    // Setup configuration
    config.bits = 128;
    key_setup(&config, key, KEYSIZE);

    for (i = 0; i < length; i += BLOCKSIZEB)
        block_encrypt(&config, &data[i]);
}

/*
    Dekripsi block data dengan mode ECB.
    Dekripsi diberlakukan secara independen tanpa ada hubungan dengan block
    sebelum dan berikutnya.
    Pastikan jumlah block valid.
*/
void camellia_decrypt_ecb(uint8_t * data, uint32_t length, uint8_t * key)
{
    uint32_t   i;
    camellia_t config;

    // Setup configuration
    config.bits = 128;
    key_setup(&config, key, KEYSIZE);

    for(i = 0; i < length; i += BLOCKSIZEB)
        block_decrypt(&config, &data[i]);
}


/*
    Enkripsi block data dengan mode CBC.
    Sebelum enkripsi, plaintext akan di-XOR dengan block sebelumnya.
    Pastikan jumlah block valid.
*/
void camellia_encrypt_cbc(uint8_t * data, uint32_t length, uint8_t * key, uint8_t * iv)
{
    uint32_t    i;
    camellia_t  config;
    uint8_t   * prev_block = iv;

    // Setup configuration
    key_setup(&config, key, KEYSIZE);

    for (i = 0; i < length; i += BLOCKSIZEB)
    {
        // XOR block plaintext dengan block ciphertext sebelumnya
        xor_block(&data[i], &data[i], prev_block);

        // Enkripsi plaintext menjadi ciphertext
        block_encrypt(&config, &data[i]);

        // Simpan block ciphertext untuk operasi XOR selanjutnya
        prev_block = &data[i];
    }
}

/*
    Dekripsi block data dengan mode CBC.
    Setelah dekripsi, plaintext akan di-XOR dengan block sebelumnya.
    Pastikan jumlah block valid.
*/
void camellia_decrypt_cbc(uint8_t * data, uint32_t length, uint8_t * key, uint8_t * iv)
{
    uint32_t   i;
    camellia_t config;
    uint8_t    prev_block[BLOCKSIZEB];
    uint8_t    ctext_block[BLOCKSIZEB];

    // Setup configuration
    key_setup(&config, key, KEYSIZE);
    
    memcpy(prev_block, iv, BLOCKSIZEB);

    for (i = 0; i < length; i += BLOCKSIZEB)
    {
        // Simpan block ciphertext untuk operasi XOR berikutnya.
        memcpy(ctext_block, &data[i], BLOCKSIZEB);

        // Dekripsi ciphertext menjadi block
        block_decrypt(&config, &data[i]);

        // XOR block block dengan block ciphertext sebelumnya
        // gunakan IV bila ini adalah block pertama
        xor_block(&data[i], &data[i], prev_block);

        // Pindahkan block ciphertext yang telah disimpan
        memcpy(prev_block, ctext_block, BLOCKSIZEB);
    }
}


/*
    Enkripsi block data dengan mode CFB.
    Pastikan jumlah block valid.
*/
void camellia_encrypt_cfb(uint8_t * data, uint32_t length, uint8_t * key, uint8_t * iv)
{
    uint32_t   i;
    camellia_t config;
    uint8_t    prev_block[BLOCKSIZEB];

    // Setup configuration
    key_setup(&config, key, KEYSIZE);

    memcpy(prev_block, iv, BLOCKSIZEB);

    for (i = 0; i < length; i += BLOCKSIZEB)
    {
        // Enkripsi block sebelumnya
        // gunakan IV bila ini block pertama
        block_encrypt(&config, prev_block);

        // XOR dengan plaintext untuk mendapatkan ciphertext
        xor_block(&data[i], &data[i], prev_block);

        // Simpan block ciphertext untuk operasi XOR berikutnya
        memcpy(prev_block, &data[i], BLOCKSIZEB);
    }
}

/*
    Dekripsi block data dengan mode CFB.
    Pastikan jumlah block valid.
*/
void camellia_decrypt_cfb(uint8_t * data, uint32_t length, uint8_t * key, uint8_t * iv)
{
    uint32_t   i;
    camellia_t config;
    uint8_t    prev_block[BLOCKSIZEB];
    uint8_t    ctext_block[BLOCKSIZEB];

    // Setup configuration
    key_setup(&config, key, KEYSIZE);

    memcpy(prev_block, iv, BLOCKSIZEB);

    for (i = 0; i < length; i += BLOCKSIZEB)
    {
        // Simpan block cipher untuk operasi
        memcpy(ctext_block, &data[i], BLOCKSIZEB);

        // Enkripsi block sebelumnya
        // gunakan IV bila ini block pertama
        block_encrypt(&config, prev_block);

        // XOR dengan plaintext untuk mendapatkan ciphertext
        xor_block(&data[i], &data[i], prev_block);

        // Simpan block ciphertext untuk operasi XOR berikutnya
        memcpy(prev_block, ctext_block, BLOCKSIZEB);
    }
}


/*
    Enkripsi block data dengan mode CTR.
    Pastikan jumlah block valid.
*/
void camellia_encrypt_ctr(uint8_t * data, uint32_t length, uint8_t * key, uint8_t *nonce)
{
    uint32_t   i;
    camellia_t config;
    uint8_t    local_nonce[BLOCKSIZEB];
    uint32_t * nonce_counter = (uint32_t*)&local_nonce[12];

    // Setup configuration
    key_setup(&config, key, KEYSIZE);

    memcpy(local_nonce, nonce, BLOCKSIZEB);

    for (i = 0; i < length; i += BLOCKSIZEB)
    {
        // Enkripsi nonce + counter
        block_encrypt(&config, local_nonce);

        // XOR nonce terenkripsi dengan plaintext untuk mendapatkan ciphertext.
        xor_block(&data[i], &data[i], local_nonce);

        // Naikkan nilai nonce dengan 1.
        (*nonce_counter) ++;
    }
}

/*
    Enkripsi block data dengan mode CTR.
    Pastikan jumlah block valid.
*/
void camellia_decrypt_ctr(uint8_t * data, uint32_t length, uint8_t * key, uint8_t *nonce)
{
    uint32_t   i;
    camellia_t config;
    uint8_t    local_nonce[BLOCKSIZEB];
    uint32_t * nonce_counter = (uint32_t*)&local_nonce[12];

    // Setup configuration
    key_setup(&config, key, KEYSIZE);
    
    memcpy(local_nonce, nonce, BLOCKSIZEB);

    for (i = 0; i < length; i += BLOCKSIZEB)
    {
        // Enkripsi nonce + counter
        block_encrypt(&config, local_nonce);

        // XOR nonce terenkripsi dengan plaintext untuk mendapatkan ciphertext.
        xor_block(&data[i], &data[i], local_nonce);

        // Naikkan nilai nonce dengan 1.
        (*nonce_counter) ++;
    }
}


/*
    Enkripsi block data dengan mode OFB.
    Pastikan jumlah block valid.
*/
void camellia_encrypt_ofb(uint8_t * data, uint32_t length, uint8_t * key, uint8_t * iv)
{
    uint32_t   i;
    camellia_t config;
    uint8_t    prev_block[BLOCKSIZEB];

    // Setup configuration
    key_setup(&config, key, KEYSIZE);
    
    memcpy(prev_block, iv, BLOCKSIZEB);
    
    for (i = 0; i < length; i += BLOCKSIZEB)
    {
        // Enkripsi block sebelumnya 
        // gunakan IV bila ini block pertama
        block_encrypt(&config, prev_block);

        // XOR plaintext dengan output dari enkripsi untuk mendapatkan ciphertext.
        xor_block(&data[i], &data[i], prev_block);
    }
}

/*
    Dekripsi block data dengan mode OFB.
    Pastikan jumlah block valid.
*/
void camellia_decrypt_ofb(uint8_t * data, uint32_t length, uint8_t * key, uint8_t * iv)
{
    uint32_t   i;
    camellia_t config;
    uint8_t    prev_block[BLOCKSIZEB];

    // Setup configuration
    key_setup(&config, key, KEYSIZE);
    
    memcpy(prev_block, iv, BLOCKSIZEB);
    
    for (i = 0; i < length; i += BLOCKSIZEB)
    {
        // Enkripsi block sebelumnya 
        // gunakan IV bila ini block pertama
        block_encrypt(&config, prev_block);

        // XOR plaintext dengan output dari enkripsi untuk mendapatkan ciphertext.
        xor_block(&data[i], &data[i], prev_block);
    }
}


/*
    Enkripsi block data dengan mode OFB.
    Pastikan jumlah block valid.
*/
void camellia_encrypt_pcbc(uint8_t * data, uint32_t length, uint8_t * key, uint8_t * iv)
{
    uint32_t   i;
    camellia_t config;
    uint8_t    prev_block[BLOCKSIZEB];
    uint8_t    ptext_block[BLOCKSIZEB];

    // Setup configuration
    key_setup(&config, key, KEYSIZE);
    
    memcpy(prev_block, iv, BLOCKSIZEB);

    for (i = 0; i < length; i += BLOCKSIZEB)
    {
        // Simpan plaintext untuk dioperasikan dengan block berikutnya.
        memcpy(ptext_block, &data[i], BLOCKSIZEB);

        // XOR plaintext dengan block sebelumnya
        // gunakan IV bila ini block pertama
        xor_block(&data[i], &data[i], prev_block);

        // Enkripsi
        block_encrypt(&config, &data[i]);

        // Hitung block berikutnya
        xor_block(prev_block, ptext_block, &data[i]);
    }
}

/*
    Dekripsi block data dengan mode OFB.
    Pastikan jumlah block valid.
*/
void camellia_decrypt_pcbc(uint8_t * data, uint32_t length, uint8_t * key, uint8_t * iv)
{
    uint32_t   i;
    camellia_t config;
    uint8_t    prev_block[BLOCKSIZEB];
    uint8_t    ptext_block[BLOCKSIZEB];

    // Setup configuration
    key_setup(&config, key, KEYSIZE);
    
    memcpy(prev_block, iv, BLOCKSIZEB);

    for (i = 0; i < length; i += BLOCKSIZEB)
    {
        // Simpan ciphertext untuk dioperasikan dengan block berikutnya.
        memcpy(ptext_block, &data[i], BLOCKSIZEB);

        // Dekripsi ciphertext untuk mendapatkan plaintext ter-XOR
        block_decrypt(&config, &data[i]);

        // XOR dengan block sebelumnya
        // gunakan IV bila ini block pertama
        xor_block(&data[i], &data[i], prev_block);

        // Hitung block berikutnya
        xor_block(prev_block, ptext_block, &data[i]);
    }
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
    Meskipun key didefinisikan sebagai 32-byte karakter, hanya 16 karakter saja yang
    digunakan, karena bits dikonfigurasi sebagai 128-bit (16-byte).
    */
    uint8_t key[32] = 
            { 0x52, 0x45, 0x56, 0x45, 0x52, 0x53, 0x49, 0x4E, 0x47, 0x2E, 0x49, 0x44, 
    /* ASCII:   R     E     V     E     R     S     I     N     G     .     I     D  */
              0x53, 0x45, 0x43, 0x52, 0x45, 0x54, 0x20, 0x4b, 0x45, 0x59, 0x31, 0x32,
            /*  S     E     C     R     E     T           K     E     Y     1     2  */
              0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x30 };
            /*  3     4     5     6     7     8     9     0 */

    /*
    initialization vector: 16-bytes
    ukuran IV disesuaikan dengan block yang dipergunakan.
    */
    uint8_t iv[16] = 
            { 0x13, 0x51, 0x00, 0x30, 0x33, 0x8F, 0x0F, 0x70, 0x96, 0xAE, 0x8F, 0xB0, 
              0x97, 0xD7, 0x86, 0xDA }; 

    length = strlen(data);
    printf("Length: %zd - Buffer: %s\n", strlen(data), data);
    printx("Original", data, length);

    /*
    Panjang plaintext: 44
    Karena block cipher mensyaratkan bahwa data harus merupakan kelipatan dari ukuran 
    block, maka harus ada padding agar panjang data mencapai kelipatan block.
    */
    memset(encbuffer, 0, sizeof(encbuffer));
    memset(decbuffer, 0, sizeof(decbuffer));

    // Enkripsi - block: 128   key: 128
    memcpy(encbuffer, data, length);
    camellia_encrypt_ecb(encbuffer, 64, key);       // ECB
    // camellia_encrypt_cbc(encbuffer, 64, key, iv);   // CBC
    // camellia_encrypt_cfb(encbuffer, 64, key, iv);   // CFB
    // camellia_encrypt_ctr(encbuffer, 64, key, iv);   // CTR
    // camellia_encrypt_ofb(encbuffer, 64, key, iv);   // OFB
    // camellia_encrypt_pcbc(encbuffer, 64, key, iv);  // PCBC
    printx("Encrypted", encbuffer, 64);

    // Dekripsi - block: 128   key: 128
    memcpy(decbuffer, encbuffer, 64);
    // camellia_decrypt_ecb(decbuffer, 64, key);       // ECB
    // camellia_decrypt_cbc(decbuffer, 64, key, iv);   // CBC
    // camellia_decrypt_cfb(decbuffer, 64, key, iv);   // CFB
    // camellia_decrypt_ctr(decbuffer, 64, key, iv);   // CTR
    // camellia_decrypt_ofb(decbuffer, 64, key, iv);   // OFB
    // camellia_decrypt_pcbc(decbuffer, 64, key, iv);  // PCBC
    printx("Decrypted", decbuffer, 64);

    printf("\nFinal: %s\n", decbuffer);

    return 0;
}
