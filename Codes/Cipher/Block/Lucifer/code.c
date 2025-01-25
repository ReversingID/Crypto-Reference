/*
    Lucifer
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

wip note: CBC and CFB gives wrong result
*/
#include <stdint.h>
#include <string.h>


/* ************************* CONFIGURATION & SEED ************************* */
#define BLOCKSIZE       128
#define BLOCKSIZEB      16
#define KEYSIZE         128
#define KEYSIZEB        16

/* Diffusion Pattern schedule	*/
static uint8_t DPS[64] = {
	0x04, 0x10, 0x20, 0x02, 0x01, 0x08, 0x40, 0x80,	
    0x80, 0x04, 0x10, 0x20, 0x02, 0x01, 0x08, 0x40,
	0x40, 0x80, 0x04, 0x10, 0x20, 0x02, 0x01, 0x08,
    0x08, 0x40, 0x80, 0x04, 0x10, 0x20, 0x02, 0x01,
    0x01, 0x08, 0x40, 0x80, 0x04, 0x10, 0x20, 0x02,
    0x02, 0x01, 0x08, 0x40, 0x80, 0x04, 0x10, 0x20,
    0x20, 0x02, 0x01, 0x08, 0x40, 0x80, 0x04, 0x10,
    0x10, 0x20, 0x02, 0x01, 0x08, 0x40, 0x80, 0x04
};

/* Precomputed S&P Boxes, Two Varieties */
static uint8_t TCB0[256] = {
    0x57, 0x15, 0x75, 0x36, 0x17, 0x37, 0x14, 0x54, 0x74, 0x76, 0x16, 0x35, 0x55, 0x77, 0x34, 0x56,
    0xdf, 0x9d, 0xfd, 0xbe, 0x9f, 0xbf, 0x9c, 0xdc, 0xfc, 0xfe, 0x9e, 0xbd, 0xdd, 0xff, 0xbc, 0xde,
    0xcf, 0x8d, 0xed, 0xae, 0x8f, 0xaf, 0x8c, 0xcc, 0xec, 0xee, 0x8e, 0xad, 0xcd, 0xef, 0xac, 0xce,
    0xd3, 0x91, 0xf1, 0xb2, 0x93, 0xb3, 0x90, 0xd0, 0xf0, 0xf2, 0x92, 0xb1, 0xd1, 0xf3, 0xb0, 0xd2,
    0xd7, 0x95, 0xf5, 0xb6, 0x97, 0xb7, 0x94, 0xd4, 0xf4, 0xf6, 0x96, 0xb5, 0xd5, 0xf7, 0xb4, 0xd6,
    0x5f, 0x1d, 0x7d, 0x3e, 0x1f, 0x3f, 0x1c, 0x5c, 0x7c, 0x7e, 0x1e, 0x3d, 0x5d, 0x7f, 0x3c, 0x5e,
    0xdb, 0x99, 0xf9, 0xba, 0x9b, 0xbb, 0x98, 0xd8, 0xf8, 0xfa, 0x9a, 0xb9, 0xd9, 0xfb, 0xb8, 0xda,
    0x43, 0x01, 0x61, 0x22, 0x03, 0x23, 0x00, 0x40, 0x60, 0x62, 0x02, 0x21, 0x41, 0x63, 0x20, 0x42,
    0xc3, 0x81, 0xe1, 0xa2, 0x83, 0xa3, 0x80, 0xc0, 0xe0, 0xe2, 0x82, 0xa1, 0xc1, 0xe3, 0xa0, 0xc2,
    0xc7, 0x85, 0xe5, 0xa6, 0x87, 0xa7, 0x84, 0xc4, 0xe4, 0xe6, 0x86, 0xa5, 0xc5, 0xe7, 0xa4, 0xc6,
    0xcb, 0x89, 0xe9, 0xaa, 0x8b, 0xab, 0x88, 0xc8, 0xe8, 0xea, 0x8a, 0xa9, 0xc9, 0xeb, 0xa8, 0xca,
    0x4b, 0x09, 0x69, 0x2a, 0x0b, 0x2b, 0x08, 0x48, 0x68, 0x6a, 0x0a, 0x29, 0x49, 0x6b, 0x28, 0x4a,
    0x5b, 0x19, 0x79, 0x3a, 0x1b, 0x3b, 0x18, 0x58, 0x78, 0x7a, 0x1a, 0x39, 0x59, 0x7b, 0x38, 0x5a,
    0x47, 0x05, 0x65, 0x26, 0x07, 0x27, 0x04, 0x44, 0x64, 0x66, 0x06, 0x25, 0x45, 0x67, 0x24, 0x46,
    0x4f, 0x0d, 0x6d, 0x2e, 0x0f, 0x2f, 0x0c, 0x4c, 0x6c, 0x6e, 0x0e, 0x2d, 0x4d, 0x6f, 0x2c, 0x4e,
    0x53, 0x11, 0x71, 0x32, 0x13, 0x33, 0x10, 0x50, 0x70, 0x72, 0x12, 0x31, 0x51, 0x73, 0x30, 0x52
};

static uint8_t TCB1[256] = {
    0x57, 0xdf, 0xcf, 0xd3, 0xd7, 0x5f, 0xdb, 0x43, 0xc3, 0xc7, 0xcb, 0x4b, 0x5b, 0x47, 0x4f, 0x53,
    0x15, 0x9d, 0x8d, 0x91, 0x95, 0x1d, 0x99, 0x01, 0x81, 0x85, 0x89, 0x09, 0x19, 0x05, 0x0d, 0x11,
    0x75, 0xfd, 0xed, 0xf1, 0xf5, 0x7d, 0xf9, 0x61, 0xe1, 0xe5, 0xe9, 0x69, 0x79, 0x65, 0x6d, 0x71,
    0x36, 0xbe, 0xae, 0xb2, 0xb6, 0x3e, 0xba, 0x22, 0xa2, 0xa6, 0xaa, 0x2a, 0x3a, 0x26, 0x2e, 0x32,
    0x17, 0x9f, 0x8f, 0x93, 0x97, 0x1f, 0x9b, 0x03, 0x83, 0x87, 0x8b, 0x0b, 0x1b, 0x07, 0x0f, 0x13,
    0x37, 0xbf, 0xaf, 0xb3, 0xb7, 0x3f, 0xbb, 0x23, 0xa3, 0xa7, 0xab, 0x2b, 0x3b, 0x27, 0x2f, 0x33,
    0x14, 0x9c, 0x8c, 0x90, 0x94, 0x1c, 0x98, 0x00, 0x80, 0x84, 0x88, 0x08, 0x18, 0x04, 0x0c, 0x10,
    0x54, 0xdc, 0xcc, 0xd0, 0xd4, 0x5c, 0xd8, 0x40, 0xc0, 0xc4, 0xc8, 0x48, 0x58, 0x44, 0x4c, 0x50,
    0x74, 0xfc, 0xec, 0xf0, 0xf4, 0x7c, 0xf8, 0x60, 0xe0, 0xe4, 0xe8, 0x68, 0x78, 0x64, 0x6c, 0x70,
    0x76, 0xfe, 0xee, 0xf2, 0xf6, 0x7e, 0xfa, 0x62, 0xe2, 0xe6, 0xea, 0x6a, 0x7a, 0x66, 0x6e, 0x72,
    0x16, 0x9e, 0x8e, 0x92, 0x96, 0x1e, 0x9a, 0x02, 0x82, 0x86, 0x8a, 0x0a, 0x1a, 0x06, 0x0e, 0x12,
    0x35, 0xbd, 0xad, 0xb1, 0xb5, 0x3d, 0xb9, 0x21, 0xa1, 0xa5, 0xa9, 0x29, 0x39, 0x25, 0x2d, 0x31,
    0x55, 0xdd, 0xcd, 0xd1, 0xd5, 0x5d, 0xd9, 0x41, 0xc1, 0xc5, 0xc9, 0x49, 0x59, 0x45, 0x4d, 0x51,
    0x77, 0xff, 0xef, 0xf3, 0xf7, 0x7f, 0xfb, 0x63, 0xe3, 0xe7, 0xeb, 0x6b, 0x7b, 0x67, 0x6f, 0x73,
    0x34, 0xbc, 0xac, 0xb0, 0xb4, 0x3c, 0xb8, 0x20, 0xa0, 0xa4, 0xa8, 0x28, 0x38, 0x24, 0x2c, 0x30,
    0x56, 0xde, 0xce, 0xd2, 0xd6, 0x5e, 0xda, 0x42, 0xc2, 0xc6, 0xca, 0x4a, 0x5a, 0x46, 0x4e, 0x52
};

static uint32_t P[8]     = {   3,  5,  0, 4,  2, 1, 7, 6 };
static uint32_t SMask[8] = { 128, 64, 32, 16, 8, 4, 2, 1 };

/* context and configuration */
typedef struct 
{
    uint8_t key[16];
    uint8_t pkey[128];
} lucifer_t;


/* ********************* INTERNAL FUNCTIONS PROTOTYPE ********************* */
void block_encrypt(lucifer_t * config, uint8_t val[BLOCKSIZEB]);
void block_decrypt(lucifer_t * config, uint8_t val[BLOCKSIZEB]);
void key_setup(lucifer_t * config, uint8_t * secret);

void block_crypt(lucifer_t * config, uint8_t val[BLOCKSIZEB]);


/* *************************** HELPER FUNCTIONS *************************** */
void xor_block(uint8_t* dst, const uint8_t * src1, const uint8_t * src2);


/* ********************* MODE OF OPERATIONS PROTOTYPE ********************* */
/** Electronic Code Book mode **/
void encrypt_ecb(uint8_t * data, uint32_t length, uint8_t * key);
void decrypt_ecb(uint8_t * data, uint32_t length, uint8_t * key);

/** Cipher Block Chaining mode **/
void encrypt_cbc(uint8_t * data, uint32_t length, uint8_t * key, uint8_t * iv);
void decrypt_cbc(uint8_t * data, uint32_t length, uint8_t * key, uint8_t * iv);

/** Cipher Feedback mode **/
void encrypt_cfb(uint8_t * data, uint32_t length, uint8_t * key, uint8_t * iv);
void decrypt_cfb(uint8_t * data, uint32_t length, uint8_t * key, uint8_t * iv);

/** Counter mode **/
void encrypt_ctr(uint8_t * data, uint32_t length, uint8_t * key, uint8_t *nonce);
void decrypt_ctr(uint8_t * data, uint32_t length, uint8_t * key, uint8_t *nonce);

/** Output Feedback mode **/
void encrypt_ofb(uint8_t * data, uint32_t length, uint8_t * key, uint8_t * iv);
void decrypt_ofb(uint8_t * data, uint32_t length, uint8_t * key, uint8_t * iv);

/** Propagating Cipher Block Chaining mode **/
void encrypt_pcbc(uint8_t * data, uint32_t length, uint8_t * key, uint8_t * iv);
void decrypt_pcbc(uint8_t * data, uint32_t length, uint8_t * key, uint8_t * iv);


/* ************************ CRYPTOGRAPHY ALGORITHM ************************ */
/* 
    Enkripsi sebuah block dengan TwoFish. 
    Pastikan konfigurasi telah dilakukan dengan memanggil key_setup()
*/
void 
block_encrypt(lucifer_t * config, uint8_t val[BLOCKSIZEB])
{
    block_crypt(config, val);
}

/* 
    Dekripsi sebuah block dengan TwoFish. 
    Pastikan konfigurasi telah dilakukan dengan memanggil key_setup()
*/
void 
block_decrypt(lucifer_t * config, uint8_t val[BLOCKSIZEB])
{
    block_crypt(config, val);
}


/* ******************* INTERNAL FUNCTIONS IMPLEMENTATION ******************* */
/*
    bangkitkan subkey untuk enkripsi dan dekripsi.
*/
void 
key_setup(lucifer_t * config, uint8_t * key)
{
    uint8_t *ep, *cp, *pp;
    uint32_t kc, i, j;
    uint8_t  kk[16], pk[16];

    memset(config->key, 0, sizeof(config->key));
    memset(config->pkey, 0, sizeof(config->pkey));

    cp = kk;
    pp = pk;
    ep = &kk[16];

    while (cp < ep)
    {
        *cp++ = *key;
        for (*pp = i = 0; i < 8; i++)
            if (*key & SMask[i])
                *pp |= SMask[P[i]];
        key++;
        pp++;
    }

    cp = config->key;
    pp = config->pkey;
    kc = 8;
    
    for (i = 0; i < BLOCKSIZEB; i++)
    {
        kc = (++kc) & 0x17;

        *cp++ = kk[((kc == 0) ? 15 : (kc - 1))];

        for (j = 0; j < 8; j++)
        {
            *pp++ = pk[kc];
            if (j < 7)
                kc = (++kc) & 0x17;
        }
    }
}

void block_crypt(lucifer_t * config, uint8_t val[BLOCKSIZEB])
{
    uint8_t   * cp, * sp, * dp;
    uint8_t   * h0, * h1, * kc, * ks;
    uint32_t    byte, tcb, i, j;
    uint32_t  * sbs;

    h0 = val;
    h1 = &val[8];
    kc = config->pkey;
    ks = config->key;

    for (i = 0; i < BLOCKSIZEB; i++)
    {
        tcb = *ks++;
        sbs = SMask;
        dp  = DPS;
        sp  = &h0[8];

        // enhancement
        for (j = 0, cp = h1; j < 8; j++) tcb ^= *cp++;

        for (j = 0; j < 8; j++)
        {
            if (tcb & *sbs++)
                byte = TCB1[h1[j] & 0377];
            else 
                byte = TCB0[h1[j] & 0377];

            byte ^= *kc++;
            for (cp = h0; cp < sp; )
                *cp++ ^= (byte & *dp++);
        }

        cp = h0;
        h0 = h1;
        h1 = cp;
    }

    dp = val;
    cp = &val[8];

    for (sp = cp; dp < sp; dp++, cp++)
    {
        byte = *dp;
        *dp  = *cp;
        *cp  = byte;
    }
}



/* *************************** HELPER FUNCTIONS *************************** */
/* Xor 2 block data */
void 
xor_block(uint8_t* dst, const uint8_t * src1, const uint8_t * src2)
{
    register uint32_t i = 0;
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
void 
encrypt_ecb(uint8_t * data, uint32_t length, uint8_t * key)
{
    uint32_t    i;
    lucifer_t   config;

    // Setup configuration
    key_setup(&config, key);

    for (i = 0; i < length; i += BLOCKSIZEB)
        block_encrypt(&config, &data[i]);
}

/*
    Dekripsi block data dengan mode ECB.
    Dekripsi diberlakukan secara independen tanpa ada hubungan dengan block
    sebelum dan berikutnya.
    Pastikan jumlah block valid.
*/
void 
decrypt_ecb(uint8_t * data, uint32_t length, uint8_t * key)
{
    uint32_t    i;
    lucifer_t   config;

    // Setup configuration
    key_setup(&config, key);

    for(i = 0; i < length; i += BLOCKSIZEB)
        block_decrypt(&config, &data[i]);
}


/*
    Enkripsi block data dengan mode CBC.
    Sebelum enkripsi, plaintext akan di-XOR dengan block sebelumnya.
    Pastikan jumlah block valid.
*/
void 
encrypt_cbc(uint8_t * data, uint32_t length, uint8_t * key, uint8_t * iv)
{
    uint32_t    i;
    lucifer_t   config;
    uint8_t   * prev_block = iv;

    // Setup configuration
    key_setup(&config, key);

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
void 
decrypt_cbc(uint8_t * data, uint32_t length, uint8_t * key, uint8_t * iv)
{
    uint32_t    i;
    lucifer_t   config;
    uint8_t     prev_block[BLOCKSIZEB];
    uint8_t     ctext_block[BLOCKSIZEB];

    // Setup configuration
    key_setup(&config, key);
    
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
void 
encrypt_cfb(uint8_t * data, uint32_t length, uint8_t * key, uint8_t * iv)
{
    uint32_t    i;
    lucifer_t   config;
    uint8_t     prev_block[BLOCKSIZEB];

    // Setup configuration
    key_setup(&config, key);

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
void 
decrypt_cfb(uint8_t * data, uint32_t length, uint8_t * key, uint8_t * iv)
{
    uint32_t    i;
    lucifer_t   config;
    uint8_t     prev_block[BLOCKSIZEB];
    uint8_t     ctext_block[BLOCKSIZEB];

    // Setup configuration
    key_setup(&config, key);

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
void 
encrypt_ctr(uint8_t * data, uint32_t length, uint8_t * key, uint8_t *nonce)
{
    uint32_t    i;
    lucifer_t   config;
    uint8_t     local_nonce[BLOCKSIZEB];
    uint32_t  * nonce_counter = (uint32_t*)&local_nonce[BLOCKSIZEB-4];

    // Setup configuration
    key_setup(&config, key);
    
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
void 
decrypt_ctr(uint8_t * data, uint32_t length, uint8_t * key, uint8_t *nonce)
{
    uint32_t    i;
    lucifer_t   config;
    uint8_t     local_nonce[BLOCKSIZEB];
    uint32_t  * nonce_counter = (uint32_t*)&local_nonce[BLOCKSIZEB-4];

    // Setup configuration
    key_setup(&config, key);
    
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
void 
encrypt_ofb(uint8_t * data, uint32_t length, uint8_t * key, uint8_t * iv)
{
    uint32_t    i;
    lucifer_t   config;
    uint8_t     prev_block[BLOCKSIZEB];

    // Setup configuration
    key_setup(&config, key);
    
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
void 
decrypt_ofb(uint8_t * data, uint32_t length, uint8_t * key, uint8_t * iv)
{
    uint32_t    i;
    lucifer_t   config;
    uint8_t     prev_block[BLOCKSIZEB];

    // Setup configuration
    key_setup(&config, key);
    
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
void 
encrypt_pcbc(uint8_t * data, uint32_t length, uint8_t * key, uint8_t * iv)
{
    uint32_t    i;
    lucifer_t   config;
    uint8_t     prev_block[BLOCKSIZEB];
    uint8_t     ptext_block[BLOCKSIZEB];

    // Setup configuration
    key_setup(&config, key);
    
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
void 
decrypt_pcbc(uint8_t * data, uint32_t length, uint8_t * key, uint8_t * iv)
{
    uint32_t    i;
    lucifer_t   config;
    uint8_t     prev_block[BLOCKSIZEB];
    uint8_t     ctext_block[BLOCKSIZEB];

    // Setup configuration
    key_setup(&config, key);
    
    memcpy(prev_block, iv, BLOCKSIZEB);

    for (i = 0; i < length; i += BLOCKSIZEB)
    {
        // Simpan ciphertext untuk dioperasikan dengan block berikutnya.
        memcpy(ctext_block, &data[i], BLOCKSIZEB);

        // Dekripsi ciphertext untuk mendapatkan plaintext ter-XOR
        block_decrypt(&config, &data[i]);

        // XOR dengan block sebelumnya
        // gunakan IV bila ini block pertama
        xor_block(&data[i], &data[i], prev_block);

        // Hitung block berikutnya
        xor_block(prev_block, ctext_block, &data[i]);
    }
}