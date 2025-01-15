/*
    LEA by Deukjo Hong, Jung-Keun Lee, Dong-Chan Kim, Daesung Kwon, Kwon Ho Ryu, Dong-Geon Lee
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
#include <string.h>
#include <stdio.h>

/* ************************* CONFIGURATION & SEED ************************* */
#define BLOCKSIZE       128
#define BLOCKSIZEB      16
#define KEYSIZE         128
#define KEYSIZEB        16

#ifdef _MSC_VER
    #pragma intrinsic(_lrotr,_lrotl)
    #define rotr(x,n)   _lrotr(x,n)
    #define rotl(x,n)   _lrotl(x,n)
#else 
    #define rotr(x,n)   (((x) >> ((int)(n))) | ((x) << (32 - (int)(n))))
    #define rotl(x,n)   (((x) << ((int)(n))) | ((x) >> (32 - (int)(n))))
#endif

#define bswap32(x)      (rotl(x,8) & 0x00FF00FF | rotr(x, 8) & 0xFF00FF00)



const uint32_t delta[8] = {
    0xc3efe9db, 0x44626b02, 0x79e27c8a, 0x78df30ec,
    0x715ea49e, 0xc785da0a, 0xe04ef22a, 0xe5c40957
};


/* context and configuration */
typedef struct 
{
    uint32_t bits;
    uint32_t rounds;
    uint32_t rkeys[256];
} lea_t;


/* ********************* INTERNAL FUNCTIONS PROTOTYPE ********************* */
void block_encrypt(lea_t * config, uint8_t * val);
void block_decrypt(lea_t * config, uint8_t * val);
void key_setup(lea_t * config, uint8_t * secret, uint32_t bits);


/* ********************* MODE OF OPERATIONS PROTOTYPE ********************* */
/** Electronic Code Book mode **/
void lea_encrypt_ecb(uint8_t * data, uint32_t length, uint8_t * key);
void lea_decrypt_ecb(uint8_t * data, uint32_t length, uint8_t * key);

/** Cipher Block Chaining mode **/
void lea_encrypt_cbc(uint8_t * data, uint32_t length, uint8_t * key, uint8_t * iv);
void lea_decrypt_cbc(uint8_t * data, uint32_t length, uint8_t * key, uint8_t * iv);

/** Cipher Feedback mode **/
void lea_encrypt_cfb(uint8_t * data, uint32_t length, uint8_t * key, uint8_t * iv);
void lea_decrypt_cfb(uint8_t * data, uint32_t length, uint8_t * key, uint8_t * iv);

/** Counter mode **/
void lea_encrypt_ctr(uint8_t * data, uint32_t length, uint8_t * key, uint8_t *nonce);
void lea_decrypt_ctr(uint8_t * data, uint32_t length, uint8_t * key, uint8_t *nonce);

/** Output Feedback mode **/
void lea_encrypt_ofb(uint8_t * data, uint32_t length, uint8_t * key, uint8_t * iv);
void lea_decrypt_ofb(uint8_t * data, uint32_t length, uint8_t * key, uint8_t * iv);

/** Propagating Cipher Block Chaining mode **/
void lea_encrypt_pcbc(uint8_t * data, uint32_t length, uint8_t * key, uint8_t * iv);
void lea_decrypt_pcbc(uint8_t * data, uint32_t length, uint8_t * key, uint8_t * iv);


/* ************************ CRYPTOGRAPHY ALGORITHM ************************ */
/* 
    Enkripsi sebuah block dengan LEA. 
    Pastikan konfigurasi telah dilakukan dengan memanggil key_setup()
*/
void 
block_encrypt(lea_t * config, uint8_t * val)
{
    // block: 32 * 4 = 128 bit
    uint32_t * rkeys  = config->rkeys;
    uint32_t   rounds = config->rounds;
    uint32_t   current[4], next[4];
    size_t     idx;

    memcpy(current, val, 16);

    for (idx = 0; idx < rounds; idx++)
    {
        next[0] = rotl((current[0] ^ rkeys[idx * 6    ]) + (current[1] ^ rkeys[idx * 6 + 1]), 9);
		next[1] = rotr((current[1] ^ rkeys[idx * 6 + 2]) + (current[2] ^ rkeys[idx * 6 + 3]), 5);
		next[2] = rotr((current[2] ^ rkeys[idx * 6 + 4]) + (current[3] ^ rkeys[idx * 6 + 5]), 3);
		next[3] = current[0];

        memcpy(current, next, 16);
    }

    memcpy(val, next, 16);
}

/* 
    Dekripsi sebuah block dengan LEA. 
    Pastikan konfigurasi telah dilakukan dengan memanggil key_setup()
*/
void 
block_decrypt(lea_t * config, uint8_t * val)
{
    // block: 32 * 4 = 128 bit
    uint32_t * rkeys  = config->rkeys;
    uint32_t   rounds = config->rounds;
    uint32_t   current[4], next[4];
    size_t     idx;

    memcpy(current, val, 16);

    for (idx = 0; idx < rounds; idx++)
    {
        next[0] = current[3];
        next[1] = (rotr(current[0], 9) - (next[0] ^ rkeys[((rounds - idx - 1) * 6)    ])) ^ rkeys[((rounds - idx - 1) * 6) + 1];
		next[2] = (rotl(current[1], 5) - (next[1] ^ rkeys[((rounds - idx - 1) * 6) + 2])) ^ rkeys[((rounds - idx - 1) * 6) + 3];
		next[3] = (rotl(current[2], 3) - (next[2] ^ rkeys[((rounds - idx - 1) * 6) + 4])) ^ rkeys[((rounds - idx - 1) * 6) + 5];

        memcpy(current, next, 16);
    }

    memcpy(val, current, 16);
}


/* ******************* INTERNAL FUNCTIONS IMPLEMENTATION ******************* */
void 
key_setup(lea_t * config, uint8_t * secret, uint32_t bits)
{
    uint32_t   T[8];
    size_t     idx;

    config->bits = bits;
    memcpy(T, secret, config->bits / 8);
    memset(config->rkeys, 0, sizeof(config->rkeys));

    // generate round keys
    if (config->bits == 128)
    {
        config->rounds = 24;
        for (idx = 0; idx < config->rounds; idx++)
        {
            T[0] = rotl(T[0] + rotl(idx    , delta[idx % 4]),  1);
            T[1] = rotl(T[1] + rotl(idx + 1, delta[idx % 4]),  3);
            T[2] = rotl(T[2] + rotl(idx + 2, delta[idx % 4]),  6);
            T[3] = rotl(T[3] + rotl(idx + 3, delta[idx % 4]), 11);

            config->rkeys[idx * 6    ] = T[0];
            config->rkeys[idx * 6 + 1] = T[1];
            config->rkeys[idx * 6 + 2] = T[2];
            config->rkeys[idx * 6 + 3] = T[1];
            config->rkeys[idx * 6 + 4] = T[3];
            config->rkeys[idx * 6 + 5] = T[1];
        }
    }
    else if (config->bits == 192)
    {
        config->rounds = 28;
        for (idx = 0; idx < config->rounds; idx ++)
        {
            T[0] = rotl(T[0] + rotl(idx    , delta[idx % 6]),  1);
            T[1] = rotl(T[1] + rotl(idx + 1, delta[idx % 6]),  3);
            T[2] = rotl(T[2] + rotl(idx + 2, delta[idx % 6]),  6);
            T[3] = rotl(T[3] + rotl(idx + 3, delta[idx % 6]), 11);
            T[4] = rotl(T[4] + rotl(idx + 4, delta[idx % 6]), 13);
            T[5] = rotl(T[5] + rotl(idx + 5, delta[idx % 6]), 17);
            
            config->rkeys[idx * 6    ] = T[0];
            config->rkeys[idx * 6 + 1] = T[1];
            config->rkeys[idx * 6 + 2] = T[2];
            config->rkeys[idx * 6 + 3] = T[3];
            config->rkeys[idx * 6 + 4] = T[4];
            config->rkeys[idx * 6 + 5] = T[5];
        
        }
    }
    else if (config->bits == 256)
    {
        config->rounds = 32;
        for (idx = 0; idx < config->rounds; idx++)
        {
            T[(6 * idx    ) % 8] =rotl(T[(6 * idx    ) % 8] + rotl(idx    , delta[idx % 8]),  1);
            T[(6 * idx + 1) % 8] =rotl(T[(6 * idx + 1) % 8] + rotl(idx + 1, delta[idx % 8]),  3);
            T[(6 * idx + 2) % 8] =rotl(T[(6 * idx + 2) % 8] + rotl(idx + 2, delta[idx % 8]),  6);
            T[(6 * idx + 3) % 8] =rotl(T[(6 * idx + 3) % 8] + rotl(idx + 3, delta[idx % 8]), 11);
            T[(6 * idx + 4) % 8] =rotl(T[(6 * idx + 4) % 8] + rotl(idx + 4, delta[idx % 8]), 13);
            T[(6 * idx + 5) % 8] =rotl(T[(6 * idx + 5) % 8] + rotl(idx + 5, delta[idx % 8]), 17);
            
            config->rkeys[idx * 6    ] = T[(idx * 6    ) % 8];
            config->rkeys[idx * 6 + 1] = T[(idx * 6 + 1) % 8];
            config->rkeys[idx * 6 + 2] = T[(idx * 6 + 2) % 8];
            config->rkeys[idx * 6 + 3] = T[(idx * 6 + 3) % 8];
            config->rkeys[idx * 6 + 4] = T[(idx * 6 + 4) % 8];
            config->rkeys[idx * 6 + 5] = T[(idx * 6 + 5) % 8];
        }
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
lea_encrypt_ecb(uint8_t * data, uint32_t length, uint8_t * key)
{
    uint32_t i;
    lea_t    config;

    // Setup configuration
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
void 
lea_decrypt_ecb(uint8_t * data, uint32_t length, uint8_t * key)
{
    uint32_t i;
    lea_t    config;

    // Setup configuration
    key_setup(&config, key, KEYSIZE);

    for(i = 0; i < length; i += BLOCKSIZEB)
        block_decrypt(&config, &data[i]);
}


/*
    Enkripsi block data dengan mode CBC.
    Sebelum enkripsi, plaintext akan di-XOR dengan block sebelumnya.
    Pastikan jumlah block valid.
*/
void 
lea_encrypt_cbc(uint8_t * data, uint32_t length, uint8_t * key, uint8_t * iv)
{
    uint32_t   i;
    lea_t      config;
    uint8_t  * prev_block = iv;

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
void 
lea_decrypt_cbc(uint8_t * data, uint32_t length, uint8_t * key, uint8_t * iv)
{
    uint32_t i;
    lea_t    config;
    uint8_t  prev_block[BLOCKSIZEB];
    uint8_t  ctext_block[BLOCKSIZEB];

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
void 
lea_encrypt_cfb(uint8_t * data, uint32_t length, uint8_t * key, uint8_t * iv)
{
    uint32_t i;
    lea_t    config;
    uint8_t  prev_block[BLOCKSIZEB];

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
void 
lea_decrypt_cfb(uint8_t * data, uint32_t length, uint8_t * key, uint8_t * iv)
{
    uint32_t i;
    lea_t    config;
    uint8_t  prev_block[BLOCKSIZEB];
    uint8_t  ctext_block[BLOCKSIZEB];

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
void 
lea_encrypt_ctr(uint8_t * data, uint32_t length, uint8_t * key, uint8_t *nonce)
{
    uint32_t   i;
    lea_t      config;
    uint8_t    local_nonce[BLOCKSIZEB];
    uint32_t * nonce_counter = (uint32_t*)&local_nonce[BLOCKSIZEB-4];

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
void 
lea_decrypt_ctr(uint8_t * data, uint32_t length, uint8_t * key, uint8_t *nonce)
{
    uint32_t   i;
    lea_t      config;
    uint8_t    local_nonce[BLOCKSIZEB];
    uint32_t * nonce_counter = (uint32_t*)&local_nonce[BLOCKSIZEB-4];

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
void 
lea_encrypt_ofb(uint8_t * data, uint32_t length, uint8_t * key, uint8_t * iv)
{
    uint32_t i;
    lea_t    config;
    uint8_t  prev_block[BLOCKSIZEB];

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
void 
lea_decrypt_ofb(uint8_t * data, uint32_t length, uint8_t * key, uint8_t * iv)
{
    uint32_t i;
    lea_t    config;
    uint8_t  prev_block[BLOCKSIZEB];

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
void 
lea_encrypt_pcbc(uint8_t * data, uint32_t length, uint8_t * key, uint8_t * iv)
{
    uint32_t i;
    lea_t    config;
    uint8_t  prev_block[BLOCKSIZEB];
    uint8_t  ptext_block[BLOCKSIZEB];

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
void 
lea_decrypt_pcbc(uint8_t * data, uint32_t length, uint8_t * key, uint8_t * iv)
{
    uint32_t i;
    lea_t    config;
    uint8_t  prev_block[BLOCKSIZEB];
    uint8_t  ctext_block[BLOCKSIZEB];

    // Setup configuration
    key_setup(&config, key, KEYSIZE);
    
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
            { 0x13, 0x51, 0x00, 0x30, 0xD7, 0xA4, 0xC5, 0xAE, 0xCB, 0x55, 0xA7, 0x1C,
              0x25, 0x3F, 0x41, 0x4D };

    length = strlen(data);
    printf("Length: %zd - Buffer: %s\n", strlen(data), data);
    printx("Original", data, length);

    /*
    Panjang plaintext: 44
    Karena block cipher mensyaratkan bahwa data harus merupakan kelipatan dari ukuran 
    block, maka harus ada padding agar panjang data mencapai kelipatan block.

    Tiap block berukuran 128-bit.
    Data 64-byte menghasilkan 4 block data masing-masing 16-byte.
    */
    memset(encbuffer, 0, sizeof(encbuffer));
    memset(decbuffer, 0, sizeof(decbuffer));

    // Enkripsi - block: 128   key: 256
    memcpy(encbuffer, data, length);
    lea_encrypt_ecb(encbuffer, 64, key);       // ECB
    // lea_encrypt_cbc(encbuffer, 64, key, iv);   // CBC
    // lea_encrypt_cfb(encbuffer, 64, key, iv);   // CFB
    // lea_encrypt_ctr(encbuffer, 64, key, iv);   // CTR
    // lea_encrypt_ofb(encbuffer, 64, key, iv);   // OFB
    // lea_encrypt_pcbc(encbuffer, 64, key, iv);  // PCBC
    printx("Encrypted:", encbuffer, 64);

    // Dekripsi - block: 128   key: 256
    memcpy(decbuffer, encbuffer, 64);
    lea_decrypt_ecb(decbuffer, 64, key);       // ECB
    // lea_decrypt_cbc(decbuffer, 64, key, iv);   // CBC
    // lea_decrypt_cfb(decbuffer, 64, key, iv);   // CFB
    // lea_decrypt_ctr(decbuffer, 64, key, iv);   // CTR
    // lea_decrypt_ofb(decbuffer, 64, key, iv);   // OFB
    // lea_decrypt_pcbc(decbuffer, 64, key, iv);  // PCBC
    printx("Decrypted:", decbuffer, 64);

    printf("\nFinal: %s\n", decbuffer);

    return 0;
}
