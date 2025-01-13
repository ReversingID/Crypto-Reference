/*
    Treyfer by Gideon Yuval
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

Note:
    - reference paper merekomendasikan 256 bilangan prima pertama sebagai S-Box, dimulai dari 2 (modulo 256)
    - Alternative S-Box adalah dengan shuffle array 256 byte untuk mendapatkan S-Box acak.
*/

#include <stdint.h>
#include <string.h>
#include <stdlib.h>

/* ************************ CONFIGURATION & SEED ************************ */
#define BLOCKSIZE   64
#define BLOCKSIZEB  8
#define KEYSIZE     64
#define KEYSIZEB    8
#define ROUNDS      12
#define SHIFT       1

// ROTL and ROTR for 8-bit
#define rotl(x, n) ((x) << (n) | (x) >> (8 - (n)))
#define rotr(x, n) ((x) >> (n) | (x) << (8 - (n)))


/*
    Membangkitkan S-Box acak
*/ 

static const uint8_t S[256] = {
	//0     1    2      3     4    5     6     7      8    9     A      B    C     D     E     F
    0xbb, 0xd6, 0x2a, 0x48, 0x8e, 0x3f, 0x89, 0x11, 0x18, 0x0b, 0x47, 0x3b, 0x12, 0x16, 0x23, 0xb7, 
    0xa5, 0xc2, 0xd1, 0xd5, 0x88, 0xc8, 0xb3, 0x92, 0x81, 0x4b, 0x7d, 0x64, 0x02, 0xed, 0xe2, 0x2f, 
    0x13, 0xfc, 0xcf, 0x46, 0x37, 0xbf, 0xb0, 0xf1, 0xa6, 0x63, 0xea, 0x97, 0x58, 0xcd, 0x03, 0xfa, 
    0xdd, 0xd3, 0xe9, 0xce, 0x71, 0x41, 0xe3, 0xad, 0x55, 0x99, 0x2b, 0xbe, 0x06, 0x2e, 0xa1, 0x4f, 
    0x56, 0x6b, 0xde, 0x8f, 0x54, 0xe7, 0x95, 0x5c, 0x82, 0x19, 0x2c, 0x8c, 0x04, 0x94, 0x7a, 0x6a, 
    0x57, 0x28, 0xa8, 0x6c, 0xf8, 0xc7, 0xaa, 0xa9, 0x9c, 0x4d, 0xb2, 0xef, 0xb4, 0x21, 0x87, 0x79, 
    0x40, 0x62, 0x10, 0xc6, 0x75, 0xf6, 0x1d, 0xf0, 0x42, 0xe4, 0x0e, 0xbc, 0x1c, 0xcc, 0xd2, 0x0a, 
    0x17, 0xaf, 0x49, 0xdb, 0xff, 0xdf, 0x36, 0xc3, 0x72, 0x3d, 0x7e, 0x9f, 0x4a, 0x7c, 0xf4, 0x8b, 
    0x84, 0x91, 0x51, 0x25, 0xf3, 0x5a, 0x86, 0x00, 0xf9, 0x09, 0x0c, 0xb6, 0x30, 0x6e, 0x6f, 0x15, 
    0xab, 0x5e, 0x07, 0xb1, 0x34, 0xf7, 0xec, 0xc1, 0x43, 0x83, 0xc9, 0x1e, 0xba, 0x93, 0xee, 0x1b, 
    0xc4, 0x20, 0x80, 0x0f, 0x2d, 0xf2, 0xe6, 0x59, 0x8a, 0x6d, 0x7b, 0x9e, 0xe5, 0x38, 0xb8, 0xcb, 
    0x29, 0xc0, 0x3c, 0x61, 0x01, 0x76, 0x85, 0x9a, 0x68, 0xfb, 0x90, 0xfe, 0x5f, 0xb5, 0x60, 0x50, 
    0x70, 0x5d, 0x27, 0xb9, 0x8d, 0x3a, 0xbd, 0xeb, 0x44, 0x9d, 0xac, 0x73, 0xd0, 0x22, 0x1a, 0xe1, 
    0xa4, 0x77, 0xe8, 0x9b, 0x45, 0x05, 0xfd, 0x33, 0x24, 0x1f, 0x5b, 0xf5, 0x39, 0xa0, 0xa3, 0x66, 
    0x08, 0x31, 0x67, 0x65, 0xda, 0xd9, 0xa2, 0xd7, 0x26, 0xca, 0x98, 0x35, 0x53, 0xd4, 0x0d, 0x4e, 
    0x69, 0x3e, 0x4c, 0xae, 0xe0, 0x32, 0x7f, 0x78, 0xa7, 0x52, 0x14, 0x96, 0xdc, 0x74, 0xc5, 0xd8,
};


/* ********************* INTERNAL FUNCTIONS PROTOTYPE ********************* */
void block_encrypt(uint8_t * data, const uint8_t * key);
void block_decrypt(uint8_t * data, const uint8_t * key);

void treyfer_crypt(uint8_t * data, const uint8_t * key);


/* ********************* MODE OF OPERATIONS PROTOTYPE ********************* */
/** Electronic Code Book mode **/
void treyfer_encrypt_ecb(uint8_t * data, uint32_t length, uint8_t * key);
void treyfer_decrypt_ecb(uint8_t * data, uint32_t length, uint8_t * key);

/** Cipher Block Chaining mode **/
void treyfer_encrypt_cbc(uint8_t * data, uint32_t length, uint8_t * key, uint8_t * iv);
void treyfer_decrypt_cbc(uint8_t * data, uint32_t length, uint8_t * key, uint8_t * iv);

/** Cipher Feedback mode **/
void treyfer_encrypt_cfb(uint8_t * data, uint32_t length, uint8_t * key, uint8_t * iv);
void treyfer_decrypt_cfb(uint8_t * data, uint32_t length, uint8_t * key, uint8_t * iv);

/** Counter mode **/
void treyfer_encrypt_ctr(uint8_t * data, uint32_t length, uint8_t * key, uint8_t * nonce);
void treyfer_decrypt_ctr(uint8_t * data, uint32_t length, uint8_t * key, uint8_t * nonce);

/** Output Feedback mode **/
void treyfer_encrypt_ofb(uint8_t * data, uint32_t length, uint8_t * key, uint8_t * iv);
void treyfer_decrypt_ofb(uint8_t * data, uint32_t length, uint8_t * key, uint8_t * iv);

/** Propagating Cipher Block Chaining mode **/
void treyfer_encrypt_pcbc(uint8_t * data, uint32_t length, uint8_t * key, uint8_t * iv);
void treyfer_decrypt_pcbc(uint8_t * data, uint32_t length, uint8_t * key, uint8_t * iv);


/* ************************ CRYPTOGRAPHY ALGORITHM ************************ */
/*
    Enkripsi sebuah block dengan Treyfer.
*/
#include <stdio.h>
void 
block_encrypt (uint8_t * val, const uint8_t * key)
{
    size_t   i, j;
    uint8_t  t = val[0];

    for (j = 0; j < ROUNDS; j++)
    {
        for (i = 0; i < BLOCKSIZEB; i++)
        {
            t = t + key[i];

            // printf("t: %d | key[%d]: %d | S[%d]: %d\n", t, j, key[j], t, S[t]);
            t = S[t] + val[(i + 1) % BLOCKSIZEB];
            t = rotl(t, SHIFT);

            val[(i + 1) % BLOCKSIZEB] = t;
        }
    }
}

/*
    Dekripsi sebuah block dengan Treyfer
*/
void
block_decrypt (uint8_t * val, const uint8_t * key)
{
    size_t   i, j;
    uint8_t  top, bottom;

    for (j = 0; j < ROUNDS; j++)
    {
        for (i = BLOCKSIZEB; i > 0; i--)
        {
            top = val[i - 1] + key[i - 1];
            top = S[top];

            bottom = val[i % BLOCKSIZEB];
            bottom = rotr(bottom, SHIFT);

            val[i % BLOCKSIZEB] = bottom - top;
        }
    }
}


/* ******************* INTERNAL FUNCTIONS IMPLEMENTATION ******************* */


/* *************************** HELPER FUNCTIONS *************************** */
/* Xor 2 block data */
void 
xor_block(uint8_t * dst, const uint8_t * src1, const uint8_t * src2)
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
treyfer_encrypt_ecb(uint8_t * data, uint32_t length, uint8_t * key)
{
    uint32_t   i;

    for (i = 0; i < length; i += BLOCKSIZEB)
        block_encrypt(&data[i], key);
}

/*
    Dekripsi block data dengan mode ECB.
    Dekripsi diberlakukan secara independen tanpa ada hubungan dengan block
    sebelum dan berikutnya.
    Pastikan jumlah block valid.
*/
void 
treyfer_decrypt_ecb(uint8_t * data, uint32_t length, uint8_t * key)
{
    uint32_t   i;

    for(i = 0; i < length; i += BLOCKSIZEB)
        block_decrypt(&data[i], key);
}


/*
    Enkripsi block data dengan mode CBC.
    Sebelum enkripsi, plaintext akan di-XOR dengan block sebelumnya.
    Pastikan jumlah block valid.
*/
void 
treyfer_encrypt_cbc(uint8_t * data, uint32_t length, uint8_t * key, uint8_t * iv)
{
    uint32_t   i;
    uint8_t  * prev_block = iv;

    for (i = 0; i < length; i += BLOCKSIZEB)
    {
        // XOR block plaintext dengan block ciphertext sebelumnya
        xor_block(&data[i], &data[i], prev_block);

        // Enkripsi plaintext menjadi ciphertext
        block_encrypt(&data[i], key);;

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
treyfer_decrypt_cbc(uint8_t * data, uint32_t length, uint8_t * key, uint8_t * iv)
{
    uint32_t   i;
    uint8_t    prev_block[BLOCKSIZEB];
    uint8_t    cipher_block[BLOCKSIZEB];
    
    memcpy(prev_block, iv, BLOCKSIZEB);

    for (i = 0; i < length; i += BLOCKSIZEB)
    {
        // Simpan block ciphertext untuk operasi XOR berikutnya.
        memcpy(cipher_block, &data[i], BLOCKSIZEB);

        // Dekripsi ciphertext menjadi block
        block_decrypt(&data[i], key);

        // XOR block block dengan block ciphertext sebelumnya
        // gunakan IV bila ini adalah block pertama
        xor_block(&data[i], &data[i], prev_block);

        // Pindahkan block ciphertext yang telah disimpan
        memcpy(prev_block, cipher_block, BLOCKSIZEB);
    }
}


/*
    Enkripsi block data dengan mode CFB.
    Pastikan jumlah block valid.
*/
void 
treyfer_encrypt_cfb(uint8_t * data, uint32_t length, uint8_t * key, uint8_t * iv)
{
    uint32_t   i;
    uint8_t    prev_block[BLOCKSIZEB];

    memcpy(prev_block, iv, BLOCKSIZEB);

    for (i = 0; i < length; i += BLOCKSIZEB)
    {
        // Enkripsi block sebelumnya
        // gunakan IV bila ini block pertama
        block_encrypt(prev_block, key);

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
treyfer_decrypt_cfb(uint8_t * data, uint32_t length, uint8_t * key, uint8_t * iv)
{
    uint32_t   i;
    uint8_t    prev_block[BLOCKSIZEB];
    uint8_t    cipher_block[BLOCKSIZEB];

    memcpy(prev_block, iv, BLOCKSIZEB);

    for (i = 0; i < length; i += BLOCKSIZEB)
    {
        // Simpan block cipher untuk operasi
        memcpy(cipher_block, &data[i], BLOCKSIZEB);

        // Enkripsi block sebelumnya
        // gunakan IV bila ini block pertama
        block_encrypt(prev_block, key);

        // XOR dengan plaintext untuk mendapatkan ciphertext
        xor_block(&data[i], &data[i], prev_block);

        // Simpan block ciphertext untuk operasi XOR berikutnya
        memcpy(prev_block, cipher_block, BLOCKSIZEB);
    }
}

/*
    Enkripsi block data dengan mode CTR.
    Pastikan jumlah block valid.
*/
void 
treyfer_encrypt_ctr(uint8_t * data, uint32_t length, uint8_t * key, uint8_t *nonce)
{
    uint32_t   i;
    uint8_t    local_nonce[16];
    uint32_t * nonce_counter = (uint32_t*)&local_nonce[12];
    
    memcpy(local_nonce, nonce, BLOCKSIZEB);

    for (i = 0; i < length; i += BLOCKSIZEB)
    {
        // Enkripsi nonce + counter
        block_encrypt(local_nonce, key);

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
treyfer_decrypt_ctr(uint8_t * data, uint32_t length, uint8_t * key, uint8_t *nonce)
{
    uint32_t   i;
    uint8_t    local_nonce[16];
    uint32_t * nonce_counter = (uint32_t*)&local_nonce[12];
    
    memcpy(local_nonce, nonce, BLOCKSIZEB);

    for (i = 0; i < length; i += BLOCKSIZEB)
    {
        // Enkripsi nonce + counter
        block_encrypt(local_nonce, key);

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
treyfer_encrypt_ofb(uint8_t * data, uint32_t length, uint8_t * key, uint8_t * iv)
{
    uint32_t   i;
    uint8_t    prev_block[BLOCKSIZEB];
    
    memcpy(prev_block, iv, BLOCKSIZEB);
    
    for (i = 0; i < length; i += BLOCKSIZEB)
    {
        // Enkripsi block sebelumnya 
        // gunakan IV bila ini block pertama
        block_encrypt(prev_block, key);

        // XOR plaintext dengan output dari enkripsi untuk mendapatkan ciphertext.
        xor_block(&data[i], &data[i], prev_block);
    }
}

/*
    Dekripsi block data dengan mode OFB.
    Pastikan jumlah block valid.
*/
void 
treyfer_decrypt_ofb(uint8_t * data, uint32_t length, uint8_t * key, uint8_t * iv)
{
    uint32_t   i;
    uint8_t    prev_block[BLOCKSIZEB];
    
    memcpy(prev_block, iv, BLOCKSIZEB);
    
    for (i = 0; i < length; i += BLOCKSIZEB)
    {
        // Enkripsi block sebelumnya 
        // gunakan IV bila ini block pertama
        block_encrypt(prev_block, key);

        // XOR plaintext dengan output dari enkripsi untuk mendapatkan ciphertext.
        xor_block(&data[i], &data[i], prev_block);
    }
}


/*
    Enkripsi block data dengan mode OFB.
    Pastikan jumlah block valid.
*/
void 
treyfer_encrypt_pcbc(uint8_t * data, uint32_t length, uint8_t * key, uint8_t * iv)
{
    uint32_t   i;
    uint8_t    prev_block[BLOCKSIZEB];
    uint8_t    ptext_block[BLOCKSIZEB];
    
    memcpy(prev_block, iv, BLOCKSIZEB);

    for (i = 0; i < length; i += BLOCKSIZEB)
    {
        // Simpan plaintext untuk dioperasikan dengan block berikutnya.
        memcpy(ptext_block, &data[i], BLOCKSIZEB);

        // XOR plaintext dengan block sebelumnya
        // gunakan IV bila ini block pertama
        xor_block(&data[i], &data[i], prev_block);

        // Enkripsi
        block_encrypt(&data[i], key);;

        // Hitung block berikutnya
        xor_block(prev_block, ptext_block, &data[i]);
    }
}

/*
    Dekripsi block data dengan mode OFB.
    Pastikan jumlah block valid.
*/
void 
treyfer_decrypt_pcbc(uint8_t * data, uint32_t length, uint8_t * key, uint8_t * iv)
{
    uint32_t   i;
    uint8_t    prev_block[BLOCKSIZEB];
    uint8_t    ctext_block[BLOCKSIZEB];
    
    memcpy(prev_block, iv, BLOCKSIZEB);

    for (i = 0; i < length; i += BLOCKSIZEB)
    {
        // Simpan ciphertext untuk dioperasikan dengan block berikutnya.
        memcpy(ctext_block, &data[i], BLOCKSIZEB);

        // Dekripsi ciphertext untuk mendapatkan plaintext ter-XOR
        block_decrypt(&data[i], key);

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
    initialization vector: 16-bytes
    namun hanya 8-byte yang digunakan, sesuai ukuran block
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

    Tiap block berukuran 64-bit.
    Data 64-byte menghasilkan 8 block data masing-masing 8-byte.
    */
    memset(encbuffer, 0, sizeof(encbuffer));
    memset(decbuffer, 0, sizeof(decbuffer));

    // Enkripsi - block: 64   key: 64
    memcpy(encbuffer, data, length);
    treyfer_encrypt_ecb(encbuffer, 48, key);       // ECB
    // treyfer_encrypt_cbc(encbuffer, 48, key, iv);   // CBC
    // treyfer_encrypt_cfb(encbuffer, 48, key, iv);   // CFB
    // treyfer_encrypt_ctr(encbuffer, 48, key, iv);   // CTR
    // treyfer_encrypt_ofb(encbuffer, 48, key, iv);   // OFB
    // treyfer_encrypt_pcbc(encbuffer, 48, key, iv);  // PCBC
    printx("Encrypted:", encbuffer, 48);

    // Dekripsi - block: 128   key: 256
    memcpy(decbuffer, encbuffer, 48);
    treyfer_decrypt_ecb(decbuffer, 48, key);       // ECB
    // treyfer_decrypt_cbc(decbuffer, 48, key, iv);   // CBC
    // treyfer_decrypt_cfb(decbuffer, 48, key, iv);   // CFB
    // treyfer_decrypt_ctr(decbuffer, 48, key, iv);   // CTR
    // treyfer_decrypt_ofb(decbuffer, 48, key, iv);   // OFB
    // treyfer_decrypt_pcbc(decbuffer, 48, key, iv);  // PCBC
    printx("Decrypted:", decbuffer, 48);

    printf("\nFinal: %s\n", decbuffer);

    return 0;
}


