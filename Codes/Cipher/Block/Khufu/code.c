/*
    Khufu
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

/* ************************* CONFIGURATION & SEED ************************* */
#define BLOCKSIZE       64
#define BLOCKSIZEB      8
#define KEYSIZE         512
#define KEYSIZEB        64
#define ROUNDS          16

#ifdef _MSC_VER
    #include <stdlib.h>
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
        #define BIG_ENDIAN
    #else 
        #define BIG_ENDIAN
    #endif
#endif

#ifdef LITTLE_ENDIAN
    #define convert(x)   bswap32(x)
#else
    #define convert(x)   (x)
#endif




/* ********************* INTERNAL FUNCTIONS PROTOTYPE ********************* */
void block_encrypt(uint8_t * data, uint8_t key[KEYSIZEB]);
void block_decrypt(uint8_t * data, uint8_t key[KEYSIZEB]);

void gen_sbox(uint8_t * sbox, uint8_t * key, uint32_t round);
void feistel(uint8_t L[4], uint8_t R[4], const uint8_t k[4]);


/* ********************* MODE OF OPERATIONS PROTOTYPE ********************* */
/** Electronic Code Book mode **/
void khufu_encrypt_ecb(uint8_t * data, uint32_t length, uint8_t * key);
void khufu_decrypt_ecb(uint8_t * data, uint32_t length, uint8_t * key);

/** Cipher Block Chaining mode **/
void khufu_encrypt_cbc(uint8_t * data, uint32_t length, uint8_t * key, uint8_t * iv);
void khufu_decrypt_cbc(uint8_t * data, uint32_t length, uint8_t * key, uint8_t * iv);

/** Cipher Feedback mode **/
void khufu_encrypt_cfb(uint8_t * data, uint32_t length, uint8_t * key, uint8_t * iv);
void khufu_decrypt_cfb(uint8_t * data, uint32_t length, uint8_t * key, uint8_t * iv);

/** Counter mode **/
void khufu_encrypt_ctr(uint8_t * data, uint32_t length, uint8_t * key, uint8_t * nonce);
void khufu_decrypt_ctr(uint8_t * data, uint32_t length, uint8_t * key, uint8_t * nonce);

/** Output Feedback mode **/
void khufu_encrypt_ofb(uint8_t * data, uint32_t length, uint8_t * key, uint8_t * iv);
void khufu_decrypt_ofb(uint8_t * data, uint32_t length, uint8_t * key, uint8_t * iv);

/** Propagating Cipher Block Chaining mode **/
void khufu_encrypt_pcbc(uint8_t * data, uint32_t length, uint8_t * key, uint8_t * iv);
void khufu_decrypt_pcbc(uint8_t * data, uint32_t length, uint8_t * key, uint8_t * iv);


/* ************************ CRYPTOGRAPHY ALGORITHM ************************ */
/* 
    Enkripsi sebuah block dengan Khufu. 
    Pastikan konfigurasi telah dilakukan dengan memanggil key_setup()
*/
void 
block_encrypt(uint8_t * data, uint8_t key[KEYSIZEB])
{
    uint32_t  * p_data = (uint32_t*)data;
    uint32_t  * p_key  = (uint32_t*)key;
    uint8_t     sbox[256];

    uint32_t    left  = convert(p_data[0]),
                right = convert(p_data[1]),
                temp, round;

    left  ^= convert(p_key[0]);
    right ^= convert(p_key[1]);

    for (round = 0; round < ROUNDS; round++)
    {
        gen_sbox(sbox, key, round);
        
        temp  = left;
        left  = right ^ sbox[left & 0xFF];
        right = rotr(temp, 8);

        temp  = left;
        left  = right;
        right = temp;
    }

    left  ^= convert(p_key[2]);
    right ^= convert(p_key[3]);

    p_data[0] = convert(left);
    p_data[1] = convert(right);
}

/* 
    Dekripsi sebuah block dengan Khufu. 
    Pastikan konfigurasi telah dilakukan dengan memanggil key_setup()
*/
void 
block_decrypt(uint8_t * data, uint8_t key[KEYSIZEB])
{
    uint32_t  * p_data = (uint32_t*)data;
    uint32_t  * p_key  = (uint32_t*)key;
    uint8_t     sbox[256];

    uint32_t    left  = convert(p_data[0]),
                right = convert(p_data[1]),
                temp;
    int32_t     round;

    left  ^= convert(p_key[2]);
    right ^= convert(p_key[3]);

    for (round = ROUNDS - 1; round >= 0; round--)
    {
        gen_sbox(sbox, key, round);

        temp  = right;
        right = left ^ sbox[right & 0xFF];
        left  = rotl(temp, 8);

        temp  = left;
        left  = right;
        right = temp;
    }

    left  ^= convert(p_key[0]);
    right ^= convert(p_key[1]);

    p_data[0] = convert(left);
    p_data[1] = convert(right);
}


/* ******************* INTERNAL FUNCTIONS IMPLEMENTATION ******************* */
void 
gen_sbox(uint8_t * sbox,uint8_t * key, uint32_t round)
{
    uint32_t i;

    for (i = 0; i < 256; i++)
    {
        sbox[i] = 
            (key[(round * 8 + i    ) % KEYSIZEB] << 24) ^
            (key[(round * 8 + i + 1) % KEYSIZEB] << 16) ^
            (key[(round * 8 + i + 2) % KEYSIZEB] << 8) ^
            (key[(round * 8 + i + 3) % KEYSIZEB]);
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
khufu_encrypt_ecb(uint8_t * data, uint32_t length, uint8_t key[KEYSIZEB])
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
khufu_decrypt_ecb(uint8_t * data, uint32_t length, uint8_t * key)
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
khufu_encrypt_cbc(uint8_t * data, uint32_t length, uint8_t * key, uint8_t * iv)
{
    uint32_t   i;
    uint8_t  * prev_block = iv;

    for (i = 0; i < length; i += BLOCKSIZEB)
    {
        // XOR block plaintext dengan block ciphertext sebelumnya
        xor_block(&data[i], &data[i], prev_block);

        // Enkripsi plaintext menjadi ciphertext
        block_encrypt(&data[i], key);

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
khufu_decrypt_cbc(uint8_t * data, uint32_t length, uint8_t * key, uint8_t * iv)
{
    uint32_t   i;
    uint8_t    prev_block[BLOCKSIZEB];
    uint8_t    ctext_block[BLOCKSIZEB];
    
    memcpy(prev_block, iv, BLOCKSIZEB);

    for (i = 0; i < length; i += BLOCKSIZEB)
    {
        // Simpan block ciphertext untuk operasi XOR berikutnya.
        memcpy(ctext_block, &data[i], BLOCKSIZEB);

        // Dekripsi ciphertext menjadi block
        block_decrypt(&data[i], key);

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
khufu_encrypt_cfb(uint8_t * data, uint32_t length, uint8_t * key, uint8_t * iv)
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
khufu_decrypt_cfb(uint8_t * data, uint32_t length, uint8_t * key, uint8_t * iv)
{
    uint32_t   i;
    uint8_t    prev_block[BLOCKSIZEB];
    uint8_t    ctext_block[BLOCKSIZEB];

    memcpy(prev_block, iv, BLOCKSIZEB);

    for (i = 0; i < length; i += BLOCKSIZEB)
    {
        // Simpan block cipher untuk operasi
        memcpy(ctext_block, &data[i], BLOCKSIZEB);

        // Enkripsi block sebelumnya
        // gunakan IV bila ini block pertama
        block_encrypt(prev_block, key);

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
khufu_encrypt_ctr(uint8_t * data, uint32_t length, uint8_t * key, uint8_t *nonce)
{
    uint32_t   i;
    uint8_t    local_nonce[BLOCKSIZEB];
    uint32_t * nonce_counter = (uint32_t*)&local_nonce[BLOCKSIZEB-4];
    
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
khufu_decrypt_ctr(uint8_t * data, uint32_t length, uint8_t * key, uint8_t *nonce)
{
    uint32_t   i;
    uint8_t    local_nonce[BLOCKSIZEB];
    uint32_t * nonce_counter = (uint32_t*)&local_nonce[BLOCKSIZEB-4];
    
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
khufu_encrypt_ofb(uint8_t * data, uint32_t length, uint8_t * key, uint8_t * iv)
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
khufu_decrypt_ofb(uint8_t * data, uint32_t length, uint8_t * key, uint8_t * iv)
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
khufu_encrypt_pcbc(uint8_t * data, uint32_t length, uint8_t * key, uint8_t * iv)
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
        block_encrypt(&data[i], key);

        // Hitung block berikutnya
        xor_block(prev_block, ptext_block, &data[i]);
    }
}

/*
    Dekripsi block data dengan mode OFB.
    Pastikan jumlah block valid.
*/
void 
khufu_decrypt_pcbc(uint8_t * data, uint32_t length, uint8_t * key, uint8_t * iv)
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
    secret key: 64-bytes (512-bit) 
    */
    uint8_t key[64] =
            { 0x52, 0x45, 0x56, 0x45, 0x52, 0x53, 0x49, 0x4E, 0x47, 0x2E, 0x49, 0x44, 
    /* ASCII:   R     E     V     E     R     S     I     N     G     .     I     D  */
              0x53, 0x45, 0x43, 0x52, 0x45, 0x54, 0x20, 0x4b, 0x45, 0x59, 0x31, 0x32,
            /*  S     E     C     R     E     T           K     E     Y     1     2  */
              0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x30, 
            /*  3     4     5     6     7     8     9     0 */
              0x52, 0x45, 0x56, 0x45, 0x52, 0x53, 0x49, 0x4E, 0x47, 0x2E, 0x49, 0x44, 
    /* ASCII:   R     E     V     E     R     S     I     N     G     .     I     D  */
              0x53, 0x45, 0x43, 0x52, 0x45, 0x54, 0x20, 0x4b, 0x45, 0x59, 0x31, 0x32,
            /*  S     E     C     R     E     T           K     E     Y     1     2  */
              0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x30 };
    
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
    khufu_encrypt_ecb(encbuffer, 64, key);       // ECB
    // khufu_encrypt_cbc(encbuffer, 64, key, iv);   // CBC
    // khufu_encrypt_cfb(encbuffer, 64, key, iv);   // CFB
    // khufu_encrypt_ctr(encbuffer, 64, key, iv);   // CTR
    // khufu_encrypt_ofb(encbuffer, 64, key, iv);   // OFB
    // khufu_encrypt_pcbc(encbuffer, 64, key, iv);  // PCBC
    printx("Encrypted:", encbuffer, 64);

    // Dekripsi - block: 128   key: 256
    memcpy(decbuffer, encbuffer, 64);
    khufu_decrypt_ecb(decbuffer, 64, key);       // ECB
    // khufu_decrypt_cbc(decbuffer, 64, key, iv);   // CBC
    // khufu_decrypt_cfb(decbuffer, 64, key, iv);   // CFB
    // khufu_decrypt_ctr(decbuffer, 64, key, iv);   // CTR
    // khufu_decrypt_ofb(decbuffer, 64, key, iv);   // OFB
    // khufu_decrypt_pcbc(decbuffer, 64, key, iv);  // PCBC
    printx("Decrypted:", decbuffer, 64);

    printf("\nFinal: %s\n", decbuffer);

    return 0;
}
