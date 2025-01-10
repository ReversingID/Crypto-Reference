/*
    3-Way by John Daemen
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
#include <stdlib.h>

/* ************************* CONFIGURATION & SEED ************************* */
#define BLOCKSIZE       96
#define BLOCKSIZEB      12
#define KEYSIZE         96
#define KEYSIZEB        12
#define ROUNDS          11

#define STRT_E          0x0b0b      /* constant for first encryption round */ 
#define STRT_D          0xb1b1      /* constant for first decryption round */

#ifdef _MSC_VER
    #pragma intrinsic(_lrotr,_lrotl)
    #define rotr(x,n)   _lrotr(x,n)
    #define rotl(x,n)   _lrotl(x,n)
#else 
    #define rotr(x,n)   (((x) >> ((int)(n))) | ((x) << (32 - (int)(n))))
    #define rotl(x,n)   (((x) << ((int)(n))) | ((x) >> (32 - (int)(n))))
#endif

#define bswap32(x)      (rotl(x,8) & 0x00FF00FF | rotr(x, 8) & 0xFF00FF00)

#ifdef _MSC_VER
    #define LITTLE_ENDIAN
#elif defined(__BYTE_ORDER__) && (__BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__)
    #define LITTLE_ENDIAN 
#elif defined(__BYTE_ORDER__) && (__BYTE_ORDER__ == __ORDER_BIG_ENDIAN__)
    #define BIG_ENDIAN
#else 
    #define BIG_ENDIAN
#endif


/* ********************* INTERNAL FUNCTIONS PROTOTYPE ********************* */
void block_encrypt(uint8_t * data, uint8_t * key);
void block_decrypt(uint8_t * data, uint8_t * key);

void mu(uint32_t * data);
void gamma(uint32_t * data);
void theta(uint32_t * data);
void rho(uint32_t * data);

void pi_1(uint32_t * data);
void pi_2(uint32_t * data);

void rndcon_gen(uint32_t start, uint32_t *rtab);


/* ********************* MODE OF OPERATIONS PROTOTYPE ********************* */
/** Electronic Code Book mode **/
void threeway_encrypt_ecb(uint8_t * data, uint32_t length, uint8_t * key);
void threeway_decrypt_ecb(uint8_t * data, uint32_t length, uint8_t * key);

/** Cipher Block Chaining mode **/
void threeway_encrypt_cbc(uint8_t * data, uint32_t length, uint8_t * key, uint8_t * iv);
void threeway_decrypt_cbc(uint8_t * data, uint32_t length, uint8_t * key, uint8_t * iv);

/** Cipher Feedback mode **/
void threeway_encrypt_cfb(uint8_t * data, uint32_t length, uint8_t * key, uint8_t * iv);
void threeway_decrypt_cfb(uint8_t * data, uint32_t length, uint8_t * key, uint8_t * iv);

/** Counter mode **/
void threeway_encrypt_ctr(uint8_t * data, uint32_t length, uint8_t * key, uint8_t *nonce);
void threeway_decrypt_ctr(uint8_t * data, uint32_t length, uint8_t * key, uint8_t *nonce);

/** Output Feedback mode **/
void threeway_encrypt_ofb(uint8_t * data, uint32_t length, uint8_t * key, uint8_t * iv);
void threeway_decrypt_ofb(uint8_t * data, uint32_t length, uint8_t * key, uint8_t * iv);

/** Propagating Cipher Block Chaining mode **/
void threeway_encrypt_pcbc(uint8_t * data, uint32_t length, uint8_t * key, uint8_t * iv);
void threeway_decrypt_pcbc(uint8_t * data, uint32_t length, uint8_t * key, uint8_t * iv);


/* ************************ CRYPTOGRAPHY ALGORITHM ************************ */
/* 
    Enkripsi sebuah block dengan 3-Way. 
    Data direpresentasikan sebagai 3 integer 32-bit.
*/
void 
block_encrypt(uint8_t * data, uint8_t * key)
{
    uint32_t i;
    uint32_t rcon[ROUNDS + 1];
    uint32_t _data[3], _key[3];

    uint32_t * p_data = (uint32_t*)data;
    uint32_t * p_key  = (uint32_t*)key;

#ifdef LITTLE_ENDIAN
    for (i = 0; i < 3; i++)
    {
        _data[i] = bswap32(p_data[i]);
        _key[i]  = bswap32(p_key[i]);
    }
#else 
    for (i = 0; i < 3; i++)
    {
        _data[i] = p_data[i];
        _key[i]  = p_key[i];
    }
#endif 

    rndcon_gen(STRT_E, rcon);
    for (i = 0; i < ROUNDS; i++)
    {
        _data[0] ^= _key[0] ^ (rcon[i] << 16);
        _data[1] ^= _key[1];
        _data[2] ^= _key[2] ^ rcon[i];
        rho(_data);
    }

    _data[0] ^= _key[0] ^ (rcon[ROUNDS] << 16);
    _data[1] ^= _key[1];
    _data[2] ^= _key[2] ^ rcon[ROUNDS];
    theta(_data);

#ifdef LITTLE_ENDIAN
    for (i = 0; i < 3; i++)
        p_data[i] = bswap32(_data[i]);
#else 
    for (i = 0; i < 3; i++)
        p_data[i] = _data[i];
#endif 
}


/* 
    Dekripsi sebuah block dengan 3-Way. 
    Pastikan konfigurasi telah dilakukan dengan memanggil key_setup()
*/
void 
block_decrypt(uint8_t * data, uint8_t * key)
{
    uint32_t i;
    uint32_t rcon[ROUNDS + 1];
    uint32_t _data[3], _key[3];

    uint32_t * p_data = (uint32_t*)data;
    uint32_t * p_key  = (uint32_t*)key;

#ifdef LITTLE_ENDIAN
    for (i = 0; i < 3; i++)
    {
        _data[i] = bswap32(p_data[i]);
        _key[i]  = bswap32(p_key[i]);
    }
#else 
    for (i = 0; i < 3; i++)
    {
        _data[i] = p_data[i];
        _key[i]  = p_key[i];
    }
#endif 

    theta(_key);
    mu(_key);
    mu(_data);

    rndcon_gen(STRT_D, rcon);
    for (i = 0; i < ROUNDS; i++)
    {
        _data[0] ^= _key[0] ^ (rcon[i] << 16);
        _data[1] ^= _key[1];
        _data[2] ^= _key[2] ^ rcon[i];
        rho(_data);
    }

    _data[0] ^= _key[0] ^ (rcon[ROUNDS] << 16);
    _data[1] ^= _key[1];
    _data[2] ^= _key[2] ^ rcon[ROUNDS];
    theta(_data);
    mu(_data);

#ifdef LITTLE_ENDIAN
    for (i = 0; i < 3; i++)
        p_data[i] = bswap32(_data[i]);
#else 
    for (i = 0; i < 3; i++)
        p_data[i] = _data[i];
#endif 
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
threeway_encrypt_ecb(uint8_t * data, uint32_t length, uint8_t * key)
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
threeway_decrypt_ecb(uint8_t * data, uint32_t length, uint8_t * key)
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
threeway_encrypt_cbc(uint8_t * data, uint32_t length, uint8_t * key, uint8_t * iv)
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
threeway_decrypt_cbc(uint8_t * data, uint32_t length, uint8_t * key, uint8_t * iv)
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
threeway_encrypt_cfb(uint8_t * data, uint32_t length, uint8_t * key, uint8_t * iv)
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
threeway_decrypt_cfb(uint8_t * data, uint32_t length, uint8_t * key, uint8_t * iv)
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
threeway_encrypt_ctr(uint8_t * data, uint32_t length, uint8_t * key, uint8_t *nonce)
{
    uint32_t   i;
    uint8_t    local_nonce[BLOCKSIZEB];
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
threeway_decrypt_ctr(uint8_t * data, uint32_t length, uint8_t * key, uint8_t *nonce)
{
    uint32_t   i;
    uint8_t    local_nonce[BLOCKSIZEB];
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
threeway_encrypt_ofb(uint8_t * data, uint32_t length, uint8_t * key, uint8_t * iv)
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
threeway_decrypt_ofb(uint8_t * data, uint32_t length, uint8_t * key, uint8_t * iv)
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
threeway_encrypt_pcbc(uint8_t * data, uint32_t length, uint8_t * key, uint8_t * iv)
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
threeway_decrypt_pcbc(uint8_t * data, uint32_t length, uint8_t * key, uint8_t * iv)
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


/* ******************* INTERNAL FUNCTIONS IMPLEMENTATION ******************* */
void mu(uint32_t * data)
{
    uint32_t i, temp[3];

	temp[0] = temp[1] = temp[2] = 0;
	for (i = 0; i < 32; i++) {
		temp[0] <<= 1;
		temp[1] <<= 1;
		temp[2] <<= 1;

		if (data[0] & 1)
			temp[2] |= 1;
		if (data[1] & 1)
			temp[1] |= 1;
		if (data[2] & 1)
			temp[0] |= 1;

		data[0] >>= 1;
		data[1] >>= 1;
		data[2] >>= 1;
	}

	data[0] = temp[0];
	data[1] = temp[1];
	data[2] = temp[2];
}

void gamma(uint32_t * data)
{
    uint32_t temp[3];

    temp[0] = data[0] ^ (data[1] | (~data[2]));
    temp[1] = data[1] ^ (data[2] | (~data[0]));
    temp[2] = data[2] ^ (data[0] | (~data[1]));

    data[0] = temp[0];
    data[1] = temp[1];
    data[2] = temp[2];
}

void theta(uint32_t * data)
{
    uint32_t temp[3];

    temp[0] =
	     data[0] ^ 
        (data[0] >> 16) ^ (data[1] << 16) ^ (data[1] >> 16) ^ (data[2] << 16) ^
	    (data[1] >> 24) ^ (data[2] <<  8) ^ (data[2] >>  8) ^ (data[0] << 24) ^ 
        (data[2] >> 16) ^ (data[0] << 16) ^ (data[2] >> 24) ^ (data[0] << 8);
	temp[1] =
	     data[1] ^ 
        (data[1] >> 16) ^ (data[2] << 16) ^ (data[2] >> 16) ^ (data[0] << 16) ^
	    (data[2] >> 24) ^ (data[0] <<  8) ^ (data[0] >>  8) ^ (data[1] << 24) ^ 
        (data[0] >> 16) ^ (data[1] << 16) ^ (data[0] >> 24) ^ (data[1] << 8);
	temp[2] =
	     data[2] ^ 
        (data[2] >> 16) ^ (data[0] << 16) ^ (data[0] >> 16) ^ (data[1] << 16) ^
	    (data[0] >> 24) ^ (data[1] <<  8) ^ (data[1] >>  8) ^ (data[2] << 24) ^ 
        (data[1] >> 16) ^ (data[2] << 16) ^ (data[1] >> 24) ^ (data[2] << 8);

	data[0] = temp[0];
	data[1] = temp[1];
	data[2] = temp[2];
}

void rho(uint32_t * data)
{
    theta(data);
	pi_1(data);
	gamma(data);
	pi_2(data);
}

void pi_1(uint32_t * data)
{
    data[0] = (data[0] >> 10) ^ (data[0] << 22);
	data[2] = (data[2] <<  1) ^ (data[2] >> 31);
}

void pi_2(uint32_t * data)
{
    data[0] = (data[0] <<  1) ^ (data[0] >> 31);
	data[2] = (data[2] >> 10) ^ (data[2] << 22);
}

void rndcon_gen(uint32_t start, uint32_t *rtab)
{
    uint32_t i;

    for (i = 0; i <= ROUNDS; i++)
    {
        rtab[i] = start;
        start <<= 1;
        if (start & 0x10000)
            start ^= 0x11011;
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
    Meskipun key didefinisikan sebagai 32-byte karakter, hanya 12 karakter saja yang
    digunakan, karena bits dikonfigurasi sebagai 96-bit (12-byte) yang
    direpresentasikan sebagai 3 integer 4-byte.
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
    ukuran IV disesuaikan dengan block yang dipergunakan (12-byte).
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

    Tiap block berukuran 96-bit (12-byte).
    Data 60-byte menghasilkan 5 block data masing-masing 12-byte.
    */
    memset(encbuffer, 0, sizeof(encbuffer));
    memset(decbuffer, 0, sizeof(decbuffer));

    // Enkripsi - block: 128   key: 256
    memcpy(encbuffer, data, length);
    threeway_encrypt_ecb(encbuffer, 48, key);       // ECB
    // threeway_encrypt_cbc(encbuffer, 48, key, iv);   // CBC
    // threeway_encrypt_cfb(encbuffer, 48, key, iv);   // CFB
    // threeway_encrypt_ctr(encbuffer, 48, key, iv);   // CTR
    // threeway_encrypt_ofb(encbuffer, 48, key, iv);   // OFB
    // threeway_encrypt_pcbc(encbuffer, 48, key, iv);  // PCBC
    printx("Encrypted:", encbuffer, 48);

    // Dekripsi - block: 128   key: 256
    memcpy(decbuffer, encbuffer, 48);
    threeway_decrypt_ecb(decbuffer, 48, key);       // ECB
    // threeway_decrypt_cbc(decbuffer, 48, key, iv);   // CBC
    // threeway_decrypt_cfb(decbuffer, 48, key, iv);   // CFB
    // threeway_decrypt_ctr(decbuffer, 48, key, iv);   // CTR
    // threeway_decrypt_ofb(decbuffer, 48, key, iv);   // OFB
    // threeway_decrypt_pcbc(decbuffer, 48, key, iv);  // PCBC
    printx("Decrypted:", decbuffer, 48);

    printf("\nFinal: %s\n", decbuffer);

    return 0;
}

