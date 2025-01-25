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

/* ************************* CONFIGURATION & SEED ************************* */
#define BLOCKSIZE       96
#define BLOCKSIZEB      12
#define KEYSIZE         96
#define KEYSIZEB        12
#define ROUNDS          11

#define STRT_E          0x0b0b      /* constant for first encryption round */ 
#define STRT_D          0xb1b1      /* constant for first decryption round */

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

#ifdef _MSC_VER
    #define LITTLE_ENDIAN
#elif defined(__BYTE_ORDER__) && (__BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__)
    #define LITTLE_ENDIAN 
#elif defined(__BYTE_ORDER__) && (__BYTE_ORDER__ == __ORDER_BIG_ENDIAN__)
    #define BIG_ENDIAN
#else 
    #define BIG_ENDIAN
#endif

#ifdef LITTLE_ENDIAN
    #define convert(x) bswap32(x)
#else 
    #define convert(x) x
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

    for (i = 0; i < 3; i++)
    {
        _data[i] = convert(p_data[i]);
        _key[i]  = convert(p_key[i]);
    }

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

    for (i = 0; i < 3; i++)
        p_data[i] = convert(_data[i]);
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

    for (i = 0; i < 3; i++)
    {
        _data[i] = convert(p_data[i]);
        _key[i]  = convert(p_key[i]);
    }

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

    for (i = 0; i < 3; i++)
        p_data[i] = convert(_data[i]);
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
decrypt_ecb(uint8_t * data, uint32_t length, uint8_t * key)
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
encrypt_cbc(uint8_t * data, uint32_t length, uint8_t * key, uint8_t * iv)
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
decrypt_cbc(uint8_t * data, uint32_t length, uint8_t * key, uint8_t * iv)
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
encrypt_cfb(uint8_t * data, uint32_t length, uint8_t * key, uint8_t * iv)
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
decrypt_cfb(uint8_t * data, uint32_t length, uint8_t * key, uint8_t * iv)
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
encrypt_ctr(uint8_t * data, uint32_t length, uint8_t * key, uint8_t *nonce)
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
decrypt_ctr(uint8_t * data, uint32_t length, uint8_t * key, uint8_t *nonce)
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
encrypt_ofb(uint8_t * data, uint32_t length, uint8_t * key, uint8_t * iv)
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
decrypt_ofb(uint8_t * data, uint32_t length, uint8_t * key, uint8_t * iv)
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
encrypt_pcbc(uint8_t * data, uint32_t length, uint8_t * key, uint8_t * iv)
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
decrypt_pcbc(uint8_t * data, uint32_t length, uint8_t * key, uint8_t * iv)
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