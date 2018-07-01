/*
    Unicorn-A by NEC Corporation
    Archive of Reversing.ID
    Block Cipher

    Assemble:
        (gcc)
        $ gcc -m32 -S -masm=intel -o Unicorn-A.asm Unicorn-A.c

        (msvc)
        $ cl /c /FaBBS.asm Unicorn-A.c
*/
#include <stdint.h>
#include <memory.h>

/* ************************ CONFIGURATION & SEED ************************ */
#define ROUND 16
#define LINE  8

#define IK0   0
#define IK4   ROUND*16+16
#define EK0   IK0+16

/* Key generation */
uint32_t S[256] =
{
    0x95AE2518, 0x6FFF22FC, 0xEDA1A290, 0x9B6D8479,
    0x15FE8611, 0x5528DC2A, 0x6C5F5B4D, 0x4C438F7F,
    0xEC212902, 0x4B7C2D23, 0xC185E5AD, 0x543AF715,
    0x16E06281, 0x8AEEB23A, 0x59814469, 0x37383871,
    0x3389D470, 0x913961E5, 0x0DA946B9, 0x99570FBD,
    0x94DD3A4C, 0xA3DC48CC, 0x56A3D8D1, 0x3B54D057,
    0xCC0E0E05, 0xAFEF6060, 0x5BABD652, 0x758AD963,
    0x7E4A8585, 0x46C0B38C, 0x90421C42, 0x0A689A40,
    0xF80878C0, 0x92FA7B6B, 0xC92B53C2, 0x007364DC,
    0x617EEB10, 0xD0580344, 0x17D4E6B7, 0xD667A0AB,
    0x933EC1DB, 0xEA52F533, 0x428FA45C, 0x41049B0D,
    0xE275FF98, 0x39E2AF56, 0xD21C4F87, 0xE09B947B,
    0xAC41E362, 0x289CDBAE, 0x9A8B1767, 0x57B75F9C,
    0xB2EB6F9D, 0xEB7D0B3B, 0x87D95791, 0xDC74689B,
    0x6E6FA39E, 0x79EDCB08, 0x609DBDE7, 0x08441D84,
    0x09A09C53, 0x35B8AD31, 0xF1D5D317, 0x69AC4020,
    0x8FAA9D55, 0xA9843545, 0xB649C4FB, 0x8B025924,
    0x700151E9, 0x10E804EE, 0xB75C54DE, 0x43F91095,
    0xE988C025, 0x276A4AF8, 0xC5AF0D1A, 0x4A05B512,
    0xA609147D, 0xDA8CB80B, 0xE7263989, 0xF2BFB7FD,
    0xA1325A4F, 0x9FFB7734, 0xC0555D38, 0x250CCF5F,
    0xB11B26F1, 0xE43083BB, 0x2F2E5E2C, 0x77343CA7,
    0x0E91747C, 0x124E0166, 0xF4A8D5E3, 0x389F7A73,
    0x036405D4, 0xC3BC658E, 0xEF10909A, 0xDBE3755D,
    0x211A4BF7, 0xA7C62ED3, 0x1AF40821, 0xB4CDAC1C,
    0x36B2AA43, 0x3D48980A, 0x3A8EE793, 0xDEA2D2E1,
    0x043342D7, 0x1EF636D2, 0xBFF10AF6, 0x2280BBA0,
    0x6BC28083, 0xF9B1CC49, 0x8E7A0C41, 0x96146639,
    0x5F90F301, 0x2A3173B6, 0x7C5389B4, 0x19A693C7,
    0xE8F79FCF, 0xB5E1E97E, 0x780B3BD8, 0x5D07DDE0,
    0x0566FD3D, 0x44F27051, 0x06B9A5CA, 0x3012C6C4,
    0x81966992, 0x29A5DEBC, 0x6879EA77, 0x49629980,
    0xBC5D2B32, 0xA5C5C91E, 0xD446795B, 0xA097B4A1,
    0xFA4B5659, 0x8D76CD0C, 0x7BCAE1C3, 0xD8D8F24A,
    0x5E6CB6EB, 0xEECF37DF, 0x510F3FE2, 0xCA70E8AC,
    0x0763FEF5, 0x7A232C07, 0xC46509DA, 0x1145159F,
    0xCF5688F2, 0x663D41D9, 0xB84F72D0, 0xBD6E1F26,
    0xF30D28A3, 0x48DA312D, 0xCE950027, 0x0C062404,
    0xC886A93E, 0xE11D1688, 0xA424F968, 0xB08323B3,
    0xF7B53E58, 0x019A11C5, 0x02B4AE06, 0xFEE6F800,
    0x474D9E8D, 0xB9C197BE, 0xE5A418F3, 0xBB1132D6,
    0xFBD3B06D, 0x89036CA2, 0x45D1433C, 0xA8697FA5,
    0x325E96C6, 0x18CE12E4, 0xAB2C02DD, 0xAD13A8A4,
    0x9E3CC26A, 0xDD7BAB65, 0x7F0AC3CB, 0x1B1F91EC,
    0xFC82638F, 0x72C31930, 0x984C506E, 0x52D0E050,
    0xD13621B0, 0x26FCC84E, 0xCBDBC5EA, 0x80CB76B5,
    0xD7C7A161, 0xD5273D54, 0x24BD8E14, 0xAE504D46,
    0x86A7BE1D, 0xB35AD1A8, 0x5A20301B, 0x761E8B48,
    0x50E9EE47, 0xF640CE5A, 0xFDF52AFF, 0x7DB67D13,
    0x1D78EFFE, 0x2CE7ED72, 0x0F7F3419, 0xE32FDFE6,
    0x6216582F, 0xCD87A72B, 0xFF371A64, 0x4D7282B2,
    0xC6EA4C28, 0xC229BF29, 0x851507F9, 0x825147BA,
    0x4FADD796, 0x67DF1BCD, 0x4E177EB8, 0x31FD06C9,
    0x1399FB8B, 0x8C19334B, 0x6D2DF136, 0xD3F88116,
    0xDF61873F, 0x3FB3F6F4, 0x40BAF46C, 0x977792AF,
    0x3EC8202E, 0xD992B1A9, 0xAABB49F0, 0x53D25299,
    0x8800E297, 0x2DE46E74, 0x73184E7A, 0xC7BEBAE8,
    0x148DF0A6, 0x2EEC8D75, 0xBE3FA60E, 0xF0C9455E,
    0x84606B6F, 0x1C7155CE, 0xA2F067ED, 0xE69395B1,
    0x83E5FAC8, 0x6A5B6D1F, 0x206BCAAA, 0x58D61378,
    0x9D5971D5, 0x1F3B8C35, 0x2B988A94, 0x9CD7270F,
    0x71B0B937, 0xBACCE4EF, 0x23F36A03, 0x65942FBF,
    0x342AFC86, 0x3C9EC7FA, 0x0B47BCC1, 0x64225C09,
    0x74DEDA82, 0xF5251E76, 0x63C4EC8A, 0x5C357C22
};

typedef struct 
{
    uint8_t rkeys[288];
} unicorn_t;


/* ********************* INTERNAL FUNCTIONS PROTOTYPE ********************* */
static void F(uint32_t, uint32_t, uint32_t*, uint32_t*, uint32_t*);


/* ********************* MODE OF OPERATIONS PROTOTYPE ********************* */
/** Electronic Code Book mode **/
void unicorn_encrypt_ecb(char* data, uint32_t length, char * key);
void unicorn_decrypt_ecb(char* data, uint32_t length, char * key);

/** Cipher Block Chaining mode **/
void unicorn_encrypt_cbc(char* data, uint32_t length, char * key, char * iv);
void unicorn_decrypt_cbc(char* data, uint32_t length, char * key, char * iv);

/** Cipher Feedback mode **/
void unicorn_encrypt_cfb(char* data, uint32_t length, char * key, char * iv);
void unicorn_decrypt_cfb(char* data, uint32_t length, char * key, char * iv);

/** Counter mode **/
void unicorn_encrypt_ctr(char* data, uint32_t length, char * key, char *nonce);
void unicorn_decrypt_ctr(char* data, uint32_t length, char * key, char *nonce);

/** Output Feedback mode **/
void unicorn_encrypt_ofb(char* data, uint32_t length, char * key, char * iv);
void unicorn_decrypt_ofb(char* data, uint32_t length, char * key, char * iv);

/** Propagating Cipher Block Chaining mode **/
void unicorn_encrypt_pcbc(char* data, uint32_t length, char * key, char * iv);
void unicorn_decrypt_pcbc(char* data, uint32_t length, char * key, char * iv);


/* ************************ CRYPTOGRAPHY ALGORITHM ************************ */
/* 
    Enkripsi sebuah block dengan Unicorn-A. 
    Pastikan konfigurasi telah dilakukan dengan memanggil unicorn_setup()
*/
void 
unicorn_encrypt(unicorn_t * config, uint8_t val[16])
{
    uint32_t wx[4], tmp[2];
    int32_t  i;
    
    for (i = 0; i < 4; i++)
    {
        wx[i]  = val[i * 4] << 24;
        wx[i] |= val[i * 4 + 1] << 16;
        wx[i] |= val[i * 4 + 2] << 8;
        wx[i] |= val[i * 4 + 3];
    }

    for (i = 0; i < 4; i++)
        wx[i] += *((uint32_t*) &config->rkeys[IK0 + i * 4]);
    
    for (i = 0; i < ROUND; i++)
    {
        F(wx[2], wx[3], (uint32_t*) &config->rkeys[EK0 + (i * 16)], &tmp[0], &tmp[1]);

        tmp[0] ^= wx[0];
        tmp[1] ^= wx[1];

        wx[0] = wx[2];
        wx[1] = wx[3];
        wx[2] = tmp[0];
        wx[3] = tmp[1];
    }

    wx[0] -= *((uint32_t*) &config->rkeys[IK4 + 8]);
    wx[1] -= *((uint32_t*) &config->rkeys[IK4 + 12]);
    wx[2] -= *((uint32_t*) &config->rkeys[IK4]);
    wx[3] -= *((uint32_t*) &config->rkeys[IK4 + 4]);

    val[0]  = (uint8_t) (wx[2] >> 24);
    val[1]  = (uint8_t) (wx[2] >> 16);
    val[2]  = (uint8_t) (wx[2] >> 8);
    val[3]  = (uint8_t)  wx[2];
    val[4]  = (uint8_t) (wx[3] >> 24);
    val[5]  = (uint8_t) (wx[3] >> 16);
    val[6]  = (uint8_t) (wx[3] >> 8);
    val[7]  = (uint8_t)  wx[3];
    val[8]  = (uint8_t) (wx[0] >> 24);
    val[9]  = (uint8_t) (wx[0] >> 16);
    val[10] = (uint8_t) (wx[0] >> 8);
    val[11] = (uint8_t)  wx[0];
    val[12] = (uint8_t) (wx[1] >> 24);
    val[13] = (uint8_t) (wx[1] >> 16);
    val[14] = (uint8_t) (wx[1] >> 8);
    val[15] = (uint8_t)  wx[1];
}
/* 
    Dekripsi sebuah block dengan Unicorn-A. 
    Pastikan konfigurasi telah dilakukan dengan memanggil unicorn_setup()
*/
void unicorn_decrypt(unicorn_t * config, uint8_t val[16])
{
    uint32_t wx[4], tmp[2];
    int32_t  i;
    
    for (i = 0; i < 4; i++)
    {
        wx[i]  = val[i * 4] << 24;
        wx[i] |= val[i * 4 + 1] << 16;
        wx[i] |= val[i * 4 + 2] << 8;
        wx[i] |= val[i * 4 + 3];
    }

    for (i = 0; i < 4; i++)
        wx[i] += *((uint32_t*) &config->rkeys[IK4 + i * 4]);
    
    for (i = ROUND - 1; i >= 0; i--)
    {
        F(wx[2], wx[3], (uint32_t*) &config->rkeys[EK0 + i * 16], &tmp[0], &tmp[1]);

        tmp[0] ^= wx[0];
        tmp[1] ^= wx[1];
    
        wx[0] = wx[2];
        wx[1] = wx[3];
        wx[2] = tmp[0];
        wx[3] = tmp[1];
    }

    wx[0]  -= *((uint32_t*) &config->rkeys[IK0 + 8]);
    wx[1]  -= *((uint32_t*) &config->rkeys[IK0 + 12]);
    wx[2]  -= *((uint32_t*) &config->rkeys[IK0]);
    wx[3]  -= *((uint32_t*) &config->rkeys[IK0 + 4]);

    val[0]  = (uint8_t) (wx[2] >> 24);
    val[1]  = (uint8_t) (wx[2] >> 16);
    val[2]  = (uint8_t) (wx[2] >> 8);
    val[3]  = (uint8_t)  wx[2];
    val[4]  = (uint8_t) (wx[3] >> 24);
    val[5]  = (uint8_t) (wx[3] >> 16);
    val[6]  = (uint8_t) (wx[3] >> 8);
    val[7]  = (uint8_t)  wx[3];
    val[8]  = (uint8_t) (wx[0] >> 24);
    val[9]  = (uint8_t) (wx[0] >> 16);
    val[10] = (uint8_t) (wx[0] >> 8);
    val[11] = (uint8_t)  wx[0];
    val[12] = (uint8_t) (wx[1] >> 24);
    val[13] = (uint8_t) (wx[1] >> 16);
    val[14] = (uint8_t) (wx[1] >> 8);
    val[15] = (uint8_t)  wx[1];
}


/* ******************* INTERNAL FUNCTIONS IMPLEMENTATION ******************* */
/* Round function */
void 
F(uint32_t ida, uint32_t idb, uint32_t *k, uint32_t *oda, uint32_t *odb)
{
    uint32_t wx0, wx1, wk0, wk1, tmp;

    wx0 = ida + k[0];
    wx1 = idb + k[2];
    wk0 = idb + k[1];
    wk1 = ida + k[3];

    tmp = wx0 ^ (wx0 << 23) ^ (wx1 >> 9) ^ (wx0 >> 23) ^ (wx1 << 9);
    wx1 = wx1 ^ (wx1 << 23) ^ (wx0 >> 9) ^ (wx1 >> 23) ^ (wx0 << 9);

    wx0  = tmp * 0x7e167289;
    wx1 ^= S[wx0 >> 24];
    wx1 *= 0xfe21464b;
    
    wx0 ^= S[wx1 >> 24];
    wx1 ^= S[(wx0 >> 16) & 0xff];
    wx0 ^= S[(wx1 >> 16) & 0xff];
    wx1 ^= S[(wx0 >> 8)  & 0xff];
    wx0 ^= S[(wx1 >> 8)  & 0xff];
    wx1 ^= S[wx0 & 0xff];
    wx0 ^= S[wx1 & 0xff];

    wk0 *= 0x7e167289;
    wk1 ^= S[wk0 >> 24];

    wk1 *= 0xfe21464b;
    wk0 ^= S[wk1 >> 24];

    wk0 *= 0xfe21464b;
    wk1 ^= S[wk0 >> 24];

    wk1 *= 0x7e167289;
    wk0 ^= S[wk1 >> 24];

    wk1 ^= S[(wk0 >> 16) & 0xff];
    wk0 ^= S[(wk1 >> 16) & 0xff];
    wx1 ^= S[(wx0 >> (24 - ((wk1 & 0xc) << 1))) & 0xff];
    wx0 ^= S[(wx1 >> (24 - ((wk1 & 0x3) *8))) & 0xff];

    *oda = wx0 ^ wk0;
    *odb = wx1 ^ wk0;
}

/* Turunkan round-key dari secret key */
void 
unicorn_setup(unicorn_t * config, uint8_t secret[32])
{
    uint32_t wk[LINE], ek[ROUND * 4 + 8];
    int32_t  i, j, n = ROUND + 2;
    int32_t  counter = 0;

    for (i = 0; i < LINE; i++)
        wk[i] = secret[i * 4] << 24 | secret[i * 4 + 1] << 16 | secret[i * 4 + 2] << 8 | secret[i * 4 + 3];

    for (i = 0; i < 3; i++)
    {
        for (j = 0; j < LINE; j++)
        {
            wk[j] *= 0x01010101;
            wk[(j + 1) % LINE] ^= S[wk[j] >> 24];
        }
    }

    for (i = 0; i < 16 * ((ROUND + 2) / 2); i += 16)
    {
        for (j = i; j < (i + 8); j++)
        {
            wk[j % LINE] *= 0x01010101;
            wk[(j + 1) % LINE] ^= S[wk[j % LINE] >> 24];
        }
        
        for (; j < (i + 16); j++)
        {
            wk[j % LINE] *= 0x01010101;
            ek[counter++] = wk[(j + 1) % LINE] ^= S[wk[j % LINE] >> 24];
        }
    }

    memcpy(&config->rkeys[IK0],      &ek[0], 4);
    memcpy(&config->rkeys[IK0 + 4],  &ek[n], 4);
    memcpy(&config->rkeys[IK0 + 8],  &ek[n * 2], 4);
    memcpy(&config->rkeys[IK0 + 12], &ek[n * 3], 4);
    memcpy(&config->rkeys[IK4],      &ek[n - 1], 4);
    memcpy(&config->rkeys[IK4 + 4],  &ek[n * 2 - 1], 4);
    memcpy(&config->rkeys[IK4 + 8],  &ek[n * 3 - 1], 4);
    memcpy(&config->rkeys[IK4 + 12], &ek[n * 4 - 1], 4);

    for (i = 1; i <= ROUND; i++)
    {
        memcpy(&config->rkeys[EK0 * i],      &ek[i], 4);
        memcpy(&config->rkeys[EK0 * i + 4],  &ek[n + i], 4);
        memcpy(&config->rkeys[EK0 * i + 8],  &ek[n * 2 + i], 4);
        memcpy(&config->rkeys[EK0 * i + 12], &ek[n * 3 + i], 4);
    }
}


/* *************************** HELPER FUNCTIONS *************************** */
/* Xor 2 block data */
void 
xor_block(char * dst, char * src1, char * src2)
{
    register uint32_t i;
    for (i = 0; i < 16; i++)
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
unicorn_encrypt_ecb(char* data, uint32_t length, char * key)
{
    uint32_t   i;
    unicorn_t  config;

    // Setup configuration
    unicorn_setup(&config, key);

    for (i = 0; i < length; i += 16)
        unicorn_encrypt(&config, &data[i]);
}

/*
    Dekripsi block data dengan mode ECB.
    Dekripsi diberlakukan secara independen tanpa ada hubungan dengan block
    sebelum dan berikutnya.
    Pastikan jumlah block valid.
*/
void 
unicorn_decrypt_ecb(char* data, uint32_t length, char * key)
{
    uint32_t   i;
    unicorn_t  config;

    // Setup configuration
    unicorn_setup(&config, key);

    for(i = 0; i < length; i += 16)
        unicorn_decrypt(&config, &data[i]);
}


/*
    Enkripsi block data dengan mode CBC.
    Sebelum enkripsi, plaintext akan di-XOR dengan block sebelumnya.
    Pastikan jumlah block valid.
*/
void 
unicorn_encrypt_cbc(char* data, uint32_t length, char * key, char * iv)
{
    uint32_t   i;
    unicorn_t  config;
    char     * prev_block;

    // Setup configuration
    unicorn_setup(&config, key);

    prev_block = iv;

    for (i = 0; i < length; i += 16)
    {
        // XOR block plaintext dengan block ciphertext sebelumnya
        xor_block(&data[i], &data[i], prev_block);

        // Enkripsi plaintext menjadi ciphertext
        unicorn_encrypt(&config, &data[i]);

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
unicorn_decrypt_cbc(char* data, uint32_t length, char * key, char * iv)
{
    uint32_t   i;
    unicorn_t  config;
    char       prev_block[16];
    char       cipher_block[16];

    // Setup configuration
    unicorn_setup(&config, key);
    
    memcpy(prev_block, iv, 16);

    for (i = 0; i < length; i += 16)
    {
        // Simpan block ciphertext untuk operasi XOR berikutnya.
        memcpy(cipher_block, &data[i], 16);

        // Dekripsi ciphertext menjadi block
        unicorn_decrypt(&config, &data[i]);

        // XOR block block dengan block ciphertext sebelumnya
        // gunakan IV bila ini adalah block pertama
        xor_block(&data[i], &data[i], prev_block);

        // Pindahkan block ciphertext yang telah disimpan
        memcpy(prev_block, cipher_block, 16);
    }
}


/*
    Enkripsi block data dengan mode CFB.
    Pastikan jumlah block valid.
*/
void 
unicorn_encrypt_cfb(char* data, uint32_t length, char * key, char * iv)
{
    uint32_t   i;
    unicorn_t  config;
    char       prev_block[16];

    // Setup configuration
    unicorn_setup(&config, key);

    memcpy(prev_block, iv, 16);

    for (i = 0; i < length; i += 16)
    {
        // Enkripsi block sebelumnya
        // gunakan IV bila ini block pertama
        unicorn_encrypt(&config, prev_block);

        // XOR dengan plaintext untuk mendapatkan ciphertext
        xor_block(&data[i], &data[i], prev_block);

        // Simpan block ciphertext untuk operasi XOR berikutnya
        memcpy(prev_block, &data[i], 16);
    }
}

/*
    Dekripsi block data dengan mode CFB.
    Pastikan jumlah block valid.
*/
void 
unicorn_decrypt_cfb(char* data, uint32_t length, char * key, char * iv)
{
    uint32_t   i;
    unicorn_t  config;
    char       prev_block[16];
    char       cipher_block[16];

    // Setup configuration
    unicorn_setup(&config, key);

    memcpy(prev_block, iv, 16);

    for (i = 0; i < length; i += 16)
    {
        // Simpan block cipher untuk operasi
        memcpy(cipher_block, &data[i], 16);

        // Enkripsi block sebelumnya
        // gunakan IV bila ini block pertama
        unicorn_encrypt(&config, prev_block);

        // XOR dengan plaintext untuk mendapatkan ciphertext
        xor_block(&data[i], &data[i], prev_block);

        // Simpan block ciphertext untuk operasi XOR berikutnya
        memcpy(prev_block, cipher_block, 16);
    }
}

/*
    Enkripsi block data dengan mode CTR.
    Pastikan jumlah block valid.
*/
void 
unicorn_encrypt_ctr(char* data, uint32_t length, char * key, char *nonce)
{
    uint32_t   i;
    unicorn_t  config;
    char       local_nonce[16];
    uint32_t * nonce_counter = (uint32_t*)&local_nonce[12];

    // Setup configuration
    unicorn_setup(&config, key);
    
    memcpy(local_nonce, nonce, 16);

    for (i = 0; i < length; i += 16)
    {
        // Enkripsi nonce + counter
        unicorn_encrypt(&config, local_nonce);

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
unicorn_decrypt_ctr(char* data, uint32_t length, char * key, char *nonce)
{
    uint32_t   i;
    unicorn_t  config;
    char       local_nonce[16];
    uint32_t * nonce_counter = (uint32_t*)&local_nonce[12];

    // Setup configuration
    unicorn_setup(&config, key);
    
    memcpy(local_nonce, nonce, 16);

    for (i = 0; i < length; i += 16)
    {
        // Enkripsi nonce + counter
        unicorn_encrypt(&config, local_nonce);

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
unicorn_encrypt_ofb(char* data, uint32_t length, char * key, char * iv)
{
    uint32_t   i;
    unicorn_t  config;
    char       prev_block[16];

    // Setup configuration
    unicorn_setup(&config, key);
    
    memcpy(prev_block, iv, 16);
    
    for (i = 0; i < length; i += 16)
    {
        // Enkripsi block sebelumnya 
        // gunakan IV bila ini block pertama
        unicorn_encrypt(&config, prev_block);

        // XOR plaintext dengan output dari enkripsi untuk mendapatkan ciphertext.
        xor_block(&data[i], &data[i], prev_block);
    }
}

/*
    Dekripsi block data dengan mode OFB.
    Pastikan jumlah block valid.
*/
void 
unicorn_decrypt_ofb(char* data, uint32_t length, char * key, char * iv)
{
    uint32_t   i;
    unicorn_t  config;
    char       prev_block[16];

    // Setup configuration
    unicorn_setup(&config, key);
    
    memcpy(prev_block, iv, 16);
    
    for (i = 0; i < length; i += 16)
    {
        // Enkripsi block sebelumnya 
        // gunakan IV bila ini block pertama
        unicorn_encrypt(&config, prev_block);

        // XOR plaintext dengan output dari enkripsi untuk mendapatkan ciphertext.
        xor_block(&data[i], &data[i], prev_block);
    }
}


/*
    Enkripsi block data dengan mode OFB.
    Pastikan jumlah block valid.
*/
void 
unicorn_encrypt_pcbc(char* data, uint32_t length, char * key, char * iv)
{
    uint32_t   i;
    unicorn_t  config;
    char       prev_block[16];
    char       ptext_block[16];

    // Setup configuration
    unicorn_setup(&config, key);
    
    memcpy(prev_block, iv, 16);

    for (i = 0; i < length; i += 16)
    {
        // Simpan plaintext untuk dioperasikan dengan block berikutnya.
        memcpy(ptext_block, &data[i], 16);

        // XOR plaintext dengan block sebelumnya
        // gunakan IV bila ini block pertama
        xor_block(&data[i], &data[i], prev_block);

        // Enkripsi
        unicorn_encrypt(&config, &data[i]);

        // Hitung block berikutnya
        xor_block(prev_block, ptext_block, &data[i]);
    }
}

/*
    Dekripsi block data dengan mode OFB.
    Pastikan jumlah block valid.
*/
void 
unicorn_decrypt_pcbc(char* data, uint32_t length, char * key, char * iv)
{
    uint32_t   i;
    unicorn_t  config;
    char       prev_block[16];
    char       ctext_block[16];

    // Setup configuration
    unicorn_setup(&config, key);
    
    memcpy(prev_block, iv, 16);

    for (i = 0; i < length; i += 16)
    {
        // Simpan ciphertext untuk dioperasikan dengan block berikutnya.
        memcpy(ctext_block, &data[i], 16);

        // Dekripsi ciphertext untuk mendapatkan plaintext ter-XOR
        unicorn_decrypt(&config, &data[i]);

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

    /* secret key: 32-bytes */
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
            { 0x13, 0x51, 0x00, 0x30, 0x1C, 0xCb, 0x33, 0xF8, 0x4F, 0xD6, 0x34, 0x9A,
              0x2A, 0x29, 0xE1, 0xD1 };

    length = strlen(data);
    printf("Length: %d - Buffer: %s\n", strlen(data), data);
    printx("Original", data, length);

    /*
    Panjang plaintext: 44
    Karena block cipher mensyaratkan bahwa data harus merupakan kelipatan dari ukuran 
    block, maka harus ada padding agar panjang data mencapai kelipatan block.
    */
    memset(encbuffer, 0, sizeof(encbuffer));
    memset(decbuffer, 0, sizeof(decbuffer));

    // Enkripsi - block: 128   key: 256
    memcpy(encbuffer, data, length);
    unicorn_encrypt_ecb(encbuffer, 4, key);       // ECB
    // unicorn_encrypt_cbc(encbuffer, 4, key, iv);   // CBC
    // unicorn_encrypt_cfb(encbuffer, 4, key, iv);   // CFB
    // unicorn_encrypt_ctr(encbuffer, 4, key, iv);   // CTR
    // unicorn_encrypt_ofb(encbuffer, 4, key, iv);   // OFB
    // unicorn_encrypt_pcbc(encbuffer, 4, key, iv);  // PCBC
    printx("Encrypted:", encbuffer, 64);

    // Dekripsi - block: 128   key: 256
    memcpy(decbuffer, encbuffer, 64);
    unicorn_decrypt_ecb(decbuffer, 4, key);       // ECB
    // unicorn_decrypt_cbc(decbuffer, 4, key, iv);   // CBC
    // unicorn_decrypt_cfb(decbuffer, 4, key, iv);   // CFB
    // unicorn_decrypt_ctr(decbuffer, 4, key, iv);   // CTR
    // unicorn_decrypt_ofb(decbuffer, 4, key, iv);   // OFB
    // unicorn_decrypt_pcbc(decbuffer, 4, key, iv);  // PCBC
    printx("Decrypted:", decbuffer, 64);

    printf("\nFinal: %s\n", decbuffer);

    return 0;
}
