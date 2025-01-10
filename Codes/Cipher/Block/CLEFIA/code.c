/*
    CLEFIA by Sony Corporation
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

/* ************************ CONFIGURATION & SEED ************************ */
#define BLOCKSIZE   128
#define BLOCKSIZEB  16
#define KEYSIZE     128
#define KEYSIZEB    16

#define clefia_mul4(x)  (clefia_mul2(clefia_mul2((x))))
#define clefia_mul6(x)  (clefia_mul2((x)) ^ clefia_mul4((x)))
#define clefia_mul8(x)  (clefia_mul2(clefia_mul4((x))))
#define clefia_mulA(x)  (clefia_mul2((x)) ^ clefia_mul8((x)))

/* Key generation */
uint8_t S0[256] = 
{
    0x57U, 0x49U, 0xD1U, 0xC6U, 0x2FU, 0x33U, 0x74U, 0xFBU,
    0x95U, 0x6DU, 0x82U, 0xEAU, 0x0EU, 0xB0U, 0xA8U, 0x1CU,
    0x28U, 0xD0U, 0x4BU, 0x92U, 0x5CU, 0xEEU, 0x85U, 0xB1U,
    0xC4U, 0x0AU, 0x76U, 0x3DU, 0x63U, 0xF9U, 0x17U, 0xAFU,
    0xBFU, 0xA1U, 0x19U, 0x65U, 0xF7U, 0x7AU, 0x32U, 0x20U,
    0x06U, 0xCEU, 0xE4U, 0x83U, 0x9DU, 0x5BU, 0x4CU, 0xD8U,
    0x42U, 0x5DU, 0x2EU, 0xE8U, 0xD4U, 0x9BU, 0x0FU, 0x13U,
    0x3CU, 0x89U, 0x67U, 0xC0U, 0x71U, 0xAAU, 0xB6U, 0xF5U,
    0xA4U, 0xBEU, 0xFDU, 0x8CU, 0x12U, 0x00U, 0x97U, 0xDAU,
    0x78U, 0xE1U, 0xCFU, 0x6BU, 0x39U, 0x43U, 0x55U, 0x26U,
    0x30U, 0x98U, 0xCCU, 0xDDU, 0xEBU, 0x54U, 0xB3U, 0x8FU,
    0x4EU, 0x16U, 0xFAU, 0x22U, 0xA5U, 0x77U, 0x09U, 0x61U,
    0xD6U, 0x2AU, 0x53U, 0x37U, 0x45U, 0xC1U, 0x6CU, 0xAEU,
    0xEFU, 0x70U, 0x08U, 0x99U, 0x8BU, 0x1DU, 0xF2U, 0xB4U,
    0xE9U, 0xC7U, 0x9FU, 0x4AU, 0x31U, 0x25U, 0xFEU, 0x7CU,
    0xD3U, 0xA2U, 0xBDU, 0x56U, 0x14U, 0x88U, 0x60U, 0x0BU,
    0xCDU, 0xE2U, 0x34U, 0x50U, 0x9EU, 0xDCU, 0x11U, 0x05U,
    0x2BU, 0xB7U, 0xA9U, 0x48U, 0xFFU, 0x66U, 0x8AU, 0x73U,
    0x03U, 0x75U, 0x86U, 0xF1U, 0x6AU, 0xA7U, 0x40U, 0xC2U,
    0xB9U, 0x2CU, 0xDBU, 0x1FU, 0x58U, 0x94U, 0x3EU, 0xEDU,
    0xFCU, 0x1BU, 0xA0U, 0x04U, 0xB8U, 0x8DU, 0xE6U, 0x59U,
    0x62U, 0x93U, 0x35U, 0x7EU, 0xCAU, 0x21U, 0xDFU, 0x47U,
    0x15U, 0xF3U, 0xBAU, 0x7FU, 0xA6U, 0x69U, 0xC8U, 0x4DU,
    0x87U, 0x3BU, 0x9CU, 0x01U, 0xE0U, 0xDEU, 0x24U, 0x52U,
    0x7BU, 0x0CU, 0x68U, 0x1EU, 0x80U, 0xB2U, 0x5AU, 0xE7U,
    0xADU, 0xD5U, 0x23U, 0xF4U, 0x46U, 0x3FU, 0x91U, 0xC9U,
    0x6EU, 0x84U, 0x72U, 0xBBU, 0x0DU, 0x18U, 0xD9U, 0x96U,
    0xF0U, 0x5FU, 0x41U, 0xACU, 0x27U, 0xC5U, 0xE3U, 0x3AU,
    0x81U, 0x6FU, 0x07U, 0xA3U, 0x79U, 0xF6U, 0x2DU, 0x38U,
    0x1AU, 0x44U, 0x5EU, 0xB5U, 0xD2U, 0xECU, 0xCBU, 0x90U,
    0x9AU, 0x36U, 0xE5U, 0x29U, 0xC3U, 0x4FU, 0xABU, 0x64U,
    0x51U, 0xF8U, 0x10U, 0xD7U, 0xBCU, 0x02U, 0x7DU, 0x8EU
};

uint8_t S1[256] = 
{
    0x6CU, 0xDAU, 0xC3U, 0xE9U, 0x4EU, 0x9DU, 0x0AU, 0x3DU,
    0xB8U, 0x36U, 0xB4U, 0x38U, 0x13U, 0x34U, 0x0CU, 0xD9U,
    0xBFU, 0x74U, 0x94U, 0x8FU, 0xB7U, 0x9CU, 0xE5U, 0xDCU,
    0x9EU, 0x07U, 0x49U, 0x4FU, 0x98U, 0x2CU, 0xB0U, 0x93U,
    0x12U, 0xEBU, 0xCDU, 0xB3U, 0x92U, 0xE7U, 0x41U, 0x60U,
    0xE3U, 0x21U, 0x27U, 0x3BU, 0xE6U, 0x19U, 0xD2U, 0x0EU,
    0x91U, 0x11U, 0xC7U, 0x3FU, 0x2AU, 0x8EU, 0xA1U, 0xBCU,
    0x2BU, 0xC8U, 0xC5U, 0x0FU, 0x5BU, 0xF3U, 0x87U, 0x8BU,
    0xFBU, 0xF5U, 0xDEU, 0x20U, 0xC6U, 0xA7U, 0x84U, 0xCEU,
    0xD8U, 0x65U, 0x51U, 0xC9U, 0xA4U, 0xEFU, 0x43U, 0x53U,
    0x25U, 0x5DU, 0x9BU, 0x31U, 0xE8U, 0x3EU, 0x0DU, 0xD7U,
    0x80U, 0xFFU, 0x69U, 0x8AU, 0xBAU, 0x0BU, 0x73U, 0x5CU,
    0x6EU, 0x54U, 0x15U, 0x62U, 0xF6U, 0x35U, 0x30U, 0x52U,
    0xA3U, 0x16U, 0xD3U, 0x28U, 0x32U, 0xFAU, 0xAAU, 0x5EU,
    0xCFU, 0xEAU, 0xEDU, 0x78U, 0x33U, 0x58U, 0x09U, 0x7BU,
    0x63U, 0xC0U, 0xC1U, 0x46U, 0x1EU, 0xDFU, 0xA9U, 0x99U,
    0x55U, 0x04U, 0xC4U, 0x86U, 0x39U, 0x77U, 0x82U, 0xECU,
    0x40U, 0x18U, 0x90U, 0x97U, 0x59U, 0xDDU, 0x83U, 0x1FU,
    0x9AU, 0x37U, 0x06U, 0x24U, 0x64U, 0x7CU, 0xA5U, 0x56U,
    0x48U, 0x08U, 0x85U, 0xD0U, 0x61U, 0x26U, 0xCAU, 0x6FU,
    0x7EU, 0x6AU, 0xB6U, 0x71U, 0xA0U, 0x70U, 0x05U, 0xD1U,
    0x45U, 0x8CU, 0x23U, 0x1CU, 0xF0U, 0xEEU, 0x89U, 0xADU,
    0x7AU, 0x4BU, 0xC2U, 0x2FU, 0xDBU, 0x5AU, 0x4DU, 0x76U,
    0x67U, 0x17U, 0x2DU, 0xF4U, 0xCBU, 0xB1U, 0x4AU, 0xA8U,
    0xB5U, 0x22U, 0x47U, 0x3AU, 0xD5U, 0x10U, 0x4CU, 0x72U,
    0xCCU, 0x00U, 0xF9U, 0xE0U, 0xFDU, 0xE2U, 0xFEU, 0xAEU,
    0xF8U, 0x5FU, 0xABU, 0xF1U, 0x1BU, 0x42U, 0x81U, 0xD6U,
    0xBEU, 0x44U, 0x29U, 0xA6U, 0x57U, 0xB9U, 0xAFU, 0xF2U,
    0xD4U, 0x75U, 0x66U, 0xBBU, 0x68U, 0x9FU, 0x50U, 0x02U,
    0x01U, 0x3CU, 0x7FU, 0x8DU, 0x1AU, 0x88U, 0xBDU, 0xACU,
    0xF7U, 0xE4U, 0x79U, 0x96U, 0xA2U, 0xFCU, 0x6DU, 0xB2U,
    0x6BU, 0x03U, 0xE1U, 0x2EU, 0x7DU, 0x14U, 0x95U, 0x1DU
};

/* context and configuration */
typedef struct 
{
    uint32_t bits;
    int32_t  round;
    uint8_t  rkeys[8 * 26 + 16];    /* 8 bytes x 26 rounds (max) + whitening keys */
} clefia_t;


/* ********************* INTERNAL FUNCTIONS PROTOTYPE ********************* */
void block_encrypt(clefia_t * config, uint8_t val[BLOCKSIZEB]);
void block_decrypt(clefia_t * config, uint8_t val[BLOCKSIZEB]);
int32_t key_setup(clefia_t * config, const uint8_t * skey, uint32_t bits);

void byte_xor(uint8_t * dst, const uint8_t * a, const uint8_t * b, uint32_t bytelen);

uint8_t clefia_mul2(uint8_t x);
void clefia_f0_xor(uint8_t * dst, const uint8_t * src, const uint8_t * rk);
void clefia_f1_xor(uint8_t * dst, const uint8_t * src, const uint8_t * rk);
void clefia_gfn4(uint8_t * y, const uint8_t * x, const uint8_t * rk, int32_t round);
void clefia_gfn8(uint8_t * y, const uint8_t * x, const uint8_t * rk, int32_t round);
void clefia_gfn4_inv(uint8_t * y, const uint8_t * x, const uint8_t * rk, int32_t round);
void clefia_double_swap(uint8_t * lk);
void clefia_con_set(uint8_t * con, const uint8_t * iv, int32_t lk);


/* ********************* MODE OF OPERATIONS PROTOTYPE ********************* */
/** Electronic Code Book mode **/
void clefia_encrypt_ecb(uint8_t * data, uint32_t length, uint8_t * key);
void clefia_decrypt_ecb(uint8_t * data, uint32_t length, uint8_t * key);

/** Cipher Block Chaining mode **/
void clefia_encrypt_cbc(uint8_t * data, uint32_t length, uint8_t * key, uint8_t * iv);
void clefia_decrypt_cbc(uint8_t * data, uint32_t length, uint8_t * key, uint8_t * iv);

/** Cipher Feedback mode **/
void clefia_encrypt_cfb(uint8_t * data, uint32_t length, uint8_t * key, uint8_t * iv);
void clefia_decrypt_cfb(uint8_t * data, uint32_t length, uint8_t * key, uint8_t * iv);

/** Counter mode **/
void clefia_encrypt_ctr(uint8_t * data, uint32_t length, uint8_t * key, uint8_t *nonce);
void clefia_decrypt_ctr(uint8_t * data, uint32_t length, uint8_t * key, uint8_t *nonce);

/** Output Feedback mode **/
void clefia_encrypt_ofb(uint8_t * data, uint32_t length, uint8_t * key, uint8_t * iv);
void clefia_decrypt_ofb(uint8_t * data, uint32_t length, uint8_t * key, uint8_t * iv);

/** Propagating Cipher Block Chaining mode **/
void clefia_encrypt_pcbc(uint8_t * data, uint32_t length, uint8_t * key, uint8_t * iv);
void clefia_decrypt_pcbc(uint8_t * data, uint32_t length, uint8_t * key, uint8_t * iv);


/* ************************ CRYPTOGRAPHY ALGORITHM ************************ */
/* 
    Enkripsi sebuah block dengan CLEFIA. 
    Pastikan konfigurasi telah dilakukan dengan memanggil key_setup()
*/
void 
block_encrypt(clefia_t * config, uint8_t val[BLOCKSIZEB])
{
    uint8_t   rin[BLOCKSIZEB], rout[BLOCKSIZEB];
    uint8_t * rkeys = config->rkeys;

    memcpy(rin, val, BLOCKSIZEB);

    byte_xor(rin +  4, rin +  4, rkeys    , 4);                     /* initial key whitening */
    byte_xor(rin + 12, rin + 12, rkeys + 4, 4);
    rkeys += 8;

    clefia_gfn4(rout, rin, rkeys, config->round);                   /* GFN_{4, r} */

    memcpy(val, rout, BLOCKSIZEB);

    byte_xor(val +  4, val +  4, rkeys + config->round * 8    , 4); /* final key whitening */
    byte_xor(val + 12, val + 12, rkeys + config->round * 8 + 4, 4);
}

/* 
    Dekripsi sebuah block dengan CLEFIA. 
    Pastikan konfigurasi telah dilakukan dengan memanggil key_setup()
*/
void 
block_decrypt(clefia_t * config, uint8_t val[BLOCKSIZEB])
{
    uint8_t   rin[BLOCKSIZEB], rout[BLOCKSIZEB];
    uint8_t * rkeys = config->rkeys;

    memcpy(rin, val, BLOCKSIZEB);

    byte_xor(rin +  4, rin +  4, rkeys + config->round * 8 +  8, 4);    /* initial key whitening */
    byte_xor(rin + 12, rin + 12, rkeys + config->round * 8 + 12, 4);
    rkeys += 8;

    clefia_gfn4_inv(rout, rin, rkeys, config->round);                   /* GFN_{4, r} */

    memcpy(val, rout, BLOCKSIZEB);

    byte_xor(val +  4, val +  4, rkeys - 8, 4);                     /* final key whitening */
    byte_xor(val + 12, val + 12, rkeys - 4, 4);
}


/* ******************* INTERNAL FUNCTIONS IMPLEMENTATION ******************* */
/* XOR 2 block data dengan panjang sembarang */
void 
byte_xor(uint8_t * dst, const uint8_t * a, const uint8_t * b, uint32_t bytelen)
{
    while (bytelen--) *dst++ = *a++ ^ *b++;
}

/* multiplication over GF(2**8) (p(x) = '11d') */
uint8_t clefia_mul2(uint8_t x)
{
    if (x & 0x80U)  x ^= 0x0EU;
    return ((x << 1) | (x >> 7));
}

/*  */
void 
clefia_f0_xor(uint8_t * dst, const uint8_t * src, const uint8_t * rk)
{
    uint8_t x[4], y[4], z[4];

    /* F0 */
    /* Key addition */
    byte_xor(x, src, rk, 4);

    /* substitution layer */
    z[0] = S0[x[0]];
    z[1] = S1[x[1]];
    z[2] = S0[x[2]];
    z[3] = S1[x[3]];

    /* diffusion layer (M0) */
    y[0] =             z[0]  ^ clefia_mul2(z[1]) ^ clefia_mul4(z[2]) ^ clefia_mul6(z[3]);
    y[1] = clefia_mul2(z[0]) ^             z[1]  ^ clefia_mul6(z[2]) ^ clefia_mul4(z[3]); 
    y[2] = clefia_mul4(z[0]) ^ clefia_mul6(z[1]) ^             z[2]  ^ clefia_mul2(z[3]); 
    y[3] = clefia_mul6(z[0]) ^ clefia_mul4(z[1]) ^ clefia_mul2(z[2]) ^             z[3]; 

    /* xor setelah F0 */
    memcpy(dst, src, 4);
    byte_xor(dst + 4, src + 4, y, 4);
}

/* */
void 
clefia_f1_xor(uint8_t * dst, const uint8_t * src, const uint8_t * rk)
{
    uint8_t x[4], y[4], z[4];

    /* F1 */
    /* Key addition */
    byte_xor(x, src, rk, 4);

    /* substitution layer */
    z[0] = S1[x[0]];
    z[1] = S0[x[1]];
    z[2] = S1[x[2]];
    z[3] = S0[x[3]];

    /* diffusion layer (M0) */
    y[0] =             z[0]  ^ clefia_mul8(z[1]) ^ clefia_mul2(z[2]) ^ clefia_mulA(z[3]);
    y[1] = clefia_mul8(z[0]) ^             z[1]  ^ clefia_mulA(z[2]) ^ clefia_mul2(z[3]); 
    y[2] = clefia_mul2(z[0]) ^ clefia_mulA(z[1]) ^             z[2]  ^ clefia_mul8(z[3]); 
    y[3] = clefia_mulA(z[0]) ^ clefia_mul2(z[1]) ^ clefia_mul8(z[2]) ^             z[3]; 

    /* xor setelah F0 */
    memcpy(dst, src, 4);
    byte_xor(dst + 4, src + 4, y, 4);
}

/* */
void 
clefia_gfn4(uint8_t * y, const uint8_t * x, const uint8_t * rk, int32_t round)
{
    uint8_t fin[BLOCKSIZEB], fout[BLOCKSIZEB];

    memcpy(fin, x, 16);

    while (round--)
    {
        clefia_f0_xor(fout    , fin    , rk    );
        clefia_f1_xor(fout + 8, fin + 8, rk + 4);

        rk += 8;

        if (round)
        {
            memcpy(fin     , fout + 4, 12);
            memcpy(fin + 12, fout    , 4);
        }
    }
    memcpy(y, fout, 16);
}

void 
clefia_gfn8(uint8_t * y, const uint8_t * x, const uint8_t * rk, int32_t round)
{
    uint8_t fin[32], fout[32];

    memcpy(fin, x, 32);

    while (round--)
    {
        clefia_f0_xor(fout    , fin    , rk    );
        clefia_f1_xor(fout + 8, fin + 8, rk + 4);

        rk += 8;

        if (round)
        {
            memcpy(fin     , fout + 4, 12);
            memcpy(fin + 12, fout    , 4);
        }
    }
    memcpy(y, fout, 16);
}

void 
clefia_gfn4_inv(uint8_t * y, const uint8_t * x, const uint8_t * rk, int32_t round)
{
    uint8_t fin[BLOCKSIZEB], fout[BLOCKSIZEB];

    rk += (round - 1) * 8;
    memcpy(fin, x, 16);
    while (round--)
    {
        clefia_f0_xor(fout    , fin    , rk    );
        clefia_f1_xor(fout + 8, fin + 8, rk + 4);

        rk -= 8;

        if (round)
        {
            memcpy(fin    , fout + 12,  4);
            memcpy(fin + 4, fout     , 12);
        }
    }
    memcpy(y, fout, 16);
}

void 
clefia_double_swap(uint8_t * lk)
{
    uint8_t t[BLOCKSIZEB];

    t[0] = (lk[0] << 7) | (lk[1]  >> 1);
    t[1] = (lk[1] << 7) | (lk[2]  >> 1);
    t[2] = (lk[2] << 7) | (lk[3]  >> 1);
    t[3] = (lk[3] << 7) | (lk[4]  >> 1);
    t[4] = (lk[4] << 7) | (lk[5]  >> 1);
    t[5] = (lk[5] << 7) | (lk[6]  >> 1);
    t[6] = (lk[6] << 7) | (lk[7]  >> 1);
    t[7] = (lk[7] << 7) | (lk[15] & 0x7FU);

    t[ 8] = (lk[ 8] >> 7) | (lk[ 0] & 0xFEU); 
    t[ 9] = (lk[ 9] >> 7) | (lk[ 8] << 1); 
    t[10] = (lk[10] >> 7) | (lk[ 9] << 1); 
    t[11] = (lk[11] >> 7) | (lk[10] << 1); 
    t[12] = (lk[12] >> 7) | (lk[11] << 1); 
    t[13] = (lk[13] >> 7) | (lk[12] << 1); 
    t[14] = (lk[14] >> 7) | (lk[13] << 1); 
    t[15] = (lk[15] >> 7) | (lk[14] << 1); 

    memcpy(lk, t, 16);
}

void 
clefia_con_set(uint8_t * con, const uint8_t * iv, int32_t lk)
{
    uint8_t t[2];
    uint8_t tmp;

    memcpy(t, iv, 2);
    while(lk--)
    {
        con[0] = t[0] ^ 0xB7U;      /* P_16 = 0xb7e1 (natural logarithm) */
        con[1] = t[1] ^ 0xE1U;
        con[2] = ~((t[0] << 1) | (t[1] >> 7));
        con[3] = ~((t[1] << 1) | (t[0] >> 7));
        con[4] = ~t[0] ^ 0x24U;     /* Q_16 = 0x243f (circle ratio) */
        con[5] = ~t[1] ^ 0x3FU;
        con[6] = t[1];
        con[7] = t[0];
        con += 8;

        /* updating T */
        if(t[1] & 0x01U)
        {
            t[0] ^= 0xA8U;
            t[1] ^= 0x30U;
        }
        tmp  = t[0] << 7;
        t[0] = (t[0] >> 1) | (t[1] << 7);
        t[1] = (t[1] >> 1) | tmp;
    }    
}

/**
 * Key setup functions
 */

void 
clefia_key_set_128(uint8_t * rkeys, const uint8_t * skey)
{
    const uint8_t iv[2] = { 0x42U, 0x8AU };    /* akar pangkat tiga dari 2 */
    uint8_t lk[BLOCKSIZEB];
    uint8_t con128[4 * 60];
    int32_t i;

    /* generating CONi^(128) (0 <= i < 60, lk = 30) */
    clefia_con_set(con128, iv, 30);

    /* GFN_{4,12} (generating L from K) */
    clefia_gfn4(lk, skey, con128, 12);

    memcpy(rkeys, skey, 8);         /* initial whitening key (WK0, WK1) */
    rkeys += 8;
    for(i = 0; i < 9; i++)
    { 
        /* round key (RKi (0 <= i < 36)) */
        byte_xor(rkeys, lk, con128 + i * 16 + (4 * 24), 16);
        if(i % 2)
            byte_xor(rkeys, rkeys, skey, 16); /* Xoring K */
        
        clefia_double_swap(lk);     /* Updating L (DoubleSwap function) */
        rkeys += 16;
    }
    memcpy(rkeys, skey + 8, 8); /* final whitening key (WK2, WK3) */
}

void 
clefia_key_set_192(uint8_t * rkeys, const uint8_t * skey)
{
    const uint8_t iv[2] = { 0x71U, 0x37U }; /* cubic root of 3 */
    uint8_t skey256[32];
    uint8_t lk[32];
    uint8_t con192[4 * 84];
    int32_t i;

    memcpy(skey256, skey, 24);
    for(i = 0; i < 8; i++)
        skey256[i + 24] = ~skey[i];

    /* generating CONi^(192) (0 <= i < 84, lk = 42) */
    clefia_con_set(con192, iv, 42);

    /* GFN_{8,10} (generating L from K) */
    clefia_gfn8(lk, skey256, con192, 10);

    byte_xor(rkeys, skey256, skey256 + 16, 8); /* initial whitening key (WK0, WK1) */
    rkeys += 8;
    for(i = 0; i < 11; i++)
    { 
        /* round key (RKi (0 <= i < 44)) */
        if((i / 2) % 2)
        {
            byte_xor(rkeys, lk + 16, con192 + i * 16 + (4 * 40), 16);  /* LR */
            if(i % 2)
                byte_xor(rkeys, rkeys, skey256 + 0,  16);     /* Xoring KL */
            
            clefia_double_swap(lk + 16);    /* updating LR */
        }
        else
        {
            byte_xor(rkeys, lk + 0,  con192 + i * 16 + (4 * 40), 16); /* LL */
            if(i % 2)
                byte_xor(rkeys, rkeys, skey256 + 16, 16); /* Xoring KR */
            
            clefia_double_swap(lk + 0);     /* updating LL */
        }
        rkeys += 16;
    }
    byte_xor(rkeys, skey256 + 8, skey256 + 24, 8);     /* final whitening key (WK2, WK3) */
}

void 
clefia_key_set_256(uint8_t * rkeys, const uint8_t * skey)
{
    const uint8_t iv[2] = {0xb5, 0xc0U}; /* cubic root of 5 */
    uint8_t lk[32];
    uint8_t con256[4 * 92];
    int32_t i;

    /* generating CONi^(256) (0 <= i < 92, lk = 46) */
    clefia_con_set(con256, iv, 46);

    /* GFN_{8,10} (generating L from K) */
    clefia_gfn8(lk, skey, con256, 10);

    byte_xor(rkeys, skey, skey + 16, 8);   /* initial whitening key (WK0, WK1) */
    rkeys += 8;
    for(i = 0; i < 13; i++)
    { 
        /* round key (RKi (0 <= i < 52)) */
        if((i / 2) % 2)
        {
            byte_xor(rkeys, lk + 16, con256 + i * 16 + (4 * 40), 16); /* LR */
            if(i % 2)
                byte_xor(rkeys, rkeys, skey + 0,  16);    /* Xoring KL */
            
            clefia_double_swap(lk + 16);            /* updating LR */
        }
        else
        {
            byte_xor(rkeys, lk + 0,  con256 + i * 16 + (4 * 40), 16); /* LL */
            if(i % 2)
                byte_xor(rkeys, rkeys, skey + 16, 16);    /* Xoring KR */
            
            clefia_double_swap(lk + 0);             /* updating LL */
        }
        rkeys += 16;
    }
    byte_xor(rkeys, skey + 8, skey + 24, 8); /* final whitening key (WK2, WK3) */
}

int32_t 
key_setup(clefia_t * config, const uint8_t * skey, uint32_t bits)
{
    config->bits = bits;
    switch (config->bits)
    {
        case 128:
            clefia_key_set_128(config->rkeys, skey);
            config->round = 18;
            break;
        case 192:
            clefia_key_set_192(config->rkeys, skey);
            config->round = 22;
            break;
        case 256:
            clefia_key_set_256(config->rkeys, skey);
            config->round = 26;
            break;
        default:
            config->round = 0;
    }

    return config->round;   /* invalid key_bitlen */
}


/* *************************** HELPER FUNCTIONS *************************** */
/* Xor 2 block data */
void 
xor_block(uint8_t * dst, uint8_t * src1, uint8_t * src2)
{
    byte_xor(dst, src1, src2, BLOCKSIZEB);
}


/* ******************* MODE OF OPERATIONS IMPLEMENTATION ******************* */
/*
    Enkripsi block data dengan mode ECB.
    Enkripsi diberlakukan secara independen tanpa ada hubungan dengan block
    sebelum dan berikutnya.
    Pastikan jumlah block valid.
*/
void 
clefia_encrypt_ecb(uint8_t * data, uint32_t length, uint8_t * key)
{
    uint32_t   i;
    clefia_t   config;

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
clefia_decrypt_ecb(uint8_t * data, uint32_t length, uint8_t * key)
{
    uint32_t   i;
    clefia_t   config;

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
clefia_encrypt_cbc(uint8_t * data, uint32_t length, uint8_t * key, uint8_t * iv)
{
    uint32_t   i;
    clefia_t   config;
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
clefia_decrypt_cbc(uint8_t * data, uint32_t length, uint8_t * key, uint8_t * iv)
{
    uint32_t   i;
    clefia_t   config;
    uint8_t    prev_block[BLOCKSIZEB];
    uint8_t    cipher_block[BLOCKSIZEB];

    // Setup configuration
    key_setup(&config, key, KEYSIZE);
    
    memcpy(prev_block, iv, 16);

    for (i = 0; i < length; i += BLOCKSIZEB)
    {
        // Simpan block ciphertext untuk operasi XOR berikutnya.
        memcpy(cipher_block, &data[i], BLOCKSIZEB);

        // Dekripsi ciphertext menjadi block
        block_decrypt(&config, &data[i]);

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
clefia_encrypt_cfb(uint8_t * data, uint32_t length, uint8_t * key, uint8_t * iv)
{
    uint32_t   i;
    clefia_t   config;
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
void 
clefia_decrypt_cfb(uint8_t * data, uint32_t length, uint8_t * key, uint8_t * iv)
{
    uint32_t   i;
    clefia_t   config;
    uint8_t    prev_block[BLOCKSIZEB];
    uint8_t    ctext_block[BLOCKSIZEB];

    // Setup configuration
    key_setup(&config, key, KEYSIZE);

    memcpy(prev_block, iv, BLOCKSIZEB);

    for (i = 0; i < length; i += BLOCKSIZEB)
    {
        // Simpan block cipher untuk operasi
        memcpy(cipher_block, &data[i], BLOCKSIZEB);

        // Enkripsi block sebelumnya
        // gunakan IV bila ini block pertama
        block_encrypt(&config, prev_block);

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
clefia_encrypt_ctr(uint8_t * data, uint32_t length, uint8_t * key, uint8_t *nonce)
{
    uint32_t   i;
    clefia_t   config;
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
clefia_decrypt_ctr(uint8_t * data, uint32_t length, uint8_t * key, uint8_t *nonce)
{
    uint32_t   i;
    clefia_t   config;
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
clefia_encrypt_ofb(uint8_t * data, uint32_t length, uint8_t * key, uint8_t * iv)
{
    uint32_t   i;
    clefia_t   config;
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
void 
clefia_decrypt_ofb(uint8_t * data, uint32_t length, uint8_t * key, uint8_t * iv)
{
    uint32_t   i;
    clefia_t   config;
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
void 
clefia_encrypt_pcbc(uint8_t * data, uint32_t length, uint8_t * key, uint8_t * iv)
{
    uint32_t   i;
    clefia_t   config;
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
void 
clefia_decrypt_pcbc(uint8_t * data, uint32_t length, uint8_t * key, uint8_t * iv)
{
    uint32_t   i;
    clefia_t   config;
    uint8_t    prev_block[BLOCKSIZEB];
    uint8_t    ctext_block[BLOCKSIZEB];

    // Setup configuration
    config.bits = 128;
    key_setup(&config, key, KEYSIZE);
    
    memcpy(prev_block, iv, 16);

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
    int32_t  i, length;
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
            { 0x13, 0x51, 0x00, 0x30, 0xDD, 0xD2, 0x94, 0x49, 0xA5, 0x3E, 0x68, 0xF6,
              0x41, 0x5E, 0xC6, 0x3C  };

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
    clefia_encrypt_ecb(encbuffer, 64, key);       // ECB
    // clefia_encrypt_cbc(encbuffer, 64, key, iv);   // CBC
    // clefia_encrypt_cfb(encbuffer, 64, key, iv);   // CFB
    // clefia_encrypt_ctr(encbuffer, 64, key, iv);   // CTR
    // clefia_encrypt_ofb(encbuffer, 64, key, iv);   // OFB
    // clefia_encrypt_pcbc(encbuffer, 64, key, iv);  // PCBC
    printx("Encrypted:", encbuffer, 64);

    // Dekripsi - block: 128   key: 256
    memcpy(decbuffer, encbuffer, 64);
    clefia_decrypt_ecb(decbuffer, 64, key);       // ECB
    // clefia_decrypt_cbc(decbuffer, 64, key, iv);   // CBC
    // clefia_decrypt_cfb(decbuffer, 64, key, iv);   // CFB
    // clefia_decrypt_ctr(decbuffer, 64, key, iv);   // CTR
    // clefia_decrypt_ofb(decbuffer, 64, key, iv);   // OFB
    // clefia_decrypt_pcbc(decbuffer, 64, key, iv);  // PCBC
    printx("Decrypted:", decbuffer, 64);

    printf("\nFinal: %s\n", decbuffer);

    return 0;
}
