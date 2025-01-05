/*
    Corrected Block TEA (XXTEA)
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

/* ************************* CONFIGURATION & SEED ************************* */


/* ********************* INTERNAL FUNCTIONS PROTOTYPE ********************* */
void block_encrypt (uint32_t * val, uint32_t N, uint32_t key[4]);
void block_decrypt (uint32_t * val, uint32_t N, uint32_t key[4]);


/* ********************* MODE OF OPERATIONS PROTOTYPE ********************* */


/* ************************ CRYPTOGRAPHY ALGORITHM ************************ */
/*
    Enkripsi serangkaian block dengan XXTEA.
    Sebuah round didefinisikan sebagai sebuah aksi enkripsi pada serangkaian block.
    Sebuah block adalah 2 buah bilangan 32-bit atau setara dengan 64-bit data.
*/
void 
block_encrypt(uint32_t * val, uint32_t N, uint32_t key[4])
{
    uint32_t y, z, i;
    uint32_t k0 = key[0], k1 = key[1], k2 = key[2], k3 = key[3];
    uint32_t delta = 0x9E3779B9, sum, e;
    uint32_t rounds = 6 + 52/N;

    z = val[N-1];
    sum = 0;
    do {
        sum += delta;
        e = (sum >> 2) & 3;

        for (i =  0; i < N-1; i++)
        {
            y = val[i+1];
            val[i] += (((z>>5 ^ y<<2) + (y>>3 ^ z<<4)) ^ ((sum ^ y) + (key[(i & 3) ^ e] ^ z)));
            z = val[i];
        }

        y = val[0];
        val[N-1] += (((z>>5 ^ y<<2) + (y>>3 ^ z<<4)) ^ ((sum ^ y) + (key[(i & 3) ^ e] ^ z)));
        z = val[N-1];
    } while (--rounds);
}

/*
    Dekripsi serangkaian block dengan XXTEA.
    Sebuah round didefinisikan sebagai sebuah aksi enkripsi pada serangkaian block.
    Sebuah block adalah 2 buah bilangan 32-bit atau setara dengan 64-bit data.
*/
void 
block_decrypt(uint32_t * val, uint32_t N, uint32_t key[4])
{
    uint32_t y, z, i;
    uint32_t k0 = key[0], k1 = key[1], k2 = key[2], k3 = key[3];
    uint32_t delta = 0x9E3779B9, sum = 0, e;
    uint32_t rounds = 6 + 52/N;

    y = val[0];
    sum = rounds * delta;
    do {
        e = (sum >> 2) & 3;

        for (i = N-1; i > 0; i--)
        {
            z = val[i-1];
            val[i] -= (((z>>5 ^ y<<2) + (y>>3 ^ z<<4)) ^ ((sum ^ y) + (key[(i & 3) ^ e] ^ z)));
            y = val[i];
        }

        z = val[N-1];
        val[0] -= (((z>>5 ^ y<<2) + (y>>3 ^ z<<4)) ^ ((sum ^ y) + (key[(i & 3) ^ e] ^ z)));
        y = val[0];

        sum -= delta;
    } while (--rounds);
}


/* ******************* INTERNAL FUNCTIONS IMPLEMENTATION ******************* */


/* *************************** HELPER  FUNCTIONS *************************** */


/* ******************* MODE OF OPERATIONS IMPLEMENTATION ******************* */





/* *************************** CONTOH PENGGUNAAN *************************** */
#include "../testutil.h"

int main(int argc, char* argv[])
{
    int  i, length;
    char data[] = "Reversing.ID - Reverse Engineering Community";
    char encbuffer[64];
    char decbuffer[64]; 
    
    uint32_t key[4] = { 0x52455645, 0x5253494E, 0x472E4944, 0x31323334 };
         /* ASCII dari:   R E V E     R S I N     G . I D     1 2 3 4 */
    uint32_t iv[2]  = { 0x13510030, 0x28c53139 };


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

    // Enkripsi
    memcpy(encbuffer, data, length);
    block_encrypt((uint32_t*)encbuffer, 16, key);
    printx("Encrypted:", encbuffer, 64);

    // Dekripsi
    memcpy(decbuffer, encbuffer, 64);
    block_decrypt((uint32_t*)decbuffer, 16, key);
    printx("Decrypted:", decbuffer, 64);

    printf("\nFinal: %s\n", decbuffer);

    return 0;
}