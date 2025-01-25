/*
    Algorithm Test
    Archive of Reversing.ID

    Unified code to test the implementation of cryptographic algorithm.
    Use this along with the algorithm code.c

    Eliminate the need to implement main function for each algorithm.

Compile:
    (msvc)
    $ cl main.c code.c
*/
#include <stdint.h>
#include <stdio.h>

/* ********************* PROTOTYPES ********************* */
void encrypt_ecb(uint8_t * data, uint32_t length, uint8_t * key);
void decrypt_ecb(uint8_t * data, uint32_t length, uint8_t * key);

void encrypt_cbc(uint8_t * data, uint32_t length, uint8_t * key, uint8_t * iv);
void decrypt_cbc(uint8_t * data, uint32_t length, uint8_t * key, uint8_t * iv);

void encrypt_cfb(uint8_t * data, uint32_t length, uint8_t * key, uint8_t * iv);
void decrypt_cfb(uint8_t * data, uint32_t length, uint8_t * key, uint8_t * iv);

void encrypt_ctr(uint8_t * data, uint32_t length, uint8_t * key, uint8_t * nonce);
void decrypt_ctr(uint8_t * data, uint32_t length, uint8_t * key, uint8_t * nonce);

void encrypt_ofb(uint8_t * data, uint32_t length, uint8_t * key, uint8_t * iv);
void decrypt_ofb(uint8_t * data, uint32_t length, uint8_t * key, uint8_t * iv);

void encrypt_pcbc(uint8_t * data, uint32_t length, uint8_t * key, uint8_t * iv);
void decrypt_pcbc(uint8_t * data, uint32_t length, uint8_t * key, uint8_t * iv);

/*

*/
typedef enum { ECB, CBC, CFB, CTR, OFB, PCBC } MODE;

void encrypt(MODE mode, uint8_t * data, uint32_t length, uint8_t * key, uint8_t * iv)
{
    switch (mode)
    {
        case ECB:  encrypt_ecb(data, length, key);
            break;
        case CBC:  encrypt_cbc(data, length, key, iv);
            break;
        case CFB:  encrypt_cfb(data, length, key, iv);
            break;
        case CTR:  encrypt_ctr(data, length, key, iv);      // gunakan IV sebagai nonce
            break;
        case OFB:  encrypt_ofb(data, length, key, iv);
            break;
        case PCBC: encrypt_pcbc(data, length, key, iv);
            break;
    }
}

void decrypt(MODE mode, uint8_t * data, uint32_t length, uint8_t * key, uint8_t * iv)
{
    switch (mode)
    {
        case ECB:  decrypt_ecb(data, length, key);
            break;
        case CBC:  decrypt_cbc(data, length, key, iv);
            break;
        case CFB:  decrypt_cfb(data, length, key, iv);
            break;
        case CTR:  decrypt_ctr(data, length, key, iv);      // gunakan IV sebagai nonce
            break;
        case OFB:  decrypt_ofb(data, length, key, iv);
            break;
        case PCBC: decrypt_pcbc(data, length, key, iv);
            break;
    }
}

void printx(const char * label, const uint8_t * data, size_t length)
{
    printf("%s: ", label);
    for (size_t i = 0; i < length; i++)
    {
        if (i % 16 == 0)
            printf("\n    ");
        printf("%02X ", data[i]);
    }
    printf("\n");
}


int main(int argc, char* argv[])
{
    uint32_t length;
    char     data[] = "Reversing.ID - Reverse Engineering Community";
 
    // buffer untuk encryption and decryption
    uint8_t  buffer[64];
    uint32_t size = 64;         // ukuran data yang digunakan (kelipatan block)

    /*
    secret key: 32-bytes
    Key dengan panjang maksimal untuk mengakomodasi beragam panjang key. 
    
    - 64-bit (8-byte)
    - 128-bit (16-byte)
    - 192-bit (24-byte)
    - 256-bit (32-byte)
    */
    uint8_t key[32] = {
            0x52, 0x45, 0x56, 0x45, 0x52, 0x53, 0x49, 0x4E, 0x47, 0x2E, 0x49, 0x44, 
/* ASCII:     R     E     V     E     R     S     I     N     G     .     I     D  */
            0x53, 0x45, 0x43, 0x52, 0x45, 0x54, 0x20, 0x4b, 0x45, 0x59, 0x31, 0x32,
          /*  S     E     C     R     E     T           K     E     Y     1     2  */
            0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x30 
    };    /*  3     4     5     6     7     8     9     0 */
    
    /*
    initialization vector: 32-bytes
    IV menyesuaikan dengan ukuran block yang digunakan.
    */
    uint8_t iv[32] = { 
        0xbd, 0xd7, 0x42, 0x56, 0xa9, 0x52, 0xf9, 0x79, 
        0x12, 0xb3, 0x91, 0x28, 0xe8, 0xd7, 0x51, 0xe8, 
        0x5a, 0xb8, 0x7e, 0x68, 0x79, 0x8d, 0x18, 0x8d, 
        0x89, 0xd8, 0x97, 0xd1, 0x6a, 0x79, 0x42, 0xa 
    };

    length = strlen(data);
    printf("Length: %d - Buffer: %s\n", length, data);
    printx("Original", data, size);

    /*
    Inisialisasi setiap buffer dengan 0
    salin data ke buffer
    */
    memset(buffer, 0, sizeof(buffer));
    memcpy(buffer, data, length);

    /*
    Proses enkripsi
    Pastikan panjang data merupakan kelipatan dari ukuran block.

    gunakan mode untuk mengganti mode enkripsi yang digunakan.
    */
    encrypt(ECB, buffer, size, key, iv);
    printx("Encrypted", buffer, size);

    /*
    Proses dekripsi
    */
    decrypt(ECB, buffer, size, key, iv);
    printx("Decrypted", buffer, size);

    printf("\nFinal: %s\n", buffer);

    return 0;
}