/*
    Algorithm Test
    Archive of Reversing.ID

    Unified code to test the implementation of cryptographic algorithm.
    Use this along with the algorithm code.c.

Compile:
    (msvc, from Codes/Cipher/Stream/)
    $ cl /I. main.c <CipherDir>/code.c

    (gcc, from Codes/Cipher/Stream/)
    $ gcc -I. -o test main.c <CipherDir>/code.c
*/
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include "stream_port.h"

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
    size_t   length;
    char     data[] = "Reversing.ID - Reverse Engineering Community";
    uint8_t  buffer[64];

    /*
    Harness buffer sizes (maximum across all stream ciphers in this tree).
    Each linked build reads only STREAM_KEY_BYTES, STREAM_NONCE_BYTES, and
    STREAM_COUNTER_BYTES from stream_port.h; unused trailing bytes are ignored.

    - key[32]     : up to 256-bit key (all ciphers)
    - nonce[16]   : up to 128-bit IV / nonce (SNOW, Loiss, Salsa20 partial, …)
    - counter[4]  : up to 32-bit block counter (ChaCha20)
    */
    uint8_t key[32] = {
            0x52, 0x45, 0x56, 0x45, 0x52, 0x53, 0x49, 0x4E, 0x47, 0x2E, 0x49, 0x44,
/* ASCII:     R     E     V     E     R     S     I     N     G     .     I     D  */
            0x53, 0x45, 0x43, 0x52, 0x45, 0x54, 0x20, 0x4b, 0x45, 0x59, 0x31, 0x32,
          /*  S     E     C     R     E     T           K     E     Y     1     2  */
            0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x30
    };    /*  3     4     5     6     7     8     9     0 */

    uint8_t nonce[16] = {
        0x13, 0x51, 0x00, 0x30, 0xD7, 0xA4, 0xC5, 0xAE,
        0xCB, 0x55, 0xA7, 0x1C, 0x00, 0x00, 0x00, 0x00
    };

    uint8_t counter[4] = {
        0x25, 0x3F, 0x41, 0x4D
    };

    length = strlen(data);
    printf("Length: %zu - Buffer: %s\n", length, data);
    printx("Original", (const uint8_t *)data, length);

    memset(buffer, 0, sizeof(buffer));
    memcpy(buffer, data, length);

    stream_encrypt(buffer, length, key, nonce, counter);
    printx("Encrypted", buffer, length);

    stream_decrypt(buffer, length, key, nonce, counter);
    printx("Decrypted", buffer, length);

    printf("\nFinal: %s\n", buffer);

    return 0;
}
