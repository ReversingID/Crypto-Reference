/*
    SAVILLE
    Archive of Reversing.ID
    Stream Cipher

Compile:
    (msvc, from Codes/Cipher/Stream/)
    $ cl /I. main.c SAVILLE/code.c

    (gcc, from Codes/Cipher/Stream/)
    $ gcc -I. -o test main.c SAVILLE/code.c

    Demo harness is in main.c (not in this file).

Assemble:
    (gcc)
    $ gcc -m32 -S -masm=intel -o SAVILLE/code.asm SAVILLE/code.c

    (msvc)
    $ cl /c /FaSAVILLE/code.asm SAVILLE/code.c
*/
#include <stdint.h>
#include <stddef.h>


/* stream port for main.c */
#include "stream_port.h"

const uint32_t STREAM_KEY_BYTES   = 32;
const uint32_t STREAM_NONCE_BYTES = 16;

void
stream_encrypt(uint8_t *data, size_t length, const uint8_t *key, const uint8_t *nonce)
{
    (void)data;
    (void)length;
    (void)key;
    (void)nonce;
    /* TODO: implement */
}

void
stream_decrypt(uint8_t *data, size_t length, const uint8_t *key, const uint8_t *nonce)
{
    stream_encrypt(data, length, key, nonce);
}
