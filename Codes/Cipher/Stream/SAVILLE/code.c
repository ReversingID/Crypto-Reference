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

Note:
    SAVILLE is a classified NSA/GCHQ Type 1 algorithm (Suite A). No public
    specification exists, so this file keeps the stream_port adapter only.
*/
#include <stdint.h>
#include <stddef.h>


/* stream port for main.c */
#include "stream_port.h"

const uint32_t STREAM_KEY_BYTES     = 32;
const uint32_t STREAM_NONCE_BYTES   = 16;
const uint32_t STREAM_COUNTER_BYTES =  0;

/*
 * stream_port contract
 *
 * Not implemented. SAVILLE is classified (NSA Suite A); no public specification.
 *
 * STREAM_KEY_BYTES     = 32 — accepted for API compatibility.
 * STREAM_NONCE_BYTES   = 16 — accepted for API compatibility.
 * STREAM_COUNTER_BYTES =  0 — counter unused.
 *
 * stream_decrypt : delegates to stream_encrypt (no-op).
 */

void
stream_encrypt(uint8_t *data, size_t length, const uint8_t *key,
               const uint8_t *nonce, const uint8_t *counter)
{
    (void)data;
    (void)length;
    (void)key;
    (void)nonce;
    (void)counter;
    /* TODO: implement — algorithm specification is classified (NSA Suite A) */
}

void
stream_decrypt(uint8_t *data, size_t length, const uint8_t *key,
               const uint8_t *nonce, const uint8_t *counter)
{
    stream_encrypt(data, length, key, nonce, counter);
}
