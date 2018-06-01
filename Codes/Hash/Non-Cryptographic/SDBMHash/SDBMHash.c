/*
    Archive of Reversing.ID
    Non-Cryptographic Hash

    Assemble:
        (gcc)
        $ gcc -m32 -S -masm=intel -o SDBMHash.asm SDBMHash.c

        (msvc)
        $ cl /c /FaSDBMHash.asm SDBMHash.c
*/
#include <stdint.h>

uint32_t SDBMHash (const char* key, uint32_t length)
{
    uint32_t state = 0;
    uint32_t i = 0;

    for (i = 0; i < length; ++key, i++)
    {
        state = (*key) + (state << 6) + (state << 16) - state;
    }
    return state;
}