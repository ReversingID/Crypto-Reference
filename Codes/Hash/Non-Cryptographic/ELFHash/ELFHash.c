/*
    Modifikasi PJWHash untuk sistem UNIX.
    Archive of Reversing.ID
    Non-Cryptographic Hash

    Assemble:
        (gcc)
        $ gcc -m32 -S -masm=intel -o ELFHash.asm ELFHash.c

        (msvc)
        $ cl /c /FaELFHash.asm ELFHash.c
*/
#include <stdint.h>

uint32_t ELFHash (const char* key, uint32_t length)
{
    uint32_t test = 0;
    uint32_t state = 0;
    uint32_t i = 0;

    for (i = 0; i < length; ++key, i++)
    {
        state = (state << 4) + (*key);

        test = state & 0xF0000000;
        if (test)
        {
            state ^= (test >> 24);
        }
        state &= ~test;
    }
    return state;
}