/*
	Hash function by Arash Partow
    Archive of Reversing.ID
    Non-Cryptographic Hash

    Assemble:
        (gcc)
        $ gcc -m32 -S -masm=intel -o APHash.asm APHash.c

        (msvc)
        $ cl /c /FaAPHash.asm APHash.c
*/
#include <stdint.h>

uint32_t APHash (const char* key, uint32_t length)
{
    uint32_t state = 0xAAAAAAAA;
    uint32_t i = 0;

    for (i = 0; i < length; ++key, i++)
    {
        state ^= (i & 1) ? (~((state << 11) + ((*key) ^ (state >> 5)))) :
                            ( (state <<  7) ^  (*key) * (state >> 3));
    }
    return state;
}