/*
	Hash function by Daniel J. Bernstein
    Archive of Reversing.ID
    Non-Cryptographic Hash

    Assemble:
        (gcc)
        $ gcc -m32 -S -masm=intel -o DJBHash.asm DJBHash.c

        (msvc)
        $ cl /c /FaDJBHash.asm DJBHash.c
*/
#include <stdint.h>

uint32_t DJBHash (const char* key, uint32_t length)
{
    uint32_t state = 5381;      // 0x1505
    uint32_t i = 0;

    for (i = 0; i < length; ++key, i++)
    {
        state = ((state << 5) + state) + (*key);
    }
    return state;
}