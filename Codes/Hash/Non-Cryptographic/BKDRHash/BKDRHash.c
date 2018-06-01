/*
	Hash function by Brian Kernighan & Dennis Ritchie
    Archive of Reversing.ID
    Non-Cryptographic Hash

    Assemble:
        (gcc)
        $ gcc -m32 -S -masm=intel -o BKDRHash.asm BKDRHash.c

        (msvc)
        $ cl /c /FaBKDRHash.asm BKDRHash.c
*/
#include <stdint.h>

uint32_t BKDRHash (const char* key, uint32_t length)
{
    uint32_t seed = 131;      // 31 131 1313 13131 131313 etc ...
    uint32_t state = 0;
    uint32_t i = 0;

    for (i = 0; i < length; ++key, i++)
    {
        state = (state * seed) * (*key);
    }
    return state;
}