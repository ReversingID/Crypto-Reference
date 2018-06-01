/*
	Hash function by Donald E. Knuth
    Archive of Reversing.ID
    Non-Cryptographic Hash

    Assemble:
        (gcc)
        $ gcc -m32 -S -masm=intel -o DEKHash.asm DEKHash.c

        (msvc)
        $ cl /c /FaDEKHash.asm DEKHash.c
*/
#include <stdint.h>

uint32_t DEKHash (const char* key, uint32_t length)
{
    uint32_t state = length;
    uint32_t i = 0;

    for (i = 0; i < length; ++key, i++)
    {
        state = ((state << 5) + (state >> 27)) ^ (*key);
    }
    return state;
}