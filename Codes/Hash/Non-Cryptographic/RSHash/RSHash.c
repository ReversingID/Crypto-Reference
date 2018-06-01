/*
	Hash function by Robert Sedgwicks
    Archive of Reversing.ID
    Non-Cryptographic Hash

    Assemble:
        (gcc)
        $ gcc -m32 -S -masm=intel -o RSHash.asm RSHash.c

        (msvc)
        $ cl /c /FaRSHash.asm RSHash.c
*/
#include <stdint.h>

uint32_t RSHash (const char* key, uint32_t length)
{
    uint32_t b = 378551;            // 0x5C6B7
    uint32_t a = 63689;             // 0xF8C9
    uint32_t state = 0;
    uint32_t i = 0;

    for (i = 0; i < length; ++key, i++)
    {
        state = state * a + (*key);
        a     = a * b;
    }
    return state;
}