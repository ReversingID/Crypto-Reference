/*
	Hash function by Justin Sobel
    Archive of Reversing.ID
    Non-Cryptographic Hash

    Assemble:
        (gcc)
        $ gcc -m32 -S -masm=intel -o JSHash.asm JSHash.c

        (msvc)
        $ cl /c /FaJSHash.asm JSHash.c
*/
#include <stdint.h>

uint32_t JSHash (const char* key, uint32_t length)
{
    uint32_t state = 1315423911;    // 0x4E67C6A7
    uint32_t i = 0;

    for (i = 0; i < length; ++key, i++)
    {
        state ^= ((state << 5) + (*key) + (state >> 2));
    }
    return state;
}