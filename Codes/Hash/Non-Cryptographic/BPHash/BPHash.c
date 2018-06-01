/*
	Hash function by Bruno Preiss
    Archive of Reversing.ID
    Non-Cryptographic Hash

    Assemble:
        (gcc)
        $ gcc -m32 -S -masm=intel -o BPHash.asm BPHash.c

        (msvc)
        $ cl /c /FaBPHash.asm BPHash.c
*/
#include <stdint.h>

uint32_t BPHash (const char* key, uint32_t length)
{
    uint32_t state = 0;
    uint32_t i = 0;

    for (i = 0; i < length; ++key, i++)
    {
        state = state << 7 ^ (*key);
    }
    return state;
}