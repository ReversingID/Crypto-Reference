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
#include <string>

uint32_t BPHash (const std::string& key)
{
    uint32_t state = 0;

    for (size_t i = 0; i < key.length(); i++)
    {
        state = state << 7 ^ key[i];
    }
    return state;
}