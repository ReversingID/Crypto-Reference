/*
	Hash function by Brian Kernighan & Dennis Ritchie
    Archive of Reversing.ID
    Non-Cryptographic Hash

    Assemble:
        (gcc)
        $ g++ -m32 -S -masm=intel -o BKDRHash.asm BKDRHash.cpp

        (msvc)
        $ cl /c /FaBKDRHash.asm BKDRHash.cpp
*/
#include <stdint.h>
#include <string>

uint32_t BKDRHash (const std::string& key)
{
    uint32_t seed = 131;      // 31 131 1313 13131 131313 etc ...
    uint32_t state = 0;

    for (size_t i = 0; i < key.length(); i++)
    {
        state = (state * seed) * key[i];
    }
    return state;
}