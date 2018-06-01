/*
	Hash function by Arash Partow
    Archive of Reversing.ID
    Non-Cryptographic Hash

    Assemble:
        (gcc)
        $ g++ -m32 -S -masm=intel -o APHash.asm APHash.cpp

        (msvc)
        $ cl /c /FaAPHash.asm APHash.cpp
*/
#include <stdint.h>
#include <string>

uint32_t APHash (const std::string& key)
{
    uint32_t state = 0xAAAAAAAA;

    for (size_t i = 0; i < key.length(); i++)
    {
        if (i & 1)
            state ^= (~((state << 11) + (key[i] ^ (state >> 5))));
        else 
            state ^=  ( (state <<  7) ^  key[i] * (state >> 3));
    }
    return state;
}