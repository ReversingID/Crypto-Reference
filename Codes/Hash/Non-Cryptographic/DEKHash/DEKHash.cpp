/*
	Hash function by Donald E. Knuth
    Archive of Reversing.ID
    Non-Cryptographic Hash

    Assemble:
        (gcc)
        $ g++ -m32 -S -masm=intel -o DEKHash.asm DEKHash.cpp

        (msvc)
        $ cl /c /FaDEKHash.asm DEKHash.cpp
*/
#include <stdint.h>
#include <string>

uint32_t DEKHash (const std::string& key)
{
    uint32_t state = static_cast<uint32_t>(key.length());

    for (size_t i = 0; i < key.length(); i++)
    {
        state = ((state << 5) + (state >> 27)) ^ key[i];
    }
    return state;
}