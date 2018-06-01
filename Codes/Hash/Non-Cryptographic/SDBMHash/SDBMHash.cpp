/*
	Hash function by Arash Partow
    Archive of Reversing.ID
    Non-Cryptographic Hash

    Assemble:
        (gcc)
        $ g++ -m32 -S -masm=intel -o SDBMHash.asm SDBMHash.cpp

        (msvc)
        $ cl /c /FaSDBMHash.asm SDBMHash.cpp
*/
#include <stdint.h>
#include <string>

uint32_t SDBMHash (const std::string& key)
{
    uint32_t state = 0;

    for (size_t i = 0; i < key.length(); i++)
    {
        state = key[i] + (state << 6) + (state << 16) - state;
    }
    return state;
}