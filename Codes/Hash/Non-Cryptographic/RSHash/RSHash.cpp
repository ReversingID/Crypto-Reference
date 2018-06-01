/*
	Hash function by Robert Sedgwicks
    Archive of Reversing.ID
    Non-Cryptographic Hash

    Assemble:
        (gcc)
        $ g++ -m32 -S -masm=intel -o RSHash.asm RSHash.cpp

        (msvc)
        $ cl /c /FaRSHash.asm RSHash.cpp
*/
#include <stdint.h>
#include <string>

uint32_t RSHash (const std::string& key)
{
    uint32_t b = 378551;            // 0x5C6B7
    uint32_t a = 63689;             // 0xF8C9
    uint32_t state = 0;

    for (size_t i = 0; i < key.length(); i++)
    {
        state = state * a + key[i];
        a     = a * b;
    }
    return state;
}