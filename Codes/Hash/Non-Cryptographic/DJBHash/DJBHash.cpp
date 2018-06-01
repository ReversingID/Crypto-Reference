/*
	Hash function by Daniel J. Bernstein
    Archive of Reversing.ID
    Non-Cryptographic Hash

    Assemble:
        (gcc)
        $ g++ -m32 -S -masm=intel -o DJBHash.asm DJBHash.cpp

        (msvc)
        $ cl /c /FaDJBHash.asm DJBHash.cpp
*/
#include <stdint.h>
#include <string>

uint32_t DJBHash (const std::string& key)
{
    uint32_t state = 5381;      // 0x1505

    for (size_t i = 0; i < key.length(); i++)
    {
        state = ((state << 5) + state) + key[i];
    }
    return state;
}