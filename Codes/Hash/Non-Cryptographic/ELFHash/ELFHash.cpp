/*
    Modifikasi PJWHash untuk sistem UNIX.
    Archive of Reversing.ID
    Non-Cryptographic Hash

    Assemble:
        (gcc)
        $ g++ -m32 -S -masm=intel -o ELFHash.asm ELFHash.cpp

        (msvc)
        $ cl /c /FaELFHash.asm ELFHash.cpp
*/
#include <stdint.h>
#include <string>

uint32_t ELFHash (const std::string& key)
{
    uint32_t test = 0;
    uint32_t state = 0;

    for (size_t i = 0; i < key.length(); i++)
    {
        state = (state << 4) + key[i];

        test = state & 0xF0000000;
        if (test)
        {
            state ^= (test >> 24);
        }
        state &= ~test;
    }
    return state;
}