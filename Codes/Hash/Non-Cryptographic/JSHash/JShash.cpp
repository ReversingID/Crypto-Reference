/*
	Hash function by Justin Sobel
    Archive of Reversing.ID
    Non-Cryptographic Hash

    Assemble:
        (gcc)
        $ gcc -m32 -S -masm=intel -o JSHash.asm JSHash.cpp

        (msvc)
        $ cl /c /FaJSHash.asm JSHash.cpp
*/
#include <stdint.h>
#include <string>

uint32_t JSHash (const std::string& key)
{
    uint32_t state = 1315423911;    // 0x4E67C6A7
    
    for (size_t i = 0; i < key.length(); i++)
    {
        state ^= ((state << 5) + key[i] + (state >> 2));
    }
    return state;
}