/*
	Hash function by Austin Appleby
    Archive of Reversing.ID
    Non-Cryptographic Hash

    Assemble:
        (gcc)
        $ gcc -m32 -S -masm=intel -o Murmur3.asm Murmur3.c

        (msvc)
        $ cl /c /FaDJBHash.asm Murmur3.c
*/
#include <stdint.h>

// 32-bit Murmur3 Hash
uint32_t Murmur3(const uint8_t * key, size_t length, uint32_t seed)
{
    uint32_t state = seed;
    if (length > 3)
    {
        const uint32_t * key_x4 = (const uint32_t*) key;
        size_t i = length >> 2;
        do 
        {
            uint32_t k = *key_x4++;
            k *= 0xCC9E2D51;
            k = (k << 15) | (k >> 17);
            k *= 0x1B873593;

            state ^= k;
            state = (state << 13) | (state >> 19);
            state = (state * 5) + 0xE6546B64;
        } while (--i);
    }
    if (length & 3)
    {
        size_t i = length & 3;
        uint32_t k = 0;
        key = &key[i - 1];
        do 
        {
            k <<= 8;
            k |= *key--;
        } while (--i);
        k *= 0xCC9E2D51;
        k = (k << 15) | (k >> 17);
        k *= 0x1B873593;

        state ^= k;
    }
    state ^= length;
    state ^= state >> 16;
    state *= 0x85EBCA6B;
    state ^= state >> 13;
    state *= 0xC2B2AE35;
    state ^= state >> 16;

    return state;
}