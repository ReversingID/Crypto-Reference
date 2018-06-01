/*
	Hash function by Peter J. Weinberger
    Archive of Reversing.ID
    Non-Cryptographic Hash

    Assemble:
        (gcc)
        $ g++ -m32 -S -masm=intel -o PJWHash.asm PJWHash.cpp

        (msvc)
        $ cl /c /FaPJWHash.asm PJWHash.cpp
*/
#include <stdint.h>
#include <string>

uint32_t PJWHash (const std::string& key)
{    
    const uint32_t BitsInUnsignedInt = (uint32_t) (sizeof(uint32_t) * 8);
    const uint32_t ThreeQuarters     = (uint32_t) ((BitsInUnsignedInt * 3) / 4);
    const uint32_t OneEight          = (uint32_t) (BitsInUnsignedInt / 8);
    const uint32_t HighBits          = (uint32_t) (0xFFFFFFFF) << (BitsInUnsignedInt - OneEight);

    uint32_t test = 0;
    uint32_t state = 0; 
    
    for (size_t i = 0; i < key.length(); i++)
    {
        state = (state << OneEight) + key[i];

        // HighBits tidak diset
        test = state & HighBits;
        if (test)
        {
            state = ((state ^ (test >> ThreeQuarters)) & ~HighBits);
        }
    }
    return state;
}