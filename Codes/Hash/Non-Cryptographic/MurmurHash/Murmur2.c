/*
	Hash function by Austin Appleby
    Archive of Reversing.ID
    Non-Cryptographic Hash

    Assemble:
        (gcc)
        $ g++ -m32 -S -masm=intel -o Murmur2.asm Murmur2.c

        (msvc)
        $ cl /c /FaDJBHash.asm Murmur2.c
*/
#include <stdint.h>

uint32_t Murmur2 ( const void * key, int length, uint32_t seed )
{
	// 'm' dan 'r' adalah konstanta untuk mixing
	const uint32_t m = 0x5bd1e995;
	const int32_t  r = 24;

	// Inisialisasi internal state
	uint32_t state = seed ^ length;

	// Mix 4 bytes sekaligus dalam hash
	const unsigned char * data = (const unsigned char *)key;
	while(length >= 4)
	{
		uint32_t k = *(uint32_t *)data;

		k *= m; 
		k ^= k >> r; 
		k *= m; 
		
		state *= m; 
		state ^= k;

		data += 4;
		length -= 4;
	}
	
	// Menangani residu jika ukuran input bukan kelipatan 4
	switch(length)
	{
	case 3: state ^= data[2] << 16;
	case 2: state ^= data[1] << 8;
	case 1: state ^= data[0];
	        state *= m;
	};

	// Final mix untuk memastikan byte terakhir benar-benar diolah
	state ^= state >> 13;
	state *= m;
	state ^= state >> 15;

	return state;
} 
