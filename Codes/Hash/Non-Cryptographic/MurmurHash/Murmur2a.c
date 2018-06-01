/*
	Hash function by Austin Appleby
    Archive of Reversing.ID
    Non-Cryptographic Hash

    Varian MurmurHash2 yang dimodifikasi untuk menggunakan Merkle-Damgard construction.

    Assemble:
        (gcc)
        $ g++ -m32 -S -masm=intel -o Murmur2a.asm Murmur2a.c

        (msvc)
        $ cl /c /FaDJBHash.asm Murmur2a.c
*/
#include <stdint.h>

#define mmix(h,k) { k *= m; k ^= k >> r; k *= m; h *= m; h ^= k; }

uint32_t Murmur2A ( const void * key, int length, uint32_t seed )
{
	// 'm' dan 'r' adalah konstanta untuk mixing
	const uint32_t m = 0x5bd1e995;
	const int32_t  r = 24;
    uint32_t l = length;

	// Inisialisasi internal state
	uint32_t state = seed;

	// Mix 4 bytes sekaligus dalam hash
	const unsigned char * data = (const unsigned char *)key;
	while(length >= 4)
	{
		uint32_t k = *(uint32_t *)data;

		mmix(state, k);

		data += 4;
		length -= 4;
	}
	
	// Menangani residu jika ukuran input bukan kelipatan 4
    uint32_t t = 0;
	switch(length)
	{
	case 3: t ^= data[2] << 16;
	case 2: t ^= data[1] << 8;
	case 1: t ^= data[0];
	};

	// Final mix untuk memastikan byte terakhir benar-benar diolah
	mmix(state, t);
    mmix(state, l);

	return state;
} 
