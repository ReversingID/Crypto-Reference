#include <stdio.h>
#include <math.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>

uint32_t decode(uint32_t val) {
	uint32_t result = 0;

	result = val & 0b11111111;
	result = (result << 8) | (val >> 8) & 0b11111111;
	result = (result << 8) | (val >> 16) & 0b11111111;
	result = (result << 8) | (val >> 24) & 0b11111111;

	return result;
}

int main() {
	const uint32_t S1[4] = {7, 12, 17, 22};
	const uint32_t S2[4] = {5, 9, 14, 20};
	const uint32_t S3[4] = {4, 11, 16, 23};
	const uint32_t S4[4] = {6, 10, 15, 21};
	char message[1000];

	printf("Masukkan string yang akan di hash (MAX: 1000 karakter)\n");
	fgets(message, 1000, stdin);

	uint32_t len = strlen(message) - 1;
	uint32_t new_len = ((len + 8) / 64 + 1) * 64;
	char *padded_message = (char *) calloc(new_len, sizeof(char));
	
	//padding message
	strncpy(padded_message, message, len);
	//menambahkan bit "1" di akhir pesan
	padded_message[len] |= 0b10000000; 

	//menambahkan panjang bit orginal string ke padded_message
	uint32_t l = len * 8;
	memcpy(&padded_message[new_len - 8], &l, 4);

	//inisialisasi konstanta spesial, T
	uint32_t T[64];
	for(uint32_t i = 0; i < 64; ++i) {
		double temp = sin(i + 1);
		temp = (temp < 0)? (temp * -1): temp;
		T[i] = temp * 4294967296;
	}

	uint32_t A = 0x67452301;
	uint32_t B = 0xEFCDAB89;
	uint32_t C = 0x98BADCFE;
	uint32_t D = 0x10325476;

	for(uint32_t i = 0; i < new_len; i += 64) {
		uint32_t AA = A;
		uint32_t BB = B;
		uint32_t CC = C;
		uint32_t DD = D;

		//membagi padded_message menjadi 16 blok yang masing-masing berukuran 32bit
		uint32_t *X = (uint32_t *) (padded_message + i);

		for(uint32_t j = 0; j < 64; ++j) {
			uint32_t F, s, g;

			if(j < 16) {
				F = (B & C) | (~B & D);
				s = S1[j % 4];
				g = j;
			} else if (j < 32) {
				F = (B & D) | (C & ~D);
				s = S2[j % 4];
				g = (5 * j + 1) % 16;
			} else if (j < 48) {
				F = B ^ C ^ D;
				s = S3[j % 4];
				g = (3 * j + 5) % 16;
			} else {
				F = C ^ (B | ~D);
				s = S4[j % 4];
				g = (7 * j) % 16;
			}

			F = F + A + T[j] + X[g];
			A = D;
			D = C;
			C = B;
			// ((F << s) | (F >> (32 - s))) digunakan untuk merotasi bit ke kiri
			B = B + ((F << s) | (F >> (32 - s)));
		}

		A = A + AA;
		B = B + BB;
		C = C + CC;
		D = D + DD;
	}

	printf("\n%08X%08X%08X%08X\n", decode(A), decode(B), decode(C), decode(D));

	return 0;
}

/*
 * Referensi:
 * http://www.herongyang.com/Cryptography/MD5-Message-Digest-Algorithm-Overview.html
 * https://en.wikipedia.org/wiki/MD5
 * https://fthb321.github.io/MD5-Hash/MD5OurVersion2.html
 * http://www.miraclesalad.com/webtools/md5.php
 * https://gist.github.com/creationix/4710780
 */
