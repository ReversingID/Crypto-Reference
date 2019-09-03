#include <stdio.h>
#include <stdint.h>
#include <string.h>

void encrypt(const char *message, char *encrypted_message, uint32_t len, uint32_t shift);
void decrypt(const char *encrypted_message, char *decrypted_message, uint32_t len, uint32_t shift);

int main() {
	char message[1001];
	char encrypted_message[1001];
	char decrypted_message[1001];
	uint32_t len;
	uint32_t shift;
	int option;

	printf("1. Encrypt\n");
	printf("2. Decrypt\n");
	printf("Pilihan: ");
	scanf("%d", &option);

	//membersihkan buffer
	while(getchar() != '\n');
	printf("\n");

	switch(option) {
		case 1:
			printf("Masukkan pesan yang akan dienkripsi (MAX: 1000 karakter)\n");
			fgets(message, 1000, stdin);

			printf("Berapa karakter yang akan digeser? ");
			scanf("%d", &shift);

			len = strlen(message) - 1;
			message[len] = 0;

			encrypt(message, encrypted_message, len, shift);
			printf("%s\n", encrypted_message);

			break;
		case 2:
			printf("Masukkan pesan yang akan didekripsi (MAX: 1000 karakter)\n");
			fgets(encrypted_message, 1000, stdin);

			printf("Berapa karakter yang tergeser? ");
			scanf("%d", &shift);

			len = strlen(encrypted_message) - 1;
			encrypted_message[len] = 0;

			decrypt(encrypted_message, decrypted_message, len, shift);
			printf("%s\n", decrypted_message);

			break;
		default:
			printf("Pilihan tidak tersedia\n");
	}

	return 0;
}

void encrypt(const char *message, char *encrypted_message, uint32_t len, uint32_t shift) {
	for(uint32_t i = 0; i < len; ++i) {
		if(message[i] >= 0x41 && message[i] <= 0x5A || message[i] >= 0x61 && message[i] <= 0x7A) {
			encrypted_message[i] = ((message[i] <= 0x5A? message[i] - 0x41: message[i] - 0x61) + shift) % 26 + 0x41;
		} else {
			encrypted_message[i] = message[i];
		}
	}

	encrypted_message[len] = 0;
}

void decrypt(const char *encrypted_message, char *decrypted_message, uint32_t len, uint32_t shift) {
	for(uint32_t i = 0; i < len; ++i) {
		if(encrypted_message[i] >= 0x41 && encrypted_message[i] <= 0x5A || encrypted_message[i] >= 0x61 && encrypted_message[i] <= 0x7A) {
			decrypted_message[i] = ((encrypted_message[i] <= 0x5A? encrypted_message[i] - 0x41: encrypted_message[i] - 0x61) - shift);
			decrypted_message[i] = (decrypted_message[i] < 0? 26 + decrypted_message[i]: decrypted_message[i]) + 0x41;	
		} else {
			decrypted_message[i] = encrypted_message[i];
		}
	}

	decrypted_message[len] = 0;
}
