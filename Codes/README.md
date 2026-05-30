# Implementasi Kode

Implementasi algoritma kriptografi dalam bahasa C.

Setiap implementasi berdiri sendiri tanpa ketergantungan pada library kriptografi eksternal. Penggunaan library untuk keperluan primitif (aritmetika bilangan besar, dsb.) tetap diperbolehkan.

---

## Daftar Isi

- [Cipher](#cipher)
  - [Block Cipher](#block-cipher)
  - [Classic Cipher — Substitusi](#classic-cipher--substitusi)
  - [Classic Cipher — Transposisi](#classic-cipher--transposisi)
  - [Stream Cipher](#stream-cipher)
- [Hash Function](#hash-function)
  - [Cryptographic Hash](#cryptographic-hash)
  - [Non-Cryptographic Hash](#non-cryptographic-hash)

---

## Cipher

### Block Cipher

Direktori: [`Cipher/Block/`](Cipher/Block/)

Mode operasi block cipher (ECB, CBC, CFB, CTR, OFB, PCBC) diimplementasikan sekali di [`Cipher/Block/mode.c`](Cipher/Block/mode.c). Setiap algoritma hanya berisi primitif (`block_encrypt` / `block_decrypt`) dan adaptor [`cipher_port.h`](Cipher/Block/cipher_port.h).

**Build (dari `Codes/Cipher/Block/`):**

```text
gcc -I. -o test main.c mode.c <CipherDir>/code.c
cl /I. main.c mode.c <CipherDir>/code.c
```

Teori mode: [`References/Modern/Encryption-Mode/`](../References/Modern/Encryption-Mode/).

**Pengecualian:** [`XXTEA`](Cipher/Block/XXTEA/) memakai `main()` sendiri dan tidak memakai `main.c` / `mode.c`.

| Algoritma | Keterangan |
|-----------|-----------|
| [3-Way](Cipher/Block/3-Way/) | |
| [Anubis](Cipher/Block/Anubis/) | |
| [BlowFish](Cipher/Block/BlowFish/) | |
| [CIPHERUNICORN-A](Cipher/Block/CIPHERUNICORN-A/) | |
| [CLEFIA](Cipher/Block/CLEFIA/) | |
| [Camellia](Cipher/Block/Camellia/) | |
| [CAST](Cipher/Block/CAST/) | CAST-128 (CAST5), 64-bit block, RFC 2144 |
| [DES](Cipher/Block/DES/) | Data Encryption Standard |
| [DFC](Cipher/Block/DFC/) | AES finalist; Decorrelated Fast Cipher (Feistel, 8 rounds) |
| [Hierocrypt3](Cipher/Block/Hierocrypt3/) | |
| [HIGHT](Cipher/Block/HIGHT/) | Lightweight block cipher (ISO/IEC 18033-3) |
| [KHAZAD](Cipher/Block/KHAZAD/) | |
| [Khufu](Cipher/Block/Khufu/) | |
| [LEA](Cipher/Block/LEA/) | Lightweight Encryption Algorithm |
| [Lucifer](Cipher/Block/Lucifer/) | Pendahulu DES |
| [Madryga](Cipher/Block/Madryga/) | Block cipher 1984, data-dependent rotations |
| [MARS](Cipher/Block/MARS/) | AES finalist |
| [MISTY1](Cipher/Block/MISTY1/) | Nested Feistel, 64-bit block, 8 rounds; RFC 2994; basis of KASUMI |
| [PRESENT](Cipher/Block/PRESENT/) | lightweight cipher |
| [RC6](Cipher/Block/RC6/) | AES finalist |
| [SAFER](Cipher/Block/SAFER/) | |
| [Speck](Cipher/Block/Speck/) | |
| [TEA](Cipher/Block/TEA/) | Tiny Encryption Algorithm |
| [TwoFish](Cipher/Block/TwoFish/) | AES finalist; successor to Blowfish |
| [Treyfer](Cipher/Block/Treyfer/) | |
| [XTEA](Cipher/Block/XTEA/) | Extended TEA |
| [XXTEA](Cipher/Block/XXTEA/) | Corrected Block TEA |

### Classic Cipher — Substitusi

Direktori: [`Cipher/Classic/Substitution/`](Cipher/Classic/Substitution/)

| Algoritma | Keterangan |
|-----------|-----------|
| [ADFGVX](Cipher/Classic/Substitution/ADFGVX/) | Cipher fraksionasi + transposisi (WWI) |
| [ADFGX](Cipher/Classic/Substitution/ADFGX/) | Pendahulu ADFGVX |
| [Affine](Cipher/Classic/Substitution/Affine/) | Generalisasi Caesar dengan fungsi linear |
| [Atbash](Cipher/Classic/Substitution/Atbash/) | Cipher substitusi terbalik |
| [AutoKey](Cipher/Classic/Substitution/AutoKey/) | |
| [Baconian](Cipher/Classic/Substitution/Baconian/) | Cipher steganografi biner |
| [Beaufort](Cipher/Classic/Substitution/Beaufort/) | Varian Vigenere |
| [Bifid](Cipher/Classic/Substitution/Bifir/) | Polybius + fraksionasi |
| [Caesar](Cipher/Classic/Substitution/Caesar/) | Cipher geser sederhana |
| [Four-Square](Cipher/Classic/Substitution/Four-Square/) | |
| [Fractionated-Morse](Cipher/Classic/Substitution/Fractionated-Morse/) | |
| [Great](Cipher/Classic/Substitution/Great/) | |
| [Hill](Cipher/Classic/Substitution/Hill/) | Cipher berbasis aljabar linear |
| [Homophonic-Substitution](Cipher/Classic/Substitution/Homophonic-Substitution/) | |
| [Playfair-Cipher](Cipher/Classic/Substitution/Playfair-Cipher/) | Cipher digram |
| [Polybius-Cipher](Cipher/Classic/Substitution/Polybius-Cipher/) | |
| [Porta](Cipher/Classic/Substitution/Porta/) | |
| [ROT13](Cipher/Classic/Substitution/ROT13/) | Caesar dengan pergeseran 13 |
| [Straddle](Cipher/Classic/Substitution/Straddle/) | |
| [Trifid](Cipher/Classic/Substitution/Trifid/) | Ekstensi Bifid ke 3 dimensi |
| [Two-Square](Cipher/Classic/Substitution/Two-Square/) | |
| [Vigenere-Gronsfeld](Cipher/Classic/Substitution/Vigenere-Gronsfeld/) | Vigenere dengan kunci numerik |

### Classic Cipher — Transposisi

Direktori: [`Cipher/Classic/Transposition/`](Cipher/Classic/Transposition/)

| Algoritma | Keterangan |
|-----------|-----------|
| [Columnar-Permutation](Cipher/Classic/Transposition/Columnar-Permutation/) | |
| [Myszkowski-Transposition](Cipher/Classic/Transposition/Myszkowski-Transposition/) | |
| [Rail-Fence](Cipher/Classic/Transposition/Rail-Fence/) | |
| [Route-Cipher](Cipher/Classic/Transposition/Route-Cipher/) | |

### Stream Cipher

Direktori: [`Cipher/Stream/`](Cipher/Stream/)

Setiap algoritma hanya berisi primitif stream cipher dan adaptor [`stream_port.h`](Cipher/Stream/stream_port.h). Demo harness ada di [`main.c`](Cipher/Stream/main.c).

Port mengekspor `STREAM_KEY_BYTES`, `STREAM_NONCE_BYTES`, dan `STREAM_COUNTER_BYTES` per algoritma, serta `stream_encrypt` / `stream_decrypt` dengan argumen `key`, `nonce`, dan `counter` terpisah. Ukuran buffer maksimum harness ada di komentar [`main.c`](Cipher/Stream/main.c) (key 32, nonce 16, counter 4).

**Build (dari `Codes/Cipher/Stream/`):**

```text
gcc -I. -o test main.c <CipherDir>/code.c
cl /I. main.c <CipherDir>/code.c
```

**Catatan:** SAVILLE masih stub — algoritma bersifat classified (NSA Suite A) sehingga tidak ada spesifikasi publik untuk diimplementasikan.

| Algoritma | Keterangan |
|-----------|-----------|
| [ChaCha20](Cipher/Stream/ChaCha20/) | Varian Salsa20 oleh Bernstein |
| [Loiss](Cipher/Stream/Loiss/) | |
| [RC4](Cipher/Stream/RC4/) | Stream cipher klasik (sudah usang) |
| [SAVILLE](Cipher/Stream/SAVILLE/) | |
| [SNOW](Cipher/Stream/SNOW/) | Stream cipher berbasis LFSR |
| [Salsa20](Cipher/Stream/Salsa20/) | |

---

## Hash Function

### Cryptographic Hash

Direktori: [`Hash/Cryptographic/`](Hash/Cryptographic/)

| Algoritma | Keterangan |
|-----------|-----------|
| [AR](Hash/Cryptographic/AR/) | |
| [ARIRANG](Hash/Cryptographic/ARIRANG/) | SHA-3 candidate |
| [AURORA](Hash/Cryptographic/AURORA/) | SHA-3 candidate |
| [Abacus](Hash/Cryptographic/Abacus/) | |
| [Argon2](Hash/Cryptographic/Argon2/) | Password hashing (PHC winner) |
| [BLAKE](Hash/Cryptographic/BLAKE/) | SHA-3 finalist |
| [Blender](Hash/Cryptographic/Blender/) | |
| [Boognish](Hash/Cryptographic/Boognish/) | |
| [Boole](Hash/Cryptographic/Boole/) | |
| [Catena](Hash/Cryptographic/Catena/) | Password hashing |
| [Cheetah](Hash/Cryptographic/Cheetah/) | |
| [CubeHash](Hash/Cryptographic/CubeHash/) | SHA-3 candidate |
| [DASH](Hash/Cryptographic/DASH/) | |
| [DHA-256](Hash/Cryptographic/DHA-256/) | |
| [ECHO](Hash/Cryptographic/ECHO/) | SHA-3 candidate |
| [FFTHash](Hash/Cryptographic/FFTHash/) | |
| [FORK-256](Hash/Cryptographic/FORK-256/) | |
| [FSBHash](Hash/Cryptographic/FSBHash/) | |
| [Fugue](Hash/Cryptographic/Fugue/) | SHA-3 candidate |
| [GOST 34.11-94](Hash/Cryptographic/GOST%2034.11-94/) | Standar hash Rusia |
| [Grindahl](Hash/Cryptographic/Grindahl/) | |
| [Grostl](Hash/Cryptographic/Grostl/) | SHA-3 finalist |
| [HAS-160](Hash/Cryptographic/HAS-160/) | |
| [HAS-V](Hash/Cryptographic/HAS-V/) | |
| [HAVAL](Hash/Cryptographic/HAVAL/) | |
| [HNF](Hash/Cryptographic/HNF/) | |
| [Hamsi](Hash/Cryptographic/Hamsi/) | SHA-3 candidate |
| [JH](Hash/Cryptographic/JH/) | SHA-3 finalist |
| [Keccak](Hash/Cryptographic/Keccak/) | SHA-3 winner |
| [LAKE](Hash/Cryptographic/LAKE/) | |
| [LASH-n](Hash/Cryptographic/LASH-n/) | |
| [Luffa](Hash/Cryptographic/Luffa/) | SHA-3 candidate |
| [Lyra2](Hash/Cryptographic/Lyra2/) | Password hashing |
| [MAME](Hash/Cryptographic/MAME/) | |
| [MD](Hash/Cryptographic/MD/) | MD2, MD4, MD5 |
| [Makwa](Hash/Cryptographic/Makwa/) | Password hashing |
| [N-Hash](Hash/Cryptographic/N-Hash/) | |
| [PARSHA](Hash/Cryptographic/PARSHA/) | |
| [PKC-Hash](Hash/Cryptographic/PKC-Hash/) | |
| [Panama](Hash/Cryptographic/Panama/) | |
| [RIPEMD](Hash/Cryptographic/RIPEMD/) | RIPEMD-128/160/256/320 |
| [RadioGatun](Hash/Cryptographic/RadioGatun/) | |
| [SHA](Hash/Cryptographic/SHA/) | SHA-1, SHA-2 (224/256/384/512), SHA-3 |
| [SHAvite-3](Hash/Cryptographic/SHAvite-3/) | SHA-3 candidate |
| [SIMD](Hash/Cryptographic/SIMD/) | SHA-3 candidate |
| [SMASH](Hash/Cryptographic/SMASH/) | |
| [SWIFTX](Hash/Cryptographic/SWIFTX/) | |
| [Sarmal](Hash/Cryptographic/Sarmal/) | |
| [Shabal](Hash/Cryptographic/Shabal/) | SHA-3 candidate |
| [Skein](Hash/Cryptographic/Skein/) | SHA-3 finalist |
| [Snefru](Hash/Cryptographic/Snefru/) | |
| [Streebog](Hash/Cryptographic/Streebog/) | GOST R 34.11-2012 |
| [Tiger](Hash/Cryptographic/Tiger/) | |
| [VSH](Hash/Cryptographic/VSH/) | |
| [Vortex](Hash/Cryptographic/Vortex/) | |
| [Whirlpool](Hash/Cryptographic/Whirlpool/) | |
| [yescrypt](Hash/Cryptographic/yescrypt/) | Password hashing |

### Non-Cryptographic Hash

Direktori: [`Hash/Non-Cryptographic/`](Hash/Non-Cryptographic/)

Digunakan untuk kebutuhan seperti hash table dan checksum, bukan untuk keamanan kriptografis.

| Algoritma | Keterangan |
|-----------|-----------|
| [APHash](Hash/Non-Cryptographic/APHash/) | Arash Partow Hash |
| [BKDRHash](Hash/Non-Cryptographic/BKDRHash/) | |
| [BPHash](Hash/Non-Cryptographic/BPHash/) | |
| [DEKHash](Hash/Non-Cryptographic/DEKHash/) | Donald E. Knuth Hash |
| [DJBHash](Hash/Non-Cryptographic/DJBHash/) | Daniel J. Bernstein Hash |
| [ELFHash](Hash/Non-Cryptographic/ELFHash/) | Digunakan pada format ELF Unix |
| [FNV](Hash/Non-Cryptographic/FNV/) | Fowler–Noll–Vo |
| [Goulburn](Hash/Non-Cryptographic/Goulburn/) | |
| [JSHash](Hash/Non-Cryptographic/JSHash/) | Justin Sobel Hash |
| [Jenkins](Hash/Non-Cryptographic/Jenkins/) | Bob Jenkins Hash |
| [MurmurHash](Hash/Non-Cryptographic/MurmurHash/) | |
| [PJWHash](Hash/Non-Cryptographic/PJWHash/) | Peter J. Weinberger Hash |
| [PearsonHash](Hash/Non-Cryptographic/PearsonHash/) | |
| [RSHash](Hash/Non-Cryptographic/RSHash/) | Robert Sedgwick Hash |
| [SDBMHash](Hash/Non-Cryptographic/SDBMHash/) | |
