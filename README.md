# Crypto Reference

[![Kontribusi Diterima](https://img.shields.io/badge/kontribusi-diterima-brightgreen.svg)](CONTRIBUTING.md)

> Repositori terbuka berisi kode dan referensi kriptografi untuk keperluan reverse engineering.

Bahasa: **[Indonesia](README.md)** | [English](README-EN.md)

---

## Daftar Isi

- [Tentang Repositori](#tentang-repositori)
- [Apa itu Kriptografi?](#apa-itu-kriptografi)
- [Kriptografi dan Reverse Engineering](#kriptografi-dan-reverse-engineering)
- [Konten](#konten)
  - [Buku](#buku)
  - [Kode](#kode)
  - [Referensi](#referensi)
  - [Alat](#alat)
- [Berkontribusi](#berkontribusi)

---

## Tentang Repositori

Repository ini digunakan untuk menghimpun informasi dan pengetahuan tentang implementasi kriptografi serta kerentanan yang berhubungan dengannya. Di sini terdapat berbagai referensi tentang pemanfaatan kriptografi secara praktikal maupun analisis terhadapnya, utamanya untuk menambah pemahaman dalam melakukan reversing sesuatu yang bersinggungan dengan kriptografi.

Repository ini merupakan repository bebas dan terbuka. Siapapun, baik internal maupun eksternal komunitas [Reversing.ID](https://reversing.id), dapat mengakses dan memanfaatkannya.

---

## Apa itu Kriptografi?

Kriptografi merupakan ilmu yang mempelajari tentang teknik dalam menjaga keamanan pesan/komunikasi dengan asumsi terdapat ancaman keberadaan pihak ketiga.

Penggunaan kriptografi secara umum mencakup:

- menjaga kerahasiaan data agar tak diketahui oleh pihak yang tak berkepentingan.
- memberikan jaminan bahwa tidak ada perubahan data yang terjadi di luar kuasa sumber informasi.
- memberikan jaminan bahwa informasi yang diberikan berasal dari pihak yang benar.

---

## Kriptografi dan Reverse Engineering

Reverse Engineering dalam beberapa hal berkaitan erat dengan kriptografi.

Seringkali dalam sebuah analisis terdapat bagian-bagian tertentu yang mengalami proteksi, baik terhadap kode maupun data. Kriptografi menjadi tulang punggung dalam beberapa proteksi modern, seperti penggunaan enkripsi pada packer maupun protector aplikasi, penggunaan cryptosystem untuk verifikasi serial number, enkripsi pada output file, dan sebagainya.

Dengan demikian, pemahaman konsep kriptografi yang baik dapat membantu secara signifikan dalam proses Reverse Engineering.

---

## Konten

### Buku

Direktori [`Books/`](Books/) berisi buku dan sumber belajar kriptografi yang bebas atau berlisensi terbuka.

| Judul | Keterangan |
|-------|-----------|
| [A Graduate Course in Applied Cryptography](Books/a-graduate-course-in-cryptography.pdf) | Mencakup banyak konstruksi untuk berbagai task kriptografi |
| [Crypto 101](Books/crypto101.pdf) | Pengantar kriptografi untuk pemula |
| [Teori dan Aplikasi Kriptografi](Books/teori-dan-aplikasi-kriptografi.pdf) | Buku berbahasa Indonesia |
| [The Joy of Cryptography](Books/the-joy-of-cryptography.pdf) | Pengantar kriptografi berbasis proof |

Lihat juga [daftar buku eksternal lengkap](References/README.md#books).

### Kode

Direktori [`Codes/`](Codes/) berisi implementasi algoritma kriptografi dalam bahasa C. Setiap implementasi berdiri sendiri tanpa ketergantungan pada library kriptografi eksternal.

**Cipher**

| Kategori | Algoritma |
|----------|-----------|
| [Block Cipher](Codes/Cipher/Block/) | 3-Way, Anubis, Blowfish, Camellia, DES, KHAZAD, LEA, Lucifer, MARS, SAFER, TEA, Treyfer, XTEA, XXTEA, dll |
| [Classic — Substitusi](Codes/Cipher/Classic/Substitution/) | ADFGVX, Affine, Atbash, AutoKey, Beaufort, Caesar, Hill, Playfair, ROT13, Vigenere, dll |
| [Classic — Transposisi](Codes/Cipher/Classic/Transposition/) | Columnar-Permutation, Myszkowski, Rail-Fence, Route-Cipher |
| [Stream Cipher](Codes/Cipher/Stream/) | ChaCha20, Loiss, RC4, SAVILLE, SNOW, Salsa20 |

**Hash**

| Kategori | Algoritma |
|----------|-----------|
| [Cryptographic Hash](Codes/Hash/Cryptographic/) | BLAKE, Keccak, MD keluarga, RIPEMD, SHA keluarga, Skein, Whirlpool, dan lainnya |
| [Non-Cryptographic Hash](Codes/Hash/Non-Cryptographic/) | APHash, DJBHash, FNV, Jenkins, MurmurHash, PearsonHash, dan lainnya |

Lihat [indeks implementasi lengkap](Codes/README.md).

### Referensi

Direktori [`References/`](References/) berisi artikel, analisis, dan dokumentasi mendalam tentang berbagai algoritma kriptografi.

- [`Classical/`](References/Classical/) — Kriptografi klasik (substitusi, transposisi)
- [`Modern/`](References/Modern/) — Kriptografi modern (block cipher, stream cipher, hash, asimetris)
- [`Modern/Structure/`](References/Modern/Structure/) — Struktur kriptografi dasar (Feistel, SPN, Sponge, dsb.)

Lihat [indeks referensi lengkap](References/README.md).

### Alat

Direktori [`Tools/`](Tools/) berisi dokumentasi penggunaan peralatan analisis kriptografi.

| Alat | Keterangan |
|------|-----------|
| [CrypTool](Tools/CrypTool/) | Perangkat lunak open source untuk mempelajari dan menganalisis algoritma kriptografi secara visual |
| [Cryptol](Tools/cryptol/) | Domain-Specific Language untuk spesifikasi dan verifikasi algoritma kriptografi |

---

## Berkontribusi

Repositori ini terbuka untuk semua orang. Kontribusi dapat berupa kode implementasi, referensi, analisis, maupun perbaikan konten yang sudah ada.

Baca [CONTRIBUTING.md](CONTRIBUTING.md) untuk panduan lengkap.
