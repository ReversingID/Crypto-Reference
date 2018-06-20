# Crypto Reference

## Implementasi Zodiac

Zodiac menggunakan struktur Feistel network dengan key-whitening. Round function hanya menggunakan XOR dan S-Box lookup.

Terdapat dua 8x8-bit S-Box: 
    - berdasarkan discrete exponentation 45^x seperti di SAFER
    - multiplicative inverse di finite field GF(2^8) seperti di SHARK

## Referensi Utama

* Zodiac 1.0 - Architecture and Specification. [lihat](Zodiac_V1.0.pdf)

## Aplikasi