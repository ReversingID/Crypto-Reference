# Crypto Reference

## Implementasi SM4

Beberapa detail tentang algoritma ini:

* menggunakan 8-bit S-Box.
* Operasi yang digunakan adalah XOR, 32-bit circular shift, dan S-Box.
* setiap round mengupdate seperempat dari internal state (alias 32 bit dari 128 bit).
* non-linear key schedul digunakan untuk menghasilkan round key.

## Referensi Utama

* 2008 - SMS4 Encryptio Algorithm for Wireless Networks. [lihat](2008.sms4.pdf)

## Aplikasi