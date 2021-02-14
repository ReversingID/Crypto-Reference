# Crypto-Reference

## BLAKE2 Hash

* Pencipta: 

    - Jean-Philippe Aumasson
    - Samuel Neves
    - Zooko Wilcox-O'Hearn
    - Christian Winnerlein

* Kategori: Cryptographic Hash
* Ukuran block (bit): -
* Ukuran state (bit): -
* Ukuran hash (bit): 

    - 8 - 512 (BLAKE2b)
    - 8 - 256 (BLAKE2s)
    - arbitrary (BLAKE2X)

* Jumlah round: 

    - 12 (BLAKE2b)
    - 10 (BLAKE2s)

* Struktur:
* IV: -
* Diturunkan dari:

    - [BLAKE](../BLAKE)

* Penerus:

    - [BLAKE3](../BLAKE3)

## Notes

- mendukung keying salt
- BLAKE2B digunakan oleh beberapa skema password hashing (Argon2, Catena, Lanarea, Lyra/Lyra2, Neoscrypt, RIG, TwoCats, Yarn)

## Reversing Notes

- Initialization vector untuk BLAKE2b

```
    IV0 = 0x6a09e667f3bcc908   // Frac(sqrt(2))
    IV1 = 0xbb67ae8584caa73b   // Frac(sqrt(3))
    IV2 = 0x3c6ef372fe94f82b   // Frac(sqrt(5))
    IV3 = 0xa54ff53a5f1d36f1   // Frac(sqrt(7))
    IV4 = 0x510e527fade682d1   // Frac(sqrt(11))
    IV5 = 0x9b05688c2b3e6c1f   // Frac(sqrt(13))
    IV6 = 0x1f83d9abfb41bd6b   // Frac(sqrt(17))
    IV7 = 0x5be0cd19137e2179   // Frac(sqrt(19))
```