# Crypto-Reference

## Skein Hash

* Pencipta: 

    - Bruce Schneier
    - Niels Ferguson
    - Stefan Lucks
    - Doug Whiting
    - Mihir Bellare
    - Tadayoshi Kohno
    - Jon Callas
    - Jesse Walker

* Kategori: Cryptographic Hash
* Ukuran block (bit): 256 / 512 / 1024
* Ukuran state (bit): 256 / 512 / 1024
* Ukuran hash (bit): arbitrary
* Jumlah round: 

    - 72 (ukuran blok 256 / 512)
    - 80 (ukuran blok 1024)

* Struktur: Unique Block Iteration
* IV: -
* Diturunkan dari:

    - [Threefish](./../../Block-Cipher/Threefish/)

* Penerus:

## Notes

- Skein diturunkan dari block cipher Threefish, dikompresi dengan Unique Block Iteration (UBI) chaining mode yang merupakan varian dari Matyas-Meyer-Oseas hash mode.

## Reversing Notes
