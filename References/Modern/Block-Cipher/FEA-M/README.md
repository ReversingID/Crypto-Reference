# Crypto Reference

## FEA-M Cipher

Fast Encryption Algorithm for Multimedia.

* Pencipta:
    - X. Yi
    - C.H. Tan
    - C. K. Siew
    - M. R. Syed
* Kategori: Block Cipher
* Ukuran block (bit): 4096
* Ukuran kunci (bit): 40942
* Jumlah round: 1
* Struktur: Lai-Massey Scheme
* Diturunkan dari: 
* Penerus: 

Semua kalkulasi FEA-M dilakukan terhadap 64x64 matriks binary. Setiap block dienkripsi menggunakan dua perkalian dan dua penjumlahan. Data terenkripsi menggunakan sepasang "session key" yang dipilih hanya untuk pesan tersebut. Kuncimerupakan invertible matrix. Session key harus dikirim bersama pesan dalam keadaan terenkripsi.