# Crypto Reference

## Hash Functions

Dalam konteks programming, fungsi hash adalah fungsi apapun yang digunakan untuk memetakan data dengan sembarang ukuran ke data dengan ukuran tetap. Nilai yang dikembalikan oleh fungsi hash disebut juga sebagai **hash values**, **hash codes**, **digest**, atau lazim disebut sebagai **hash** saja.

Sebuah fungsi hash yang baik harus memiliki beberapa property sebagai berikut:

* deterministik: nilai yang sama harus dapat diberikan untuk input yang sama
* uniform: nilai-nilai yang dihasilkan harus memiliki persebaran yang seragam (uniform) di seluruh rentang yang didukung (0 ~ 2**32, misalnya). Artinya tidak ada nilai yang tidak dihasilkan oleh fungsi hash. 
* injektif: fungsi hash bersifat searah, artinya nilai input hanya dipetakan menjadi satu kemungkinan nilai hash (keluaran).

Karena sifat tersebut, fungsi hash banyak digunakan untuk berbagai keperluan yang berkaitan dengan verifikasi integritas data (checksum).

Terdapat beberapa fungsi hash yang telah dikembangkan. Namun dalam bidang kriptografi terdapat beberapa kriteria tambahan yang harus dipenuhi oleh sebuah nilai hash, yang tidak disediakan oleh sembarang fungsi. Beberapa property yang diinginkan tersebut antara lain:

* Pre-image resistance: jika diberikan sebuah nilai hash H, maka sulit untuk mencari pesan P dimana H = hash(P).
* Second pre-image resistance: jika diberikan sebuah input P1, maka sulit untuk mendapat nilai lain P2 (P1 != P2) sedemikian hingga hash(P1) = hash(P2).
* Collision resistance: untuk fungsi hash H, sulit ditemukan pasangan pesan P1 dan P2 yang memiliki nilai berbeda namun menghasilkan nilai hash yang sama sehingga hash(P1) = hash(P2)

Dengan demikian kita dapat mengklasifikasikan fungsi hash menjadi dua kategori yaitu:

* Cryptographic Hash Function
* Non-Cryptographic Hash Function

Meskipun tak disarankan dalam penggunaan kriptografi, namun non-cryptographic hash function dapat pula digunakan dalam berbagai kesempatan untuk keperluan yang sama dengan cryptographic hash function dengan pertimbangan tertentu.

## Struktur Hash

Terdapat beberapa operasi yang lazim digunakan dalam implementasi fungsi hash, antara lain:

* operasi bitwise: ! | & ^ << >> <<< >>>
* operasi matematika: + *
* lookup table: tabel bilangan prima, magic number, [P-Box](../Structure/p-box), [S-Box](../Structure/s-box), dsb.

Sebagian besar fungsi hash, baik kategori Cryptographic Hash maupun Non-Cryptographic Hash, diterapkan dengan multi iterasi. Dalam tiap iterasi, sebuah block dari pesan akan diolah dan memodifikasi buffer internal yang disebut sebagai _internal state_. Umumnya metode yang digunakan dalam struktur fungsi hash mengacu kepada [Merkle-Damgard Construction](../Structure/merkle-damgard-construction).

Beberapa desain algoritma hash menggunakan LUT (Look Up Table). Alasan penggunaan tabel ini bervariasi namun umumnya bertujuan untuk menambah variasi "static values" yang digunakan dalam operasi.

Ketika LUT digunakan dalam fungsi hash, terdapat beberapa kombinasi beberapa kemungkinan lokasi:

* Lookup per round index
* Lookup per internal state
* Lookup per current message

Sementara nilai, ukuran, serta penggunaan LUT merupakan detail implementasi yang bergantung kepada masing-masing hash yang menggunakannya.

Selain konstruksi merkle-damgard yang bersifat linear, sebuah hash dapat pula dikonstruksi secara paralel dengan setiap block diproses terpisah kemudian disatukan dalam operasi pencampuran (mixing). Hal ini dapat secara signifikan meningkatkan throughput fungsi hash ketika dijalankan di atas arsitektur yang mendukung multicore. Metode ini dikenal sebagai Merkle-Tree atau hash tree.

