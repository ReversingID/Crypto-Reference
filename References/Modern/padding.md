# Crypto Reference

Padding mechanism.

## Introduction

Padding merupakan sebuah mekanisme untuk menambahkan nilai yang telah ditentukan ke block pesan. Mekanisme ini digunakan dalam algoritma yang berkaitan dengan blok data.

Terdapat beberapa skema padding yang dipakai dalam praktik kriptografi.

### PKCS#5 dan PKCS#7

Skema `PKCS#7` dijabarkan dalam `RFC 5652`.

Setiap byte yang menjadi padding akan memiliki nilai seragam. Nilai dari setiap pad byte ini merupakan jumlah byte yang ditambahkan ke dalam block.

Misal, sebuah block utuh berukuran 8-byte. Terdapat block yang hanya memiliki ukuran 4 byte. Padding akan menambahkan 4 buah byte di akhir dengan nilai `0x04` (block size - ukuran block saat ini).

```
[ ... | DD DD DD DD DD DD DD DD | DD DD DD DD 04 04 04 04 ]
```

### ISO 7816-4

Skema ini mengacu kepada standard `ISO/EIC 7816-4 2005`.

Dalam skema ini, padding dapat dianggap sebagai beberapa byte yang berurutan dengan byte awal padding memiliki nilai 0x80 dan byte lainnya memiliki nilai 0x00.

Misal, sebuah block utuh berukuran 8-byte. Terdapat block yang hanya memiliki ukuran 4 byte. Proses padding dilakukan dengan menambahkan 4 buah byte di akhir dengan nilai 80 00 00 00

```
[ ... | DD DD DD DD DD DD DD DD | DD DD DD DD 80 00 00 00 ]
```

### ISO 10126-2

Skema ini telah ditarik pada tahun 2007 dan tidak direkomendasikan dalam praktik kriptografi.

Dalam skema ini, padding dapat dianggap sebagai beberapa byte yang acak (random) dengan byte akhir bernilai banyaknya pad byte yang diberikan.

Misal, sebuah block utuh berukuran 8-byte. Terdapat blok yang hanya memiliki ukuran 4 byte. Proses padding dilakukan dengan menambahkan 3 buah byte secara random dan sebuah byte bernilai 0x04.

```
[ ... | DD DD DD DD DD DD DD DD | DD DD DD DD 13 51 03 04 ]
```

### ANSI X9.23

Dalam skema ini, padding dapat dianggap sebagai beberapa byte bernilai 0x00 dengan byte akhir bernilai banyaknya pad byte yang diberikan.

Misal, sebuah block utuh berukuran 8-byte. Terdapat blok yang hanya memiliki ukuran 4 byte. Proses padding dilakukan dengan menambahkan 3 buah byte 0x00 dan sebuah byte bernilai 0x04.

```
[ ... | DD DD DD DD DD DD DD DD | DD DD DD DD 00 00 00 04 ]
```

### Zero Bytes

Dalam skema ini, padding dapat dianggap sebagai beberapa byte yang seluruhnya bernilai 0x00. Padding ini sangat tidak dapat diandalkan (unreliable) dalam praktik pertukaran data. Salah satu kasus yang dapat menggambarkan hal ini adalah bila terdapat byte 0x00 di ujung block, maka akan terjadi kerancuan dalam interpretasi, bagaimana data sesungguhnya sebelum padding terjadi.

Misal, sebuah block utuh berukuran 8-byte. Terdapat block yang hanya memiliki ukuran 4 byte. Proses padding dilakukan dengan menambahkan 4 buah byte 0x00.

```
[ ... | DD DD DD DD DD DD DD DD | DD DD DD DD 00 00 00 00 ]
```

Skema ini sebaiknya tidak dilakukan dalam desain sistem yang baru. Namun skema ini mungkin akan ditemui dalam beberapa aplikasi legacy (jadul).