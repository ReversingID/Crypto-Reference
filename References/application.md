# Crypto Reference

Keseluruhan poin dari ilmu kriptografi adalah menjaga kerahasiaan plaintext (atau kunci, atau keduanya) dari penyadap (eavesdropper) atau kriptanalis (cryptanalyst).

Namun seiring perkembangan ilmu, penggunaan kriptografi kini tak terbatas hanya dalam perlindungan pesan saja. Beberapa hal terkait komunikasi melibatkan kriptografi di dalamnya. 

## Kegunaan Kriptografi

Secara umum kriptografi mencakup dua komponen dasar keamanan informasi, yaitu kerahasiaan (`confidentiality`) dan keutuhan (`integrity`).

Secara umum konsep kriptografi dapat diterapkan untuk:

* Menjaga kerahasiaan pesan.
* Menjaga integritas data.
* Keabsahan pengirim (user authentication).
* Antipenyangkalan (nonrepudiation).

## Kriptografi Dalam Kehidupan Sehari-hari

-- Smart card --

Salah satu aplikasi `PKI (Public-Key Infrastructure)` yang kian ramai digunakan. Kartu cerdas memiliki rupa fisik berupa kartu dengan chip di dalamnya dan digunakan untuk melayani banyak fungsi, mulai dari otentikasi hingga penyimpanan data.

Untuk dapat beroperasi, kartu cerdas membutuhkan daya eksternal yang didapatkan dari pembaca (reader).

Kartu cerdas menyimpan kunci privat, sertifikat digital, dan informasi lainnya untuk mengimplementasikan PKI. Selain komponen kriptografi, kartu cerdas juga menyimpan data lain sesuai kebutuhannya seperti nomor kartu kredit, informasi kontak personal, dll.

Untuk otentikasi kartu, server akan mengirimkan suatu nilai atau string yang disebut challenge ke kartu untuk ditandatangani dengan kunci private yang tersimpan di dalam kartu. Hasil ini kemudian akan diverifikasi oleh mesin dengan kunci publik pemilik kartu.

-- Pay TV --

Pay TV adalah jasa siaran TV yang hanya dapat dinikmati oleh pelanggan yang membayar (berlangganan). Siaran Pay TV dipancarkan secara broadcast namun hanya sejumlah pesawat TV yang berhasil menangkap siaran tersebut.

Informasi yang dipancarkan pada Pay TV telah dienkripsi dengan kunci yang unik.

Secara umum proses otentikasi dan enkripsi/dekripsi pesan melalui tahap berikut:

- Setiap pelanggan mendapatkan smart card yang mengandung kunci private yang unik.
- Kartu cerdas dimasukkan ke dalam reader yang dipasang pada TV.
- Pelanggan dikirimi kunci simetri yang terenkripsi dengan kunci publik pelanggan.
- Smart card mendekripsi kunci simetri ini dengan kunci private yang dimiliki.
- Kunci simetri kemudian digunakan untuk mendekripsi siaran TV.

