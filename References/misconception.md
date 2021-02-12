# Crypto Reference

Miskonsepsi dan salah kaprah tentang kriptografi.

## Enkripsi vs Hash vs Encoding

`Enkripsi`, `hash`, dan `encoding` merupakan tiga istilah yang sering dipertukarkan. Banyak orang yang bingung dan menganggap bahwa ketiganya merupakan hal yang sama namun sebenarnya tidak. Ketiga istilah tersebut memiliki konsep yang berbeda meski termasuk dalam kategori yang sama yaitu transformasi data atau mengubah data menjadi bentuk lain yang berbeda.

#### Enkripsi

Tujuan enkripsi adalah untuk menjaga kerahasiaan informasi sehingga hanya orang-orang tertentu yang dapat membaca pesan tersebut. Ciri-ciri enkripsi antara lain:

* menggunakan kunci;
* ukuran data yang dihasilkan (ciphertext) sama atau lebih besar dari data asli (plaintext);
* data dapat dikembalikan ke bentuk semula.

#### Hash

[Hash](References/Modern/Hash) adalah fungsi searah. Hash banyak digunakan untuk melakukan validasi, memastikan integritas dari suatu data terjaga sehingga dapat dideteksi apabila suatu data mengalami perubahan. Ciri-ciri fungsi hash antara lain:

* ukuran data yang dihasilkan tetap meski berapapun ukuran data yang diberikan;
* data tidak dapat dikembalikan ke bentuk semula;
* perubahan kecil di input akan mengakibatkan perubahan hash yang signifikan.

#### Encoding

Tujuan encoding adalah melakukan transformasi data sehingga data dapat ditransfer melalui medium tertentu dan dapat dengan baik diolah oleh sistem yang berbeda. Encoding tidak bertujuan untuk membuat sebuah pesan rahasia. Encoding mentransformasikan data menjadi format lain menggunakan skema yang diketahui oleh publik. Beberapa contoh encoding antara lain:

* URL encoding;
* Base64 / Base32 / Base58;
* UU encoding.


## Semua Algoritma Kriptografi Dapat Dipecahkan

Banyak orang sulit menerima bahwa dalam kasus tertentu tidak ada cara membongkar data yang terenkripsi tanpa mengetahui kuncinya meskipun kita berhasil membongkar (reverse engineering) algoritma hingga sangat detail. Dalam praktik reverse engineering, terdapat tiga macam break yang ada:

* break karena algoritma yang memang rentan;
* break karena implementasi algoritma yang salah;
* break karena kesalahan dalam penggunaan.

Tidak semua penggunaan kriptografi mengarah pada kasus pertama. Beberapa algoritma lawas memang telah dibuktikan dapat dipecahkan, namun sangat jarang algoritma modern memiliki pemecahan secara praktikal. Sebagian mungkin mengarah ke kasus kedua, namun hanya sedikit. Sementara kasus ketiga merupakan kasus yang lebih umum ditemukan dibandingkan kedua kasus yang lain. Kesalahan seperti penyimpanan key yang tak aman, penyimpanan temporer, penggunaan key berulang untuk sesi berbeda, IV yang statis (tidak random), dsb.

Apabila ketiga hal di atas dapat ditangani dengan baik maka satu-satunya cara memecahkan sandi tersebut adalah dengan mengetahui kuncinya. Terkadang satu-satunya cara mencari kunci adalah dengan mencoba semua kemungkinan yang ada, dan jumlahnya sangat besar.

Referensi:

* [Unbreakable Encryption](http://blog.compactbyte.com/2017/05/16/unbreakable-encryption/)

## Kriptografi Adalah Solusi Segala Hal di Security

"If you think cryptography is the answer to your problem, then you don't know what your problem is." - Peter G. neumann

Banyak orang berpendapat bahwa segala permasalahan di bidang security dapat diselesaikan dengan kriptografi. Misal, untuk mengamankan komunikasi maka langkah yang diambil adalah mengamankan jalurnya tanpa mengamankan data yang lewat di jalur tersebut.

Kriptografi tidak dapat berdiri sendiri untuk menyelesaikan persoalan apapun. Kriptografi tidak dapat menjamin keamanan secara mutlak. Permasalahan yang umum terjadi di bidang security bukan karena tidak adanya penggunaan kriptografi. Beberapa alasan berikut justru memberikan kerentanan meskipun kriptografi telah digunakan:

* menggunakan algoritma yang lawas (outdated) dak tidak direkomendasikan lagi, seperti DES;
* penggunaan kriptografi yang salah, seperti kunci simetris yang disematkan dalam aplikasi secara hardcoded;
* RNG yang lemah, sehingga seseorang dapat memprediksi nilai yang akan dihasilkan berikutnya;
* kesalahan implementasi;
* kesalahan dalam access control;
* management password yang salah, misal penyimpanan password dalam cleartext;
* key management yang tidak baik;
* dsb.

Sebuah sistem yang secure tidak hanya dibangun dengan kriptografi semata. Desain yang baik dan implementasi yang sesuai didampingi oleh penggunaan teknologi yang sesuai merupakan kunci dari sistem yang secure.