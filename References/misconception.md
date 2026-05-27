# Crypto Reference

Miskonsepsi dan salah kaprah tentang kriptografi.

---

## Enkripsi vs Hash vs Encoding

`Enkripsi`, `hash`, dan `encoding` merupakan tiga istilah yang sering dipertukarkan. Banyak orang yang bingung dan menganggap bahwa ketiganya merupakan hal yang sama namun sebenarnya tidak. Ketiga istilah tersebut memiliki konsep yang berbeda meski termasuk dalam kategori yang sama yaitu transformasi data atau mengubah data menjadi bentuk lain yang berbeda.

#### Enkripsi

Tujuan enkripsi adalah untuk menjaga kerahasiaan informasi sehingga hanya orang-orang tertentu yang dapat membaca pesan tersebut. Ciri-ciri enkripsi antara lain:

* menggunakan kunci;
* ukuran data yang dihasilkan (ciphertext) sama atau lebih besar dari data asli (plaintext);
* data dapat dikembalikan ke bentuk semula (reversible).

#### Hash

[Hash](Modern/Hash) adalah fungsi searah. Hash banyak digunakan untuk melakukan validasi, memastikan integritas dari suatu data terjaga sehingga dapat dideteksi apabila suatu data mengalami perubahan. Ciri-ciri fungsi hash antara lain:

* ukuran data yang dihasilkan tetap meski berapapun ukuran data yang diberikan;
* data tidak dapat dikembalikan ke bentuk semula (one-way);
* perubahan kecil di input akan mengakibatkan perubahan hash yang signifikan (avalanche effect).

#### Encoding

Tujuan encoding adalah melakukan transformasi data sehingga data dapat ditransfer melalui medium tertentu dan dapat dengan baik diolah oleh sistem yang berbeda. Encoding tidak bertujuan untuk membuat sebuah pesan rahasia. Encoding mentransformasikan data menjadi format lain menggunakan skema yang diketahui oleh publik. Beberapa contoh encoding antara lain:

* URL encoding;
* Base64 / Base32 / Base58;
* UU encoding.

---

## Semua Algoritma Kriptografi Dapat Dipecahkan

Banyak orang sulit menerima bahwa dalam kasus tertentu tidak ada cara membongkar data yang terenkripsi tanpa mengetahui kuncinya meskipun kita berhasil membongkar (reverse engineering) algoritma hingga sangat detail. Dalam praktik reverse engineering, terdapat tiga macam break yang ada:

* break karena algoritma yang memang rentan;
* break karena implementasi algoritma yang salah;
* break karena kesalahan dalam penggunaan.

Tidak semua penggunaan kriptografi mengarah pada kasus pertama. Beberapa algoritma lawas memang telah dibuktikan dapat dipecahkan, namun sangat jarang algoritma modern memiliki pemecahan secara praktikal. Sebagian mungkin mengarah ke kasus kedua, namun hanya sedikit. Sementara kasus ketiga merupakan kasus yang lebih umum ditemukan dibandingkan kedua kasus yang lain. Kesalahan seperti penyimpanan key yang tak aman, penyimpanan temporer, penggunaan key berulang untuk sesi berbeda, IV yang statis (tidak random), dsb.

Apabila ketiga hal di atas dapat ditangani dengan baik maka satu-satunya cara memecahkan sandi tersebut adalah dengan mengetahui kuncinya. Terkadang satu-satunya cara mencari kunci adalah dengan mencoba semua kemungkinan yang ada, dan jumlahnya sangat besar.

Referensi:

* [Unbreakable Encryption](http://blog.compactbyte.com/2017/05/16/unbreakable-encryption/)

---

## Kriptografi Adalah Solusi Segala Hal di Security

> "If you think cryptography is the answer to your problem, then you don't know what your problem is." — Peter G. Neumann

Banyak orang berpendapat bahwa segala permasalahan di bidang security dapat diselesaikan dengan kriptografi. Misal, untuk mengamankan komunikasi maka langkah yang diambil adalah mengamankan jalurnya tanpa mengamankan data yang lewat di jalur tersebut.

Kriptografi tidak dapat berdiri sendiri untuk menyelesaikan persoalan apapun. Kriptografi tidak dapat menjamin keamanan secara mutlak. Permasalahan yang umum terjadi di bidang security bukan karena tidak adanya penggunaan kriptografi. Beberapa alasan berikut justru memberikan kerentanan meskipun kriptografi telah digunakan:

* menggunakan algoritma yang lawas (outdated) dan tidak direkomendasikan lagi, seperti DES, MD5, SHA-1;
* penggunaan kriptografi yang salah, seperti kunci simetris yang disematkan dalam aplikasi secara hardcoded;
* RNG yang lemah, sehingga seseorang dapat memprediksi nilai yang akan dihasilkan berikutnya;
* kesalahan implementasi;
* kesalahan dalam access control;
* management password yang salah, misal penyimpanan password dalam cleartext;
* key management yang tidak baik;
* dsb.

Sebuah sistem yang secure tidak hanya dibangun dengan kriptografi semata. Desain yang baik dan implementasi yang sesuai didampingi oleh penggunaan teknologi yang sesuai merupakan kunci dari sistem yang secure.

---

## Security Through Obscurity

> "Security through obscurity is no security at all."

Miskonsepsi ini berasumsi bahwa suatu sistem aman karena cara kerjanya tidak diketahui publik — misalnya, menggunakan algoritma enkripsi buatan sendiri yang tidak dipublikasikan, atau menyembunyikan lokasi penyimpanan kunci.

Prinsip yang benar adalah **Prinsip Kerckhoffs**: keamanan sebuah sistem kriptografi harus bergantung semata-mata pada kerahasiaan kunci, bukan pada kerahasiaan algoritma. Algoritma yang baik adalah yang tetap aman meskipun algoritmanya diketahui publik sepenuhnya.

Praktik security through obscurity tidak memberikan jaminan apapun karena:

* code dapat di-reverse engineer;
* desain yang buruk tidak menjadi lebih baik hanya karena disembunyikan;
* ketika sistem bocor, seluruh "keamanan" yang bergantung pada kerahasiaannya langsung runtuh.

---

## Algoritma Buatan Sendiri Lebih Aman

Merancang algoritma kriptografi yang kuat adalah salah satu tugas yang paling sulit dalam ilmu komputer. Algoritma yang digunakan saat ini (AES, ChaCha20, SHA-3, dsb.) telah melalui bertahun-tahun pengujian publik, analisis akademis, dan kompetisi terbuka.

Algoritma buatan sendiri yang tidak melalui proses ini hampir pasti memiliki kelemahan yang tidak terdeteksi oleh pembuatnya. Dalam reverse engineering, sering dijumpai algoritma custom yang tampak kompleks namun mudah dipecahkan karena tidak memenuhi properti kriptografis yang diperlukan.

Gunakan algoritma standar yang telah terbukti; jangan merancang primitif kriptografi sendiri kecuali untuk keperluan riset.

---

## Hash Biasa Cukup untuk Menyimpan Password

Menggunakan hash kriptografis umum (MD5, SHA-1, SHA-256) secara langsung untuk menyimpan password adalah praktik yang salah. Alasannya:

* Hash kriptografis dirancang untuk kecepatan — GPU modern dapat menghitung miliaran hash SHA-256 per detik, membuat brute force sangat cepat.
* Tanpa salt, password yang sama menghasilkan hash yang sama sehingga rentan terhadap rainbow table dan analisis database massal.

Password harus disimpan menggunakan fungsi hash khusus yang dirancang lambat secara sengaja: `Argon2`, `bcrypt`, atau `scrypt`. Setiap password harus memiliki salt yang unik dan acak.

---

## Kunci yang Lebih Panjang Selalu Lebih Aman

Kunci yang lebih panjang meningkatkan keamanan hanya jika semua faktor lain tetap sama dalam algoritma yang sama. Namun asumsi ini tidak berlaku lintas algoritma atau lintas konteks:

* Kunci RSA 1024-bit dianggap tidak aman, tetapi kunci ECC 256-bit memberikan tingkat keamanan yang setara dengan RSA 3072-bit karena perbedaan matematis yang mendasarinya.
* Memperpanjang kunci dari 128-bit ke 256-bit pada AES meningkatkan exhaustive search space dari 2^128 ke 2^256, tetapi keduanya sudah jauh melampaui kapabilitas komputasi yang ada saat ini.
* Kunci yang sangat panjang dengan algoritma yang lemah tidak memberikan keamanan yang bermakna.

---

## Enkripsi Menjamin Autentikasi

Enkripsi hanya menjamin **kerahasiaan** — pihak ketiga tidak dapat membaca isi pesan. Enkripsi tidak otomatis menjamin bahwa:

* pesan tidak dimodifikasi dalam perjalanan (integritas);
* pengirim benar-benar adalah siapa yang diklaim (autentikasi).

Contoh: mode ECB dan CBC tanpa MAC (Message Authentication Code) rentan terhadap serangan bit-flipping — penyerang dapat memodifikasi ciphertext secara terprediksi tanpa mengetahui kunci atau plaintext. Untuk menjamin kerahasiaan sekaligus integritas, gunakan mode enkripsi yang juga terautentikasi seperti `AES-GCM` atau `ChaCha20-Poly1305` (AEAD — Authenticated Encryption with Associated Data).

---

## HTTPS Berarti Situs Aman Sepenuhnya

HTTPS menjamin bahwa koneksi antara browser dan server dienkripsi sehingga tidak dapat disadap di perjalanan. Namun HTTPS **tidak** menjamin:

* bahwa server di ujung sana dapat dipercaya (bisa saja situs phishing dengan sertifikat valid);
* bahwa data yang tersimpan di server aman;
* bahwa aplikasi web tidak memiliki kerentanan lain (SQL injection, XSS, dsb.).

Ikon gembok di browser hanya menunjukkan bahwa koneksi terenkripsi, bukan bahwa situs tersebut legitimate atau aman secara keseluruhan.
