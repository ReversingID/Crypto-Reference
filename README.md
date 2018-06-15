# Crypto Reference

Open repository of cryptography code and reference for reverse engineer purpose.

### Selayang Pandang

Repository ini digunakan untuk menghimpun informasi dan pengetahuan tentang implementasi kriptografi serta kerentanan yang berhubungan dengannya. Di repository ini terdapat berbagai referensi tentang pemanfaatan kriptografi secara praktikal maupun analisis terhadapnya, utamanya untuk menambah pemahaman dalam melakukan reversing sesuatu yang bersinggungan dengan kriptografi.

Repository ini merupakan repository bebas dan terbuka. Siapapun, baik internal maupun eksternal komunitas Reversing.ID, dapat mengakses dan memanfaatkannya.

### Apa itu Kriptografi?

Kriptografi merupakan ilmu yang mempelajari tentang teknik dalam menjaga keamanan pesan / komunikasi dengan asumsi terdapat ancaman keberadaan pihak ketiga.

Beberapa penggunaan kriptografi secara umum adalah:

- menjaga kerahasiaan data agar tak diketahui oleh pihak yang tak berkepentingan.
- memberikan jaminan bahwa tidak ada perubahan data yang terjadi di luar kuasa sumber informasi.
- memberikan jaminan bahwa informasi yang diberikan berasal dari pihak yang benar.

### Kriptografi dan Reverse Engineering

Reverse Engineering dalam beberapa hal berkaitan dengan kriptografi.

Seringkali dalam sebuah analisis terdapat bagian-bagian tertentu yang mengalami proteksi baik proteksi terhadap kode maupun data. Analisis perlu dilakukan untuk mengidentifikasi bagian yang terproteksi agar dapat diatur strategi yang optimal untuk menganalisis objek secara keseluruhan sehingga meminimalisir usaha yang diperlukan.

Kriptografi menjadi tulang punggung dalam beberapa proteksi modern, seperti penggunaan enkripsi pada packer maupun protector aplikasi, penggunaan cryptosystem untuk verifikasi serial number, enkripsi pada output file, dsb.

Dengan demikian, pemahaman konsep kriptografi yang baik dapat membantu dalam proses Reverse Engineering.

### Struktur dan Konten

Repositori ini terbagi menjadi beberapa bagian dengan direktori berbeda.

- Books
- Codes
- References
- Tools
- Libraries

_Books_ adalah kumpulan buku, diktat perkuliahan, maupun catatan kecil yang membahas kriptografi baik secara umum maupun topik-topik tertentu di dalamnya. Buku-buku di bagian ini diseleksi secara khusus berdasarkan bukan hanya isi namun juga aspek legalitas penyebaran informasi.

_Codes_ adalah implementasi algoritma kriptografi (enkripsi, hash, digital signature, dsb) dalam berbagai bahasa pemrograman.

_References_ merupakan himpunan referensi berupa artikel, tulisan tangan, dsb tentang implementasi kriptografi, analisis pemecahan algoritma, penerapan dalam kasus tertentu (utamanya proteksi program), dsb.

_Tools_ adalah bagian yang secara khusus membahas penggunaan peralatan maupun perangkat yang khusus digunakan dalam analisis sebuah algoritma maupun produk kriptografi.

_Libraries_ adalah bagian yang secara khusus membahas penggunaan library kriptografi yang tersedia serta karakteristik-karakteristik yang ada padanya.

### Bagaimana Cara Berkontribusi?

Ini adalah projek terbuka.

Kamu bisa memberikan sumbangan seperti kode implementasi cipher, hash, maupun penggunaan algoritma kriptografi untuk kasus-kasus tertentu (verifikasi serial number, verifikasi integritas data, enkripsi informasi sensitif, dsb). Tidak ada batasan dalam hal bahasa pemrograman yang digunakan, namun tidak diperbolehkan penggunaan pustaka (library) kriptografi secara khusus. Adapun penggunana library untuk membantu perhitungan secara primitif (seperti: perkalian bilangan sangat besar) masih diperbolehkan.

Selain contoh kode, kamu juga dapat menyumbangkan informasi, referensi, catatan, maupun analisis terhadap algoritma kriptografi.

Yang harus kamu lakukan:

- melakukan pull request.
- mengirimkan email ke pengurus [at] reversing.id
- memberi tahu di telegram @ReversingID

Diharapkan agar segala referensi yang ada menggunakan Bahasa Indonesia sebagai sarana penyampaian informasi.