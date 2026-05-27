# Crypto Reference

Istilah umum dalam kriptografi.

---

## Pihak dalam Komunikasi

* `Pengirim` (sender) adalah pihak yang memberikan pesan dalam sebuah percakapan.
* `Penerima` (receiver) adalah pihak yang berhak menerima pesan dari pengirim.
* `Penyadap` (eavesdropper) adalah pihak memperhatikan percakapan yang dilakukan oleh pengirim dan penerima untuk mengetahui makna dari percakapan tersebut tanpa memiliki hak untuk menerima informasi.
* `Penyerang` (attacker / adversary) adalah pihak yang secara aktif berusaha merusak, memodifikasi, atau mendapatkan akses tidak sah terhadap sistem kriptografi.

## Karakter & Ilustrasi

Pembahasan konsep berkaitan kriptografi seringkali berupa skenario dengan ilustrasi tertentu. Dalam ilustrasi tersebut seringkali dimunculkan beberapa tokoh dengan peran tertentu. Beberapa nama dan peran yang umum digunakan, antara lain:

* A = Alice (pengirim/penerima)
* B = Bob (pengirim/penerima)
* C = Carol (pihak ketiga yang sah)
* E = Eve (passive eavesdropper — hanya mendengarkan)
* M = Mallory (malicious, penyerang aktif — dapat memodifikasi pesan)
* T = Trent (trusted third party — pihak ketiga yang dipercaya)
* O = Oscar (penyerang)
* P = Peggy (prover, dalam zero-knowledge proof)
* V = Victor (verifier, dalam zero-knowledge proof)

---

## Pesan dan Perubahan Bentuk

* `Pesan` adalah data atau informasi yang dapat dibaca dan dimengerti maknanya. Istilah lainnya adalah `plaintext` dan `cleartext`.
* Agar pesan tidak dapat dimengerti oleh pihak lain maka pesan diubah (transformasi) menjadi bentuk lain. Aturan ini disebut penyandian (`cipher`).
* Hasil dari penyandian adalah sebuah data yang tampak acak atau tak bermakna. Bentuk pesan tersandi ini disebut dengan `ciphertext` atau `kriptogram`.
* Proses pengubahan dari plaintext menjadi ciphertext disebut sebagai `enkripsi` (encryption). Kebalikannya, pengubahan dari ciphertext menjadi plaintext kembali disebut sebagai `dekripsi` (decryption).

---

## Sistem Kriptografi

* `Algoritma kriptografi` adalah aturan penyandian (enciphering dan deciphering) yang mengubah (transformasi) data dari plaintext ke ciphertext dan juga sebaliknya.
* `Kunci` (key) adalah parameter yang digunakan untuk transformasi data dalam penyandian.
* `Cryptosystem` (sistem kriptografi) adalah gabungan algoritma kriptografi, plaintext, ciphertext, dan kunci sebagai kesatuan.
* `Kriptografi kunci simetris` (Symmetric Key Cryptography) adalah jenis algoritma kriptografi di mana pihak pengirim dan penerima menggunakan kunci yang sama untuk enkripsi dan dekripsi.
* `Kriptografi kunci asimetris` (Asymmetric Key Cryptography) adalah jenis algoritma kriptografi di mana digunakan sepasang kunci yang berbeda untuk enkripsi dan dekripsi. Artinya kunci untuk enkripsi berbeda dengan kunci untuk dekripsi.

---

## Jenis Kunci

* `Kunci simetris` (symmetric key / secret key) — satu kunci yang sama digunakan untuk enkripsi dan dekripsi. Harus dijaga kerahasiaannya oleh semua pihak yang berkomunikasi.
* `Kunci publik` (public key) — kunci yang dapat disebarluaskan secara bebas. Digunakan untuk enkripsi (dalam sistem asimetris) atau verifikasi tanda tangan.
* `Kunci privat` (private key) — kunci yang harus dijaga kerahasiaannya oleh pemiliknya. Digunakan untuk dekripsi atau pembuatan tanda tangan.
* `Session key` — kunci sementara yang digunakan hanya untuk satu sesi komunikasi, kemudian dibuang. Membatasi dampak jika kunci bocor.
* `Master key` — kunci utama yang digunakan untuk menghasilkan atau mengenkripsi kunci-kunci lainnya.
* `Subkey` / `Round key` — kunci turunan yang dihasilkan dari master key melalui key schedule, digunakan pada setiap ronde dalam block cipher.

---

## Hash Function

* `Hash function` — fungsi yang memetakan data berukuran sembarang ke output berukuran tetap (disebut _digest_ atau _hash value_).
* `Digest` — output dari hash function. Juga disebut _message digest_, _hash value_, atau _checksum_.
* `Collision` — kondisi di mana dua input berbeda menghasilkan digest yang sama.
* `Preimage resistance` — sifat hash function yang menjamin sulitnya menemukan input `m` dari digest `h(m)` yang diketahui.
* `Second preimage resistance` — sifat yang menjamin sulitnya menemukan input kedua `m'` ≠ `m` sedemikian rupa sehingga `h(m') = h(m)`.
* `Collision resistance` — sifat yang menjamin sulitnya menemukan sembarang dua input `m` dan `m'` dengan `h(m) = h(m')`.
* `Avalanche effect` — properti di mana perubahan kecil pada input (bahkan satu bit) menghasilkan perubahan yang sangat besar dan acak pada output.
* `Salt` — nilai acak yang ditambahkan ke input sebelum hashing, biasanya dalam konteks penyimpanan password, untuk mencegah penggunaan rainbow table.

---

## MAC dan Autentikasi Pesan

* `MAC (Message Authentication Code)` — tag kriptografis singkat yang dihasilkan dari pesan dan kunci rahasia. Memverifikasi bahwa pesan tidak dimodifikasi dan berasal dari pihak yang memiliki kunci.
* `HMAC (Hash-based MAC)` — konstruksi MAC yang menggunakan hash function kriptografis (misalnya HMAC-SHA256). Terdefinisi dalam RFC 2104.
* `CMAC` — MAC berbasis block cipher.
* `Authenticated Encryption (AE)` — skema yang menjamin sekaligus kerahasiaan dan integritas pesan.
* `AEAD (Authenticated Encryption with Associated Data)` — ekstensi AE yang juga melindungi integritas data tambahan (associated data) yang tidak perlu dienkripsi, seperti header paket. Contoh: AES-GCM, ChaCha20-Poly1305.

---

## Parameter Kriptografis

* `IV (Initialization Vector)` — nilai awal yang digunakan bersama kunci untuk memastikan enkripsi yang sama menghasilkan ciphertext yang berbeda setiap kali. IV tidak perlu rahasia, tetapi harus unik untuk setiap enkripsi.
* `Nonce` (number used once) — nilai yang hanya boleh digunakan satu kali dengan kunci tertentu. Mirip dengan IV; penggunaan ulang nonce pada cipher tertentu (seperti AES-GCM) dapat merusak keamanan sepenuhnya.
* `Padding` — byte tambahan yang disisipkan ke akhir pesan untuk membuatnya mencapai panjang yang merupakan kelipatan ukuran block. Lihat [padding.md](Modern/padding.md).
* `KDF (Key Derivation Function)` — fungsi yang menghasilkan satu atau lebih kunci kriptografis dari materi kunci yang ada (misalnya password). Contoh: PBKDF2, bcrypt, Argon2, HKDF.

---

## Block Cipher

* `Block cipher` — algoritma enkripsi yang memproses data dalam blok berukuran tetap.
* `Block size` — ukuran blok data yang diproses sekaligus (dalam bit), misalnya 128-bit untuk AES.
* `Key size` / `Key length` — panjang kunci (dalam bit) yang menentukan jumlah kunci yang mungkin, misalnya 128, 192, atau 256-bit untuk AES.
* `Round` — satu iterasi dari serangkaian operasi transformasi dalam block cipher. Semakin banyak ronde, semakin kuat cipher (hingga titik tertentu).
* `S-box (Substitution box)` — komponen non-linear dalam block cipher yang memetakan sekelompok bit input ke sekelompok bit output. Memberikan sifat _confusion_.
* `P-box (Permutation box)` — komponen yang melakukan permutasi (pengacakan posisi) bit. Memberikan sifat _diffusion_.
* `Key schedule` — algoritma yang menghasilkan subkey (round key) dari kunci utama untuk digunakan di setiap ronde.
* `Feistel structure` — struktur block cipher yang membagi blok data menjadi dua bagian dan mengiterasi fungsi bulat secara bergantian. Contoh: DES.
* `SPN (Substitution-Permutation Network)` — struktur yang menggunakan S-box dan P-box secara langsung. Contoh: AES.
* `Mode of operation` — cara mengaplikasikan block cipher pada data yang lebih panjang dari satu blok. Contoh: ECB, CBC, CTR, GCM.

---

## Kriptografi Asimetris

* `Public key infrastructure (PKI)` — kerangka kerja untuk mengelola kunci publik dan sertifikat digital.
* `Sertifikat digital` — dokumen elektronik yang mengikat kunci publik dengan identitas pemiliknya, ditandatangani oleh Certificate Authority (CA).
* `Certificate Authority (CA)` — pihak terpercaya yang menerbitkan dan menandatangani sertifikat digital.
* `Tanda tangan digital` (digital signature) — skema kriptografis yang membuktikan keaslian dan integritas pesan atau dokumen.
* `Key exchange` — protokol yang memungkinkan dua pihak sepakat pada kunci rahasia bersama melalui kanal yang tidak aman. Contoh: Diffie-Hellman, ECDH.
* `Perfect Forward Secrecy (PFS)` — properti protokol kriptografi di mana session key tidak dapat dikompromikan meskipun kunci jangka panjang (private key) bocor di kemudian hari. Dicapai dengan menggunakan key exchange ephemeral (sementara) untuk setiap sesi.

---

## Kriptanalisis dan Kriptologi

* `Kriptanalisis` (cryptanalysis) adalah ilmu dan seni untuk memecahkan ciphertext menjadi plaintext tanpa mengetahui kunci yang diberikan. Pelakunya disebut sebagai `kriptanalis`.
* `Kriptologi` (cryptology) adalah studi mengenai kriptografi dan kriptanalisis.
* `Keamanan komputasional` (computational security) — keamanan yang bergantung pada asumsi sulitnya masalah komputasi tertentu (bukan keamanan mutlak secara matematis).
* `Keamanan informasi-teoritis` (information-theoretic security) — keamanan yang berlaku bahkan terhadap penyerang dengan kekuatan komputasi tak terbatas. Contoh: One-Time Pad.
* `Semantic security` — properti formal yang menyatakan bahwa ciphertext tidak memberikan informasi apapun tentang plaintext kepada penyerang.
* `IND-CPA` — model keamanan formal: indistinguishability under chosen-plaintext attack.
* `IND-CCA` — model keamanan formal: indistinguishability under chosen-ciphertext attack.
