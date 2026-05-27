# Crypto Reference

Kriptografi merupakan ilmu yang berkembang. Pada awal abad ke-20, kriptografi umumnya bergantung kepada linguistik dan pola leksikografi. Namun saat era digital tiba, kriptografi mulai menggunakan konsep matematika secara ekstensif. Beberapa konsep matematika yang digunakan antara lain:

- information theory
- computational complexity
- statistics
- combinatorics
- abstract algebra
- number theory
- finite mathematics

Kriptografi kemudian berkembang juga sebagai salah satu cabang dari engineering.

---

## Topik Kriptografi

Sama dengan cabang ilmu yang lain, kriptografi dapat ditinjau dari dua sisi yaitu sisi aplikasi dan sisi teori / pengayaan konsep.

Beberapa topik dan bahasan yang terdapat pada kriptografi antara lain:

- protocol design
- key management
- key exchange
- key authentication
- secure random number generation
- information signing
- DRM (digital right management)
- cipher attack

---

## Kriptografi Simetris

Menggunakan satu kunci yang sama untuk enkripsi dan dekripsi. Kunci harus disepakati dan dijaga kerahasiaannya oleh semua pihak yang berkomunikasi.

**Sub-topik:**

- Block cipher — mengenkripsi data dalam blok berukuran tetap. Contoh: AES, DES, Blowfish, Camellia.
- Stream cipher — mengenkripsi data satu bit atau satu byte pada satu waktu menggunakan keystream. Contoh: RC4, ChaCha20, Salsa20.
- Mode of operation — cara mengaplikasikan block cipher pada data panjang. Contoh: ECB, CBC, CTR, GCM.
- Authenticated Encryption — enkripsi yang sekaligus menjamin integritas. Contoh: AES-GCM, ChaCha20-Poly1305.

---

## Kriptografi Asimetris (Kunci Publik)

Menggunakan sepasang kunci: kunci publik (dapat disebarluaskan) dan kunci privat (dirahasiakan). Memungkinkan komunikasi aman tanpa perlu berbagi kunci rahasia terlebih dahulu.

**Sub-topik:**

- Enkripsi kunci publik — Contoh: RSA, ElGamal, ECIES.
- Tanda tangan digital — Contoh: RSA-PSS, DSA, ECDSA, EdDSA.
- Key exchange — Contoh: Diffie-Hellman, ECDH, X25519.
- PKI (Public Key Infrastructure) — pengelolaan sertifikat dan kepercayaan.

**Fondasi matematis:**

- Faktorisasi bilangan prima besar (RSA)
- Discrete logarithm problem (DH, DSA, ElGamal)
- Elliptic Curve Discrete Logarithm Problem / ECDLP (ECC)

---

## Hash Function

Fungsi yang memetakan data berukuran sembarang ke output berukuran tetap. Sifat utama: one-way dan collision resistant.

**Sub-topik:**

- Cryptographic hash — digunakan untuk integritas data, tanda tangan digital, dan komitmen. Contoh: SHA-2, SHA-3, BLAKE2.
- Non-cryptographic hash — dioptimalkan untuk kecepatan; digunakan untuk hash table, checksum. Contoh: MurmurHash, FNV, xxHash.
- Password hashing / KDF — hash yang sengaja dibuat lambat dan memory-intensive untuk melindungi password. Contoh: Argon2, bcrypt, scrypt.
- MAC / HMAC — hash berkunci untuk autentikasi pesan.

---

## Protokol Kriptografi

Protokol kriptografi mendefinisikan urutan langkah-langkah yang melibatkan dua atau lebih pihak beserta primitif kriptografi yang digunakan.

**Sub-topik:**

- Key agreement protocol — TLS, SSH, Signal Protocol.
- Authentication protocol — Kerberos, OAuth, FIDO2/WebAuthn.
- Zero-knowledge proof (ZKP) — membuktikan pengetahuan akan sebuah fakta tanpa mengungkapkan fakta itu sendiri. Contoh: zk-SNARK, Schnorr proof.
- Commitment scheme — berkomitmen pada sebuah nilai tanpa mengungkapkannya, kemudian mengungkapkannya di waktu yang tepat.
- Secret sharing — membagi rahasia menjadi beberapa bagian sedemikian rupa sehingga diperlukan sejumlah minimum bagian untuk merekonstruksinya. Contoh: Shamir's Secret Sharing.
- Oblivious Transfer (OT) — protokol di mana pengirim mengirimkan salah satu dari beberapa pesan tanpa mengetahui pesan mana yang diterima, dan penerima tidak mendapatkan pesan lainnya.
- Secure Multi-Party Computation (MPC) — memungkinkan beberapa pihak menghitung fungsi bersama atas input privat masing-masing tanpa mengungkapkan input tersebut.

---

## Kriptografi Pasca-Kuantum (Post-Quantum Cryptography)

Komputer kuantum yang cukup besar berpotensi memecahkan banyak sistem kriptografi modern berbasis RSA, ECC, dan DH melalui algoritma Shor. NIST telah menstandarisasi beberapa algoritma post-quantum.

**Pendekatan utama:**

- Lattice-based cryptography — CRYSTALS-Kyber (enkripsi), CRYSTALS-Dilithium (tanda tangan); keamanan berbasis masalah Learning With Errors (LWE) dan variannya.
- Hash-based signatures — SPHINCS+; keamanan hanya bergantung pada keamanan hash function.
- Code-based cryptography — McEliece; berbasis masalah decoding kode koreksi error.
- Multivariate cryptography — berbasis sulitnya menyelesaikan sistem persamaan polinomial multivariat.
- SIDH / SIKE — berbasis isogeni kurva eliptis (namun beberapa skema telah dipecahkan).

---

## Enkripsi Homomorfik (Homomorphic Encryption)

Skema enkripsi yang memungkinkan perhitungan dilakukan langsung pada data terenkripsi tanpa perlu mendekripsinya terlebih dahulu. Hasilnya, ketika didekripsi, identik dengan hasil perhitungan pada data asli.

- Partially Homomorphic Encryption (PHE) — hanya mendukung satu jenis operasi (penjumlahan atau perkalian).
- Somewhat Homomorphic Encryption (SHE) — mendukung operasi terbatas.
- Fully Homomorphic Encryption (FHE) — mendukung operasi aritmetika tak terbatas; sangat lambat dalam praktik saat ini.

**Aplikasi:** komputasi privat di cloud, analisis data medis tanpa mengekspos data pasien.

---

## Random Number Generator

Angka acak adalah fondasi dari hampir semua operasi kriptografi (pembuatan kunci, IV, nonce, dsb.).

- PRNG (Pseudo-Random Number Generator) — menghasilkan urutan angka yang tampak acak berdasarkan seed awal; deterministik dan tidak cocok untuk kriptografi.
- CSPRNG (Cryptographically Secure PRNG) — PRNG yang memenuhi persyaratan kriptografis: tidak dapat diprediksi secara komputasional. Contoh: /dev/urandom (Linux), CryptGenRandom (Windows), arc4random (BSD).
- TRNG (True RNG) — menggunakan sumber entropi fisik (noise termal, jitter clock, dsb.) untuk menghasilkan angka benar-benar acak.

---

## Kriptografi Klasik

Kriptografi sebelum era komputer, beroperasi pada teks alfanumerik dan dapat dikerjakan secara manual.

**Substitusi** — mengganti simbol plaintext dengan simbol lain. Contoh: Caesar, Vigenere, Playfair, Hill.

**Transposisi** — menyusun ulang posisi simbol plaintext tanpa mengubah nilainya. Contoh: Rail-fence, Columnar transposition.

---

## Kriptografi dalam Reverse Engineering

Kriptografi sering dijumpai dalam konteks reverse engineering, antara lain:

- Identifikasi algoritma — mengenali konstanta, S-box, atau pola kode yang merupakan implementasi algoritma tertentu.
- Proteksi software — enkripsi pada packer, protector, dan obfuscator; verifikasi serial number.
- Analisis protokol — mendekonstruksi protokol komunikasi proprietary yang menggunakan kriptografi.
- Breaking implementasi — menemukan kelemahan bukan pada algoritma melainkan pada cara penggunaannya (hardcoded key, static IV, dsb.).
- DRM analysis — analisis sistem manajemen hak digital.
