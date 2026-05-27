# Crypto Reference

Keseluruhan poin dari ilmu kriptografi adalah menjaga kerahasiaan plaintext (atau kunci, atau keduanya) dari penyadap (eavesdropper) atau kriptanalis (cryptanalyst).

Namun seiring perkembangan ilmu, penggunaan kriptografi kini tak terbatas hanya dalam perlindungan pesan saja. Beberapa hal terkait komunikasi melibatkan kriptografi di dalamnya.

## Kegunaan Kriptografi

Secara umum kriptografi mencakup dua komponen dasar keamanan informasi, yaitu kerahasiaan (`confidentiality`) dan keutuhan (`integrity`).

Secara umum konsep kriptografi dapat diterapkan untuk:

* Menjaga kerahasiaan pesan (confidentiality).
* Menjaga integritas data (integrity).
* Keabsahan pengirim (authentication).
* Antipenyangkalan (non-repudiation).

---

## Kriptografi Dalam Kehidupan Sehari-hari

### Smart Card

Salah satu aplikasi `PKI (Public-Key Infrastructure)` yang kian ramai digunakan. Kartu cerdas memiliki rupa fisik berupa kartu dengan chip di dalamnya dan digunakan untuk melayani banyak fungsi, mulai dari otentikasi hingga penyimpanan data.

Untuk dapat beroperasi, kartu cerdas membutuhkan daya eksternal yang didapatkan dari pembaca (reader).

Kartu cerdas menyimpan kunci privat, sertifikat digital, dan informasi lainnya untuk mengimplementasikan PKI. Selain komponen kriptografi, kartu cerdas juga menyimpan data lain sesuai kebutuhannya seperti nomor kartu kredit, informasi kontak personal, dll.

Untuk otentikasi kartu, server akan mengirimkan suatu nilai atau string yang disebut _challenge_ ke kartu untuk ditandatangani dengan kunci private yang tersimpan di dalam kartu. Hasil ini kemudian akan diverifikasi oleh mesin dengan kunci publik pemilik kartu.

### Pay TV

Pay TV adalah jasa siaran TV yang hanya dapat dinikmati oleh pelanggan yang membayar (berlangganan). Siaran Pay TV dipancarkan secara broadcast namun hanya sejumlah pesawat TV yang berhasil menangkap siaran tersebut.

Informasi yang dipancarkan pada Pay TV telah dienkripsi dengan kunci yang unik.

Secara umum proses otentikasi dan enkripsi/dekripsi pesan melalui tahap berikut:

1. Setiap pelanggan mendapatkan smart card yang mengandung kunci private yang unik.
2. Kartu cerdas dimasukkan ke dalam reader yang dipasang pada TV.
3. Pelanggan dikirimi kunci simetri yang terenkripsi dengan kunci publik pelanggan.
4. Smart card mendekripsi kunci simetri ini dengan kunci private yang dimiliki.
5. Kunci simetri kemudian digunakan untuk mendekripsi siaran TV.

### Komunikasi Web (HTTPS / TLS)

`HTTPS` adalah HTTP yang dilindungi menggunakan protokol `TLS (Transport Layer Security)`. TLS menggunakan kombinasi kriptografi asimetris dan simetris:

1. Handshake: server mengirimkan sertifikat digital (berisi kunci publik) untuk membuktikan identitasnya.
2. Key exchange: client dan server sepakat pada sebuah session key menggunakan algoritma pertukaran kunci (seperti ECDHE).
3. Enkripsi: seluruh komunikasi selanjutnya dienkripsi dengan kunci simetris yang disepakati.

Penggunaan TLS menjamin bahwa data yang dikirim tidak dapat dibaca atau dimodifikasi oleh pihak ketiga di perjalanan (in-transit).

### Virtual Private Network (VPN)

VPN membangun terowongan (tunnel) enkripsi antara dua titik jaringan, memungkinkan komunikasi yang aman melalui jaringan publik. Protokol seperti WireGuard, OpenVPN, dan IPSec menggunakan berbagai primitif kriptografi — ECDH untuk key exchange, AES-GCM atau ChaCha20-Poly1305 untuk enkripsi, dan HMAC untuk autentikasi pesan.

### Keamanan Email

- `S/MIME (Secure/Multipurpose Internet Mail Extensions)`: standard berbasis sertifikat X.509 untuk menandatangani dan mengenkripsi email.
- `PGP / GPG (Pretty Good Privacy / GNU Privacy Guard)`: sistem enkripsi email berbasis web-of-trust yang menggunakan pasangan kunci publik-privat. Pengirim mengenkripsi pesan dengan kunci publik penerima; hanya penerima dengan kunci privat yang dapat mendekripsinya.

### Enkripsi Disk dan File

- `Full Disk Encryption (FDE)`: mengenkripsi seluruh isi media penyimpanan secara transparan. Contoh: BitLocker (Windows), FileVault (macOS), dm-crypt/LUKS (Linux). Kunci enkripsi biasanya dilindungi oleh password pengguna melalui KDF.
- `File-level Encryption`: mengenkripsi file secara individual. Contoh: enkripsi pada arsip ZIP/7z, atau integrasi enkripsi pada cloud storage seperti Cryptomator.

### Penyimpanan Password

Password tidak boleh disimpan dalam bentuk plaintext. Praktik yang benar adalah menyimpan hash password menggunakan fungsi hash khusus (_password hash function_ / _KDF_) yang memiliki sifat _memory-hard_ dan lambat secara sengaja untuk mempersulit brute force.

Algoritma yang direkomendasikan:

- `Argon2` — pemenang Password Hashing Competition (PHC), direkomendasikan sebagai pilihan utama.
- `bcrypt` — sudah lama digunakan dan terbukti kuat.
- `scrypt` — memory-hard, cocok untuk kebutuhan ketahanan terhadap serangan GPU/ASIC.

Setiap hash harus menggunakan `salt` yang unik dan acak untuk mencegah penggunaan rainbow table.

### Tanda Tangan Digital (Digital Signature)

Tanda tangan digital membuktikan keaslian dan integritas dokumen digital. Penandatangan menggunakan kunci privat untuk menghasilkan tanda tangan dari hash dokumen; siapapun dapat memverifikasinya menggunakan kunci publik yang sesuai.

Penggunaan praktis:

- Penandatanganan dokumen (PDF, kontrak digital)
- Code signing (memastikan software tidak dimodifikasi)
- Penandatanganan commit dan tag Git (`git commit -S`)
- Sertifikat TLS/SSL

### Autentikasi Dua Faktor (2FA)

Algoritma berbasis kriptografi digunakan untuk menghasilkan kode OTP (One-Time Password):

- `TOTP (Time-based OTP)` — menggunakan HMAC-SHA1 dengan waktu Unix sebagai counter (RFC 6238). Diimplementasikan pada Google Authenticator, Authy, dsb.
- `HOTP (HMAC-based OTP)` — OTP berbasis counter, tidak tergantung waktu (RFC 4226).
- `FIDO2 / WebAuthn` — standar autentikasi berbasis kunci publik yang tidak memerlukan password; menggunakan hardware security key (YubiKey, dsb.) atau platform authenticator (Face ID, Windows Hello).

### Secure Messaging

Protokol seperti `Signal Protocol` (yang digunakan oleh Signal, WhatsApp, dll.) mengkombinasikan beberapa primitif kriptografi:

- `X3DH (Extended Triple Diffie-Hellman)` — key agreement awal.
- `Double Ratchet Algorithm` — menyediakan forward secrecy dan break-in recovery untuk setiap sesi.
- `AES-256-CBC` atau `AES-256-GCM` — enkripsi pesan.

Hasilnya adalah enkripsi end-to-end di mana bahkan penyedia layanan pun tidak dapat membaca pesan pengguna.

### Blockchain dan Cryptocurrency

Kriptografi merupakan fondasi dari teknologi blockchain:

- Hash kriptografis (SHA-256 pada Bitcoin) digunakan untuk membangun rantai blok yang tak dapat dimodifikasi.
- Tanda tangan digital (ECDSA / EdDSA) membuktikan kepemilikan dan mengotorisasi transaksi.
- Fungsi hash juga digunakan dalam mekanisme konsensus Proof-of-Work.

### DRM (Digital Rights Management)

DRM menggunakan enkripsi untuk membatasi akses dan penggunaan konten digital (film, musik, ebook, software). Kunci dekripsi hanya tersedia pada perangkat yang berhasil melakukan autentikasi ke server lisensi. Analisis DRM merupakan salah satu topik relevan dalam reverse engineering.

### Verifikasi Integritas Software

- `Code signing`: pengembang menandatangani installer atau binary secara digital sehingga sistem operasi dapat memverifikasi bahwa software tidak dimodifikasi oleh pihak ketiga.
- `Checksum`: hash seperti SHA-256 digunakan untuk memverifikasi integritas file yang diunduh.
- `Package signing`: manajer paket (APT, RPM, Homebrew) menggunakan tanda tangan digital untuk memverifikasi paket sebelum instalasi.
