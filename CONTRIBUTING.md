# Panduan Berkontribusi

Bahasa: **[Indonesia](CONTRIBUTING.md)** | [English](CONTRIBUTING-EN.md)

Terima kasih telah tertarik untuk berkontribusi pada Crypto Reference! Repositori ini merupakan proyek terbuka dan kontribusi dari siapapun sangat diterima.

---

## Daftar Isi

- [Jenis Kontribusi](#jenis-kontribusi)
- [Kontribusi Kode](#kontribusi-kode)
- [Kontribusi Referensi](#kontribusi-referensi)
- [Cara Berkontribusi](#cara-berkontribusi)
- [Panduan Gaya](#panduan-gaya)
- [Kontak](#kontak)

---

## Jenis Kontribusi

Kontribusi yang diterima meliputi:

1. **Kode** — Implementasi algoritma cipher, hash, maupun algoritma kriptografi lainnya
2. **Referensi** — Artikel, analisis, catatan, atau studi kasus terkait kriptografi
3. **Dokumentasi** — Penjelasan atau catatan tentang algoritma yang sudah ada
4. **Perbaikan** — Perbaikan bug pada kode yang ada, atau koreksi informasi yang keliru

---

## Kontribusi Kode

### Aturan Umum

- Bahasa pemrograman yang digunakan tidak dibatasi
- **Dilarang** menggunakan pustaka (library) kriptografi secara khusus (misalnya: OpenSSL, libsodium, Crypto++)
- Penggunaan library untuk perhitungan primitif (seperti: aritmetika bilangan besar, operasi bitwise) masih diperbolehkan
- Kode harus dapat dikompilasi dan dijalankan

### Penempatan File

Letakkan implementasi sesuai kategori:

```
Codes/
├── Cipher/
│   ├── Block/                  ← Block cipher
│   ├── Classic/
│   │   ├── Substitution/       ← Cipher substitusi klasik
│   │   └── Transposition/      ← Cipher transposisi klasik
│   └── Stream/                 ← Stream cipher
└── Hash/
    ├── Cryptographic/          ← Hash function kriptografis
    └── Non-Cryptographic/      ← Hash function non-kriptografis
```

### Struktur Implementasi

Setiap implementasi sebaiknya terdiri dari:

- File implementasi utama (`.c` untuk C, atau ekstensi bahasa yang digunakan)
- Header file jika diperlukan (`.h` untuk C)
- Komentar singkat yang menjelaskan algoritma dan referensi yang digunakan

---

## Kontribusi Referensi

- Referensi dapat berupa artikel, paper akademik, tutorial, atau analisis
- Tempatkan di direktori `References/` sesuai kategori topik
- Format dalam Markdown (`.md`)
- Sertakan penjelasan singkat tentang isi referensi

---

## Cara Berkontribusi

### Via GitHub Pull Request

1. Fork repositori ini
2. Buat branch baru: `git checkout -b fitur/nama-kontribusi`
3. Lakukan perubahan
4. Commit dengan pesan deskriptif: `git commit -m "Tambah implementasi <nama algoritma>"`
5. Push ke fork kamu: `git push origin fitur/nama-kontribusi`
6. Buat Pull Request ke branch `master` repositori ini

### Via Kontak Langsung

Jika kamu tidak nyaman menggunakan GitHub, kamu dapat menghubungi kami melalui:

- **Email**: `pengurus [at] reversing.id`
- **Telegram**: [@ReversingID](https://t.me/ReversingID)

---

## Panduan Gaya

- Gunakan **Bahasa Indonesia** sebagai bahasa utama dalam dokumentasi
- Penamaan direktori dan file mengikuti konvensi yang sudah ada (CamelCase atau kebab-case)
- Komentar dalam kode dapat menggunakan Bahasa Indonesia atau Inggris

---

## Kontak

- **Email**: `pengurus [at] reversing.id`
- **Telegram**: [@ReversingID](https://t.me/ReversingID)
- **GitHub**: [ReversingID/Crypto-Reference](https://github.com/ReversingID/Crypto-Reference)
