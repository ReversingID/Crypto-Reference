# Crypto Reference

## Kriptanalisis pada Sandi Klasik 

Meski serangan terhadap kriptografi secara umum telah dijelaskan pada [dokumen lain](../attack.md), dokumen ini dirasa perlu untuk memberikan informasi lebih detail tentang teknik-teknik umum dalam analisis sebuah kriptogram klasik.

hal ini dikarenakan proses kriptanalisis pada sandi klasik memiliki karakteristik tersendiri dan telah diformulasikan pada beberapa studi.

William F. Friedman mengusulkan operasi dasar yang dilakukan untuk memecahkan semua kriptogram klasik:

1. penentuan bahasa yang digunakan pada plaintext;
2. penentuan sistem umum dari algoritma kriptografi yang digunakan;
3. rekonstruksi kunci spesifik pada sistem persandian, atau rekonstruksi codebook, baik secara sebagian maupun seutuhnya, pada sistem pengodean atau keduanya.
4. rekonstruksi plaintext.

Dalam beberapa kasus, langkah (2) mungkin akan mendahului langkah (1). Dalam penyandian klasik, kita dapat menjabarkan lebih jauh teknik yang digunakan sebagai:

1. pengaturan (arrangement) dan penataan ulang (rearrangement) data untuk mengungkapkan karakteristik non-random atau manifestasinya. Misal, dengan penghitungan frekuensi (frequency counting), deteksi perulangan, deteksi pola, deteksi fenomena simetris;
2. identifikasi karakteristik yang muncul sebagai hasil langkah (1);
3. menyusun hipotesis atau penjelasan bagaimana karakteristik dapat muncul.

Sebagian besar usaha dicurahkan untuk menentukan bagaimana sistem bekerja secara umum.

Berdasarkan course `OP-20-G Cryptanalysis` yang diberikan pada Navy Departement, solusi untuk sandi substitusi dapat diperoleh melalui serangkaian langkah berikut:

* Analisis kriptogram

    1. persiapan tabel frekuensi
    2. mencari perulangan
    3. penentuan tipe sistem yang digunakan
    4. persiapan worksheet
    5. persiapan alfabet individual (jika terdapat lebih dari satu).
    6. pembuatan tabel (tabulasi) untuk perulangan panjang dan distribusi huruf yang aneh.

* Klasifikasi vokal dan konsonan dengan melakukan studi

    1. frekuensi
    2. spasi
    3. kombinasi huruf
    4. perulangan

* identifikasi huruf

    1. proses breaking dan wedge
    2. verifikasi asumsi yang muncul
    3. substitusi nilai yang didapat pada pesan
    4. pemulihan (recovery) nilai yang mungkin untuk melengkapi solusi

* rekonstruksi sistem

    1. membangun ulang tabel sandi
    2. pemulihan kunci yang digunakan dalam pengoperasian sistem
    3. pemulihan kunci atau frasa kunci yang digunakan untuk merekonstruksi urutan alfabet.

Semua proses di atas dilakukan dengan pertimbangan logis yang dibutuhkan dan bukan merupakan langkah-langkah baku yang harus ditempuh.

