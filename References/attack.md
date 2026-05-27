# Crypto Reference

## Prerequisite

Serangan terhadap kriptografi adalah upaya-upaya yang mengarah ke sistem persandian dengan tujuan memecahkan (break) algoritma. Memecahkan sandi / cipher tidak selalu berarti menemukan teknik yang praktikal bagi penyadap untuk mendapatkan plaintext dari sekadar ciphertext. Dalam riset kriptografi, memecahkan sandi merupakan usaha untuk menemukan kelemahan di cipher yang dapat dieksploitasi dan mereduksi kekuatan suatu algoritma sehingga resource maupun kompleksitas yang dibutuhkan lebih kecil dibandingkan dengan kemungkinan terburuk (jika dilakukan brute-force).

Mustahil untuk memahami kriptografi dan kriptanalisis tanpa memiliki pemahaman yang baik tentang konsep-konsep yang berkaitan. Beberapa konsep yang penting untuk dipahami sebelum melangkah lebih jauh dalam analisis algoritma kriptografi adalah:

* probabilitas dan statistika
* matematika diskrit
* pemrograman (implementasi algoritma)

---

## Attack Model

Dalam kriptanalisis, sebuah _attack model_ (atau _attack types_) adalah klasifikasi serangan terhadap kriptografi berdasarkan akses yang dibutuhkan untuk memecahkan pesan terenkripsi. Semakin besar akses yang dibutuhkan maka semakin banyak informasi yang dapat digunakan untuk memecahkan sandi.

Terdapat beberapa model umum yang sering digunakan, antara lain (diurutkan berdasarkan banyaknya informasi yang dibutuhkan):

* Ciphertext-only attack
* Known-plaintext attack
* Chosen-plaintext attack
* Chosen-ciphertext attack
* Open key model attack
* Side-channel attack


#### Ciphertext-Only Attack (COA)

Tujuan: mendapatkan key atau plaintext.

Di jenis serangan ini diasumsikan bahwa hanya terdapat akses terhadap sekumpulan ciphertext tanpa adanya akses terhadap plaintext maupun fungsi enkripsi. Jenis serangan ini adalah yang paling lemah karena kurangnya informasi yang berguna. Namun, jenis ini merupakan jenis yang paling sering dijumpai dalam kriptanalisis.

Beberapa informasi sekunder diperlukan untuk memecahkan pesan menggunakan model ini, misal: bahasa yang digunakan dalam plaintext.

#### Known Plaintext Attack (KPA)

Tujuan: mendapatkan key.

Di jenis serangan ini diasumsikan bahwa terdapat akses terhadap sekumpulan pasangan plaintext-ciphertext yang diciptakan dengan kunci yang sama. Analisis dilakukan untuk melihat korelasi antara plaintext dan ciphertext. Jumlah plaintext-ciphertext yang dapat digunakan terbatas atau tidak dalam kendali analis sehingga tidak dapat diciptakan secara bebas.

Terdapat beberapa kemungkinan skenario yang membuat serangan jenis ini dapat terjadi, sebagai contoh antara lain:

* implementasi algoritma yang buruk sehingga meninggalkan sebagian atau keseluruhan plaintext.
* struktur data atau payload selalu sama.
* penyimpanan sebagian informasi sensitif dalam log atau penyimpanan yang tak aman.

#### Chosen-Plaintext Attack (CPA)

Tujuan: mendapatkan key.

Di jenis serangan ini diasumsikan bahwa terdapat akses terhadap fungsi enkripsi dan ciphertext yang dihasilkan. Analis dapat menentukan beberapa plaintext yang akan dienkrip dan mengamati ciphertext yang dihasilkan. Analisis ini mengasumsikan implementasi kriptografi modern (software dan hardware) bersifat blackbox, sehingga analisis dapat mengamati proses transformasi.

Terdapat dua variasi Chosen-Plaintext Attack:

- `Batch Chosen-Plaintext Attack`: pemrosesan plaintext dilakukan sekaligus sehingga ciphertext hanya dapat diperoleh ketika seluruh plaintext telah selesai diproses.
- `Adaptive Chosen-Plaintext Attack`: analis dapat memproses plaintext berikutnya setelah mengamati ciphertext yang telah dihasilkan.

#### Chosen-Ciphertext Attack (CCA)

Tujuan: mendapatkan key.

Di jenis serangan ini diasumsikan bahwa terdapat akses terhadap fungsi dekripsi dan plaintext yang dihasilkan. Analis dapat menentukan sembarang ciphertext yang akan didekrip sehingga observasi terhadap plaintext terkait dapat dilakukan.

Terdapat dua variasi Chosen-Ciphertext Attack:

- `CCA1 (Lunchtime / Midnight Attack)`: analis hanya dapat melakukan query dekripsi sebelum menerima target ciphertext.
- `CCA2 (Adaptive Chosen-Ciphertext Attack)`: analis dapat melakukan query dekripsi bahkan setelah menerima target ciphertext, kecuali target itu sendiri.

#### Open Key Model Attack

Tujuan: mendapatkan key (utuh) atau plaintext.

Di jenis serangan ini diasumsikan bahwa terdapat informasi sebagian key yang digunakan untuk menciptakan ciphertext.

#### Side-Channel Attack

Tujuan: mendapatkan key.

Serangan jenis ini tidak menargetkan secara langsung pesan, algoritma, maupun perkakas yang melakukan enkripsi/dekripsi melainkan dengan melakukan observasi adanya efek samping ketika proses enkripsi/dekripsi berlangsung. Dengan demikian, kekuatan dari cipher bukanlah faktor utama.

Beberapa varian side-channel attack:

- `Timing Attack`: memanfaatkan perbedaan waktu eksekusi operasi kriptografi untuk menyimpulkan informasi tentang kunci. Operasi seperti perkalian modular dapat memiliki durasi yang berbeda tergantung pada bit-bit kunci.
- `Power Analysis Attack`: menganalisis konsumsi daya perangkat keras selama operasi kriptografi. Terbagi menjadi Simple Power Analysis (SPA) yang mengamati satu trace tunggal, dan Differential Power Analysis (DPA) yang menganalisis banyak trace secara statistik.
- `Cache-Timing Attack`: memanfaatkan perbedaan waktu akses cache CPU. Pola akses memori tergantung nilai kunci dapat terungkap melalui pengukuran waktu yang teliti.
- `Fault Injection Attack`: menyebabkan kesalahan yang disengaja (melalui glitching tegangan, radiasi EM, dsb.) selama komputasi kriptografi dan menganalisis output yang salah untuk menyimpulkan kunci.
- `Electromagnetic Attack`: menganalisis emisi elektromagnetik dari perangkat, mirip dengan power analysis namun menggunakan probe EM.

---

## Attack Category

Berdasarkan kuantitas serta kualitas informasi rahasia yang didapatkan melalui cryptanalysis, serangan dapat dibagi menjadi beberapa kategori:

* _Total Break_: attacker dapat mengetahui secret key yang digunakan.
* _Global Deduction_: attacker menemukan fungsionalitas yang sama (ekivalen) dengan algoritma enkripsi dan dekripsi tanpa mengetahui kunci yang digunakan.
* _Local Deduction_: attacker mengetahui plaintext / ciphertext yang sebelumnya tidak diketahui.
* _Information Reduction_: attacker mendapatkan _Shannon information_ tentang plaintext (maupun ciphertext) yang sebelumnya tidak diketahui.
* _Distinguishing Algorithm_: attacker dapat mengidentifikasi / membedakan ciphertext dari permutasi random / data random.

Serangan-serangan dapat pula dikelompokkan menjadi dua kelompok besar berdasarkan pendekatan yang dilakukan, yaitu:

* _Analytic Attack_: menggunakan algoritma dan serangkaian manipulasi aljabar untuk mengidentifikasi kelemahan di struktur algoritma.
* _Statistical Attack_: mengidentifikasi perilaku nonrandom dengan mengumpulkan banyak data dan melakukan analisis statistik terhadap kumpulan data tersebut.

---

## Teknik Serangan

Teknik-teknik serangan dapat dikelompokkan berdasarkan model serangan serta beberapa properti yang dimiliki.

### Exhaustive / Brute Force Attack

Serangan paling mendasar: mencoba seluruh kemungkinan kunci hingga menemukan kunci yang benar. Kompleksitas bergantung sepenuhnya pada panjang kunci. Serangan ini tidak bergantung pada kelemahan algoritma sehingga semua cipher rentan terhadapnya secara teoritis; keamanan sebuah cipher diukur dari seberapa sulit brute force ini dilakukan.

### Birthday Attack

Serangan yang memanfaatkan _birthday paradox_ dalam teori probabilitas. Dalam konteks hash function, birthday attack bertujuan menemukan dua input yang menghasilkan hash yang sama (collision). Untuk hash dengan output _n_ bit, birthday attack membutuhkan sekitar 2^(n/2) operasi — jauh lebih sedikit dari 2^n yang diperlukan untuk preimage attack.

### Meet-in-the-Middle Attack (MitM)

Serangan yang memecah masalah enkripsi berlapis menjadi dua bagian yang diselesaikan dari dua sisi secara independen, kemudian mencocokkan hasilnya di tengah. Serangan ini relevan terhadap double encryption (seperti 2DES): alih-alih membutuhkan 2^(2k) operasi, cukup 2^k dengan trade-off memori yang lebih besar. Berbeda dengan Man-in-the-Middle.

### Man-in-the-Middle Attack (MitM)

Serangan di mana penyerang menyisipkan diri secara transparan di antara dua pihak yang berkomunikasi, memungkinkan penyadapan dan/atau modifikasi pesan. Serangan ini menargetkan protokol komunikasi, bukan algoritma kriptografi secara langsung. Dapat dicegah dengan autentikasi yang kuat dan verifikasi identitas (sertifikat digital, pinning).

### Padding Oracle Attack

Serangan terhadap implementasi mode enkripsi (terutama CBC) yang memanfaatkan pesan error terkait padding. Penyerang mengirimkan ciphertext yang dimodifikasi dan mengamati apakah server melaporkan padding error atau tidak. Dengan mengiterasi modifikasi ini secara sistematis, plaintext dapat dipulihkan satu byte pada satu waktu tanpa mengetahui kunci.

### Time-Memory Trade-Off (TMTO)

Teknik yang menyeimbangkan penggunaan waktu komputasi dan memori untuk mempercepat pencarian kunci. Rainbow table adalah implementasi TMTO yang umum digunakan untuk membalikkan hash password. Dapat diatasi dengan penggunaan salt yang unik pada setiap hash.

### Chosen Plaintext / Ciphertext Attacks

* Differential Cryptanalysis
* Truncated Differential Cryptanalysis
* Higher-Order Differential Cryptanalysis
* Impossible Differential Cryptanalysis
* Integral Cryptanalysis
* Amplified Boomerang Attack
* Rectangle Attack

### Adaptive Chosen Plaintext / Ciphertext Attacks

* Boomerang Attack

### Open Key Model

* Related Key Attack
* Slide Attack — mengeksploitasi cipher yang memiliki sifat self-similarity; menemukan pasangan plaintext-ciphertext yang terkait melalui pergeseran jadwal kunci (key schedule).

### Known Plaintext / Ciphertext Attacks

* Linear Cryptanalysis
* Zero Correlation Attack
* Algebraic Attack — merepresentasikan cipher sebagai sistem persamaan aljabar kemudian menyelesaikannya untuk memperoleh kunci.
* Interpolation Attack — menggunakan interpolasi polinomial untuk merekonstruksi fungsi enkripsi.

### Stream Cipher Attacks

* Correlation Attack — mengeksploitasi korelasi statistik antara keystream dan output LFSR yang menyusun generator.
* Distinguishing Attack — membedakan keystream dari data random menggunakan sifat statistik tertentu.
* Time-Memory-Data Trade-Off — ekstensi TMTO untuk stream cipher.

### Others

* Statistical Attack
* Mod-n Cryptanalysis
