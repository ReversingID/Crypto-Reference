# Crypto Reference

## Prerequisite

---

Serangan terhadap kriptografi adalah upaya-upaya yang mengarah ke sistem persandian dengan tujuan memecahkan (break) algoritma. Memecahkan sandi / cipher tidak selalu berarti menemukan teknik yang praktikal bagi penyadap untuk mendapatkan plaintext dari sekadar ciphertext. Dalam riset kriptografi, memecahkan sandi merupakan usaha untuk menemukan kelemahan di cipher yang dapat dieksploitasi dan mereduksi kekuatan suatu algoritma sehingga resource maupun kompleksitas yang dibutuhkan lebih kecil dibandingkan dengan kemungkinan terburuk (jika dilakukan brute-force).

Mustahil untuk memahami kriptografi dan kriptanalisis tanpa memiliki pemahaman yang baik tentang konsep-konsep yang berkaitan. Beberapa konsep yang penting untuk dipahami sebelum melangkah lebih jauh dalam analisis algoritma kriptografi adalah:

* probabilitas dan statistika.
* matematika diskrit
* pemrograman (implementasi algoritma)

## Attack Model

---

Dalam kriptanalisis, sebuah _attack model_ (atau _attack types_) adalah klasifikasi serangan terhadap kriptografi berdasarkan akses yang dibutuhkan untuk memecahkan pesan terenkripsi. Semakin besar akses yang dibutuhkan maka semakin banyak informasi yang dapat digunakan untuk memecahkan sandi.

Terdapat beberapa model umum yang sering digunakan, antara lain (diurutkan berdasarkan banyaknya informasi yang dibutuhkan):

* Ciphertext-only attack
* Known-plaintext attack
* Chosen-plaintext attack
* Chosen-ciphertext attack
* Open key model attack
* Side-channel attack

### Cipher-Only Attack (COA)

Tujuan: mendapatkan key atau plaintext

Pada jenis serangan ini diasumsikan bahwa hanya terdapat akses terhadap sekumpulan ciphertext tanpa adanya akses menuju plaintext. Dalam beberapa skenario, ciphertext dapat dikumpulkan melalui penyadapan maupun penyitaan terhadap sumber data yang terenkrip.

Di antara sekian model, jenis serangan ini merupakan jenis serangan yang paling lemah karena kurangnya informasi yang berguna. Namun model ini adalah realita yang paling sering dijumpai dalam kriptanalisis.

Beberapa informasi sekunder diperlukan untuk memecahkan pesan menggunakan model ini, misal: bahasa yang digunakan dalam plaintext.

Di model ini mencakup teknik serangan:

* Bruteforce attack


### Known Plaintext Attack (KPA)

Tujuan: mendapatkan key

Pada jenis serangan ini diasumsikan bahwa terdapat akses terhadap sekumpulan pasangan plaintext-ciphertext yang diciptakan dengan kunci yang sama. Diasumsikan pula bahwa terdapat batasan jumlah pasangan plaintext-ciphertext yang dapat digunakan. 

Terdapat beberapa kemungkinan skenario yang membuat serangan jenis ini dapat terjadi, sebagai contoh antara lain:

* implementasi algoritma yang buruk sehingga meninggalkan sebagian atau keseluruhan plaintext.
* struktur data atau payload selalu sama
* penyimpanan sebagian informasi sensitif dalam log atau penyimpanan yang tak aman.

### Chosen-Plaintext Attack (CPA)

Tujuan: mencari key atau plaintext

Pada jenis serangan ini diasumsikan bahwa terdapat akses terhadap fungsi enkripsi dan ciphertext yang dihasilkan. Analisis dapat dilakukan dengan memilih beberapa plaintext yang akan dienkrip sehingga observasi dapat dilakukan terhadap ciphertext terkait.

Dengan serangan model ini, analisis dapat memungkinkan untuk terjadi eksplorasi berbagai area dari state space yang diinginkan. Sebagai implikasi, analis dapat mengeksploitasi kerentanan serta mengobservasi adanya perilaku nonrandom yang muncul akibat plaintext tertentu.

#### Adaptive Chosen-Plaintext Attack (CPA2)

Model ini adalah bagian dari Chosen-Plaintext Attack. Dalam analisis ini,  ciphertext berdasarkan plaintext yang diberikan, dalam setiap langkah analisis analisis dapat dilakukan dengan melihat hasil dari 

### Chosen-Ciphertext Attack (CCA)

Tujuan: mendapatkan key

Pada jenis serangan ini diasumsikan bahwa terdapat akses terhadap fungsi decryption, dan plaintext yang dihasilkan. Analisis dapat dilakukan dengan memilih sembarang ciphertext yang akan didekrip sehingga observasi terhadap plaintext terkait dapat dilakukan.
 
### Open Key Model Attack

Tujuan: mendapatkan key (utuh) atau plaintext

Pada jenis serangan ini diasumsikan bahwa terdapat informasi sebagian key yang digunakan untuk menciptakan ciphertext.

### Side-Channel Attack

Tujuan: mendapatkan key

Serangan jenis ini tidak menargetkan secara langsung pesan, algoritma, maupun perkakas yang melakukan enkripsi/dekripsi melainkan dengan melakukan observasi adanya efek samping ketika proses enkripsi/dekripsi berlangsung. Dengan demikian, kekuatan dari cipher bukanlah faktor utama.


## Attack Category

---


Berdasarkan kuantitas serta kualitas informasi rahasia yang didapatkan melalui cryptanalisis, serangan dapat dibagi menjadi beberapa kategori:

* _Total Break_: attacker dapat mengetahui secret key yang digunakna.
* _Global Deduction_: attacker menemukan functionalitas yang sama (ekivalen) dengan al_goritma enkripsi dan dekripsi tanpa mengetahui kunci yang digunakan
* _Local Deduction_: attacker mengetahui plaintext / ciphertext yang sebelumnya tidak di_ketahui.
* _Information Reduction_: attacker mendapatkan _Shannon information_ tentang plaintext (m_aupun ciphertext) yang sebelumnya tidak diketahui.
* _Distinguishing Algorithm_: attacker dapat mengidentifikasi / membedakan ciphertext dari permutasi random / data random.

Serangan-serangan dapat pula dikelompokkan menjadi dua kelompok besar berdasarkan pendekatan yang dilakukan, yaitu:

* _Analytic Attack_: menggunakan algoritma dan serangkaian manipulasi aljabar untuk mengidentifikasi kelemahan di struktur algoritma.
* _Statistical Attack_: mengidentifikasi perilaku nonrandom dengan mengumpulkan banyak data dan melakukan analisis statistik terhadap kumpulan data tersebut.

Teknik-teknik serangna dapat dikelompokkan menjadi beberapa kategori berdasarkan model serangan serta beberapa property yang dimiliki.

* Chosen Plaintext / Ciphertext Attack

    + Differential Cryptanalysis
    + Truncated Cryptanalysis
    + Higher-Order Differential Cryptanalysis
    + Impossible Differential Cryptanalysis
    + Integral Cryptanalysis
    + Amplified Boomerang Attack
    + Rectangle Attack

* Adaptive Chosen Plaintext / Ciphertext Attack

    + Boomerang Attack

* Open key Model

    + Related Key Attack

* Known Plaintext / Ciphertext Attack

    + Linear Cryptanalysis
    + Zero Correlation Attack

* Others

    + Statistical Attack
    + Mod-n Cryptanalysis