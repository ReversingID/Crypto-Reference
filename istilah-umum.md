# Crypto Reference

Istilah umum dalam kriptografi.

## Pihak dalam Komunikasi

* **Pengirim** (sender) adalah pihak yang memberikan pesan dalam sebuah percakapan.
* **Penerima** (receiver) adalah pihak yang berhak menerima pesan dari pengirim.
* **Penyadap** (eavesdropper) adalah pihak memperhatikan percakapan yang dilakukan oleh pengirim dan penerima untuk mengetahui makna dari percakapan tersebut tanpa memiliki hak untuk menerima informasi.


## Karakter & Ilustrasi

Pembahasan konsep berkaitan kriptografi seringkali berupa skenario dengan ilustrasi tertentu. Dalam ilustrasi tersebut seringkali dimunculkan beberapa tokoh dengan peran tertentu. Beberapa nama dan peran yang umum digunakan, antara lain:

* A = Alice (pengirim/penerima)
* B = Bob (pengirim/penerima)
* E = Eve (passive eavesdropper)
* M = Mallory (malicious, penyerang aktif)
* T = Trent (trusted third party)


## Pesan dan Perubahan Bentuk

* **Pesan** adalah data atau informasi yang dapat dibaca dan dimengerti maknanya. Istilah lainnya adalah **plaintext** dan **cleartext**.
* Agar pesan tidak dapat dimengerti oleh pihak lain maka pesan diubah (transformasi) menjadi bentuk lain. Aturan ini disebut penyandian (**cipher**).
* Hasil dari penyandian adalah sebuah data yang tampak acak atau tak bermakna. Bentuk pesan tersandi ini disebut dengan **ciphertext** atau **kriptogram** (cryptogram).
* Proses pengubahan dari plaintext menjadi ciphertext disebut sebagai enkripsi (**encryption**). Kebalikannya, pengubahan dari ciphertext menjadi plaintext kembali disebut sebagai dekripsi (**decryption**)


## Sistem Kriptografi

* **Algoritma kriptografi** adalah aturan penyandian (enciphering dan deciphering) yang mengubah (transformasi) data dar plaintext ke ciphertext dan juga sebaliknya.
* **Kunci** adalah parameter yang digunakan untuk transformasi data dalam penyandian.
* Sistem Kriptografi (**cryptosystem**) adalah gabungan algoritma kriptofrafi, plaintext, ciphertext, dan kunci sebagai kesatuan.
* **Kriptografi kunci simetris** (Symmetric Key Cryptography) adalah jenis algoritma kriptografi dimana pihak pengirim dan penerima menggunakan kunci yang sama untuk enkripsi dan dekripsi.
* **Kriptografi kunci asimetris** (Asymmetric Key Cryptography) adalah jenis algoritma kriptografi dimana digunakan sepasang kunci yang berbeda untuk enkripsi dan dekripsi. Artinya kunci untuk enkripsi berbeda dengan kunci untuk dekripsi.


## Kriptanalisis dan Kriptologi 

* **Kriptanalisis** (cryptanalysis) adalah ilmu dan seni untuk memecahkan ciphertext menjadi plaintext tanpa mengetahui kunci yang diberikan. Pelakunya disebut sebagai **kriptanalis**
* **Kriptologi** (cryptology) adalah studi mengenai kriptografi dan kriptanalisis.



