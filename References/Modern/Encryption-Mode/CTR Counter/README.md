## CTR (Counter)

---

Counter (CTR) adalah salah satu _block cipher mode of operations_ (mode pengoperasian block cipher) yang memengaruhi operasi enkripsi dan dekripsi suatu algoritma di level block, namun setiap block tidak memiliki hubungan dengan block sebelumnya maupun block setelahnya.

Mode ini mengubah sebuah block cipher menjadi sebuah _synchronous stream cipher_.

Keystream akan diciptakan dengan cara mengenkripsi sebuah _counter_. Counter dapat berupa sembarang fungsi yang menyediakan deret angkadengan jaminan bahwa tidak akan ada nilai berulang dalam kurun waktu yang lama. Dalam praktiknya, counter paling sederhana seperti increment-by-one merupakan counter yang populer untuk digunakan.

Secara formal, operasi enkripsi dengan mode CTR akan memiliki fungsi sebagai berikut:

```
C[i] = Ek(Ctr[i]) ^ P[i]
```

![CTR Encryption][encryption.png]

Sementara proses dekripsi dengan mode CTR akan memiliki fungsi sebagai berikut:

```
P[i] = Dk(Ctr[i]) ^ C[i]
```

![CTR Decryption][decryption.png]
