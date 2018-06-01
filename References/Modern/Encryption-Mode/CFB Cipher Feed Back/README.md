## CFB (Cipher Feed Back)

---

Cipher Feed Back adalah salah satu _block cipher mode of operations_ (mode pengoperasian block cipher) yang memengaruhi operasi enkripsi dan dekripsi suatu algoritma di level block, sehingga setiap block memiliki hubungan dengan block sebelumnya dan block setelahnya.

Mode ini berkaitan erat dengan CBC, dimana mode ini akan membuat sebuah block cipher menjadi _self-synchronizing stream cipher_ atau stream cipher yang dapat melakukan sinkronisasi secara mandiri. Dekripsi pada CFB hampir identik dengan enkripsi pada CBC namun dilakukan secara berkebalikan.

Secara formal, operasi enkripsi dengan mode CFB akan memiliki fungsi sebagai berikut:

```
C[i] = Ek(C[i-1]) ^ P[i]

C[0] = IV
```

![CFB Encryption][encryption.png]

Sementara proses dekripsi dengan mode CFB akan memiliki fungsi sebagai berikut:

```
P[i] = Dk(C[i-1]) ^ C[i]

C[0] = IV
```

![CFB Decryption][decryption.png]
