## CBC (Cipher Block Chaining)

---

Cipher Block Chain adalah salah satu _block cipher mode of operations_ (mode pengoperasian block cipher) yang memengaruhi operasi enkripsi dan dekripsi suatu algoritma di level block, sehingga setiap block memiliki hubungan dengan block sebelumnya dan block setelahnya.

Dalam proses enkripsi, setiap block plaintext akan di-XOR terlebih dahulu dengan block ciphertext yang lalu sebelum proses enkripsi dilakukan.

Secara formal, operasi enkripsi dengan mode CBC akan memiliki fungsi sebagai berikut:

```
C[i] = Ek(P[i] ^ C[i-1])

C[0] = IV
```

![CBC Encryption][encryption.png]

Dalam proses dekripsi, setiap block ciphertext akan di-XOR terlebih dahulu dengna block ciphertext yang lalu sebelum proses dekripsi dilakukan.

Secara formal dekripsi dengan mode CBC akan memiliki fungsi sebagai berikut:

```
P[i] = Dk(C[i]) ^ C[i-1]

P[0] = IV 
```

![CBC Decryption][decryption.png]
