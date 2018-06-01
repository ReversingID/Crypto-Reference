## PCBC (Propagating Cipher Block Chaining)

---

Propagating Cipher Block Chain adalah salah satu _block cipher mode of operations_ (mode pengoperasian block cipher) yang memengaruhi operasi enkripsi dan dekripsi suatu algoritma di level block, sehingga setiap block memiliki hubungan dengan block sebelumnya dan block setelahnya.

Sebagaimana tersirat dalam namanya, mode ini memiliki kaitan yang erat dengan mode CBC. Mode ini didesain sedemikian hingga jika terjadi perubahan kecil di ciphertext akan menyebabkan kesalahan yang tak terkira ketika melakukan dekripsi.

Secara formal, operasi enkripsi dengan mode PCBC akan memiliki fungsi sebagai berikut:

```
C[i] = Ek(P[i] ^ P[i-1] ^ C[i])

P[0] ^ C[0] = IV 
```

![PCBC Encryption][encryption.png]

Dalam proses dekripsi, setiap block ciphertext akan di-XOR terlebih dahulu dengna block ciphertext yang lalu sebelum proses dekripsi dilakukan.

Secara formal dekripsi dengan mode PCBC akan memiliki fungsi sebagai berikut:

```
P[i] = Dk(C[i]) ^ P[i-1] ^ C[i-1]

P[0] ^ C[0] = IV 
```

![PCBC Decryption][decryption.png]
