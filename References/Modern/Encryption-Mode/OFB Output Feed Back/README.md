## OFB (Output Feed Back)

---

Output Feed Back adalah salah satu _block cipher mode of operations_ (mode pengoperasian block cipher) yang memengaruhi operasi enkripsi dan dekripsi suatu algoritma di level block, sehingga setiap block memiliki hubungan dengan block sebelumnya dan block setelahnya.

Mode ini mengubah sebuah block cipher menjadi sebuah _synchronous stream cipher_.

Keystream yang diciptakan akan di-XOR dengan plaintext untuk memperoleh ciphertext. Keystream ini kemudian akan diumpankan ke proses pada block berikutnya untuk mendapatkan keystream selanjutnya.

Operasi enkripsi dengna mode OFB dapat dituliskan sebagai berikut:

```
C[i] = P[i] ^ O[i]

O[i] = Ek(I[i])

I[i] = O[i-1]

I[0] = IV
```

![OFB Encryption][encryption.png]

Sementara proses dekripsi dengan mode OFB akan memiliki fungsi berikut:

```
P[i] = C[i] ^ O[i]

O[i] = Ek(I[i])

I[i] = O[i-1]

I[0] = IV
```

![OFB Decryption][decryption.png]