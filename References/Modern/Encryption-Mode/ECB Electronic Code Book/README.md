## ECB (Electronic Code Book)

---

Electronic Code Book adalah salah satu _block cipher mode of operations_ (mode pengoperasian block cipher) yang memengaruhi operasi enkripsi dan dekripsi suatu algoritma di level block, namun setiap block tidak memiliki hubungan dengan block sebelumnya maupun block setelahnya.

Electronic Code Book merupakan mode enkripsi paling sederhana. Mode ini merupakan mode dasar enkripsi dimana setiap block dienkripsi / didekripsi secara independen tanpa bergantun kepada block sebelum maupun sesudahnya. Dengan demikian, sebuah pesan yang dibagi menjadi beberapa block akan dapat dilakukan enkripsi dan dekripsi secara terpisah dan dalam waktu paralel.

Dalam mode ini tidak terdapat operasi tambahan yang memengaruhi proses enkripsi dan dekripsi secara keseluruhan. Dengan demikian maka proses enkripsi dan dekripsi akan sama sebagaimana desain awal dari algoritma tersebut.

Proses enkripsi dengan mode ECB adalah sebagai berikut:

![ECB Encryption][encryption.png]

Sementara proses dekripsi dengan mode ECB adalah sebagai berikut:

![ECB Decryption][decryption.png]