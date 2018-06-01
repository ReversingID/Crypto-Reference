Beberapa istilah terkait operasi enkripsi di block cipher.

# Block Cipher

Algoritma BLock Cipher terdiri atas dua pasangan algoritma, satu algoritma untuk proses enkripsi dan lainnya sebagai untuk dekripsi. Masing-masing algoritma menerima dua input: sebuah block serta kunci (key).

# Block

Potongan data dalam ukuran tertentu dan menjadi satuan terkecil dalam operasi enkripsi maupun dekripsi sebuah algoritma Block Cipher.

Data dapat dipandang sebagai kumpulan block-block berurutan dengan ukuran yang seragam. Ukuran block (block size), diukur dalam satuan bit dan merupakan ukuran yang tetap sesuai dengan spesifikasi dari algoritma yang digunakan. Lazimnya, ukuran block merupakan kelipatan dari sebuah byte (8-bit).

# Initialization Vector (IV)

Disebut juga sebagai Starting Variable (SV).

IV atau SV merupakan sebuah block awal (initial) yang terlibat dalam mode operasi suatu enkripsi maupun dekripsi.

Sebuah IV berbeda dengan key dan tidak terdapat keharusan untuk dirahasiakan. Namun dalam kebanyakan kasus, disarankan bahwa IV tidak pernah digunakan kembali untuk key yang sama.

# Padding

Seperti telah diketahui, dalam enkripsi / dekripsi sebuah data akan dipecah menjadi beberapa block dengan ukuran yang sama. Apabila ukuran data bukan merupakan kelipatan dari block size, maka akan terdapat sebuah block yang memiliki ukuran yang tidak semestinya. Agar block tersebut mencapai ukuran block yang ditentukan, maka data berukuran tertentu ditambahkan di akhir.

Lihat bagian [padding](../padding.md) untuk informasi lebih lanjut.