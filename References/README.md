# Crypto Reference

Curated list of cryptography references.

## Introduction

Pada awalnya repository ini dikembangkan secara spesifik sebagai referensi untuk membantu dalam reverse engineering (mengidentifikasi algoritma, mencari celah atau flaw). Seiring dengan semakin berkembangnya komunitas, repository ini pun diperluas untuk mencakup berbagai topik terkait kriptografi.

## Table of Contents

- Resources
    - [Books](#books)
    - [Courses](#courses)
    - [Challenges](#challenges)
    - [Forums](#forums)
    - [Blogs](#blogs)
    - [Tools](#tools)
    - [Web References](#web-references)

- - -

## Books

Sebagian buku yang gratis atau berlisensi terbuka dapat diperoleh pada direktori [Books](/Books).

-- General Cryptography --

- [A Graduate Course in Applied Cryptography](https://toc.cryptobook.us) - mencakup banyak konstruksi untuk berbagai task dalam kriptografi. (free, [indexed](/Books/a-graduate-course-in-cryptography.pdf))
- [An Introduction to Mathematical Cryptography](http://www.math.brown.edu/~jhs/MathCryptoHome.html) - pengantar kriptografi modern berbasis matematika.
- [Crypto101](https://www.crypto101.io) - pengantar kriptografi. (free, [indexed](/Books/crypto101.pdf))
- [Cryptography Engineering](https://www.schneier.com/books/cryptography_engineering/) - membuat protokol kriptografi yang digunakan di dunia nyata.
- [Handbook of Applied Cryptography](https://cacr.uwaterloo.ca/hac/) - dikhususkan sebagai referensi bagi kriptografer profesional. (free)
- [Introduction to Modern Cryptography](http://www.cs.umd.edu/~jkatz/imc.html) - pengenalan kriptografi dalam perspektif computer science.
- [Kriptografi](https://informatika.stei.itb.ac.id/~rinaldi.munir/Kriptografi/kriptografi.htm) - Rinaldi Munir. ISBN: 978-623-7131-05-2
- [Practical Cryptography for Developers](https://cryptobook.nakov.com) - kriptografi modern dengan contoh kode (hash, MAC, symmetric, asymmetric, dsb). (free)
- [Serious Cryptography](https://nostarch.com/seriouscrypto) - pengenalan enkripsi modern.
- [Teori dan Aplikasi Kriptografi](http://www.buku-e.lipi.go.id/utama.cgi?lihatarsip&sent001&1254672494) - berbahasa Indonesia. (free, [indexed](/Books/teori-dan-aplikasi-kriptografi.pdf))
- [The Code Book](https://simonsingh.net/books/the-code-book/) - rangkuman sejarah kriptografi dari jaman ke jaman.
- [The Cryptoparty Handbook](https://unglue.it/work/141611/) - panduan komprehensif terhadap berbagai topik terkait keamanan. (free)
- [The Joy of Cryptography](https://joyofcryptography.com) - pengantar kriptografi berbasis proof. (free, [indexed](/Books/the-joy-of-cryptography.pdf))
- [Understanding Cryptography](http://www.crypto-textbook.com/) - ditujukan bagi pemula dengan latihan yang berlimpah di akhir setiap bab.

-- Engineering & Application --

- [Applied Cryptography: Protocols, Algorithms and Source Code in C](https://www.schneier.com/books/applied-cryptography/) - Bruce Schneier. Survei komprehensif kriptografi modern beserta implementasinya.
- [Real World Cryptography](https://www.manning.com/books/real-world-cryptography/) - teknik kriptografi terapan untuk memahami dan menerapkan keamanan di sistem nyata.
- [Security Engineering](http://www.cl.cam.ac.uk/~rja14/book.html) - Ross Anderson. Buku teks keamanan komputer yang mencakup kriptografi dalam konteks rekayasa sistem. (free)

-- Quantum Cryptography --

-- Cryptanalysis --

- [Modern Cryptanalysis: Techniques for Advanced Code Breaking](https://www.wiley.com/en-us/Modern+Cryptanalysis%3A+Techniques+for+Advanced+Code+Breaking-p-9780470135938) - Christopher Swenson. ISBN: 978-0-470-13593-8

-- Tools --

Buku spesifik terkait tools dan framework berkaitan dengan kriptografi.

- [OpenSSL Cookbook](https://www.feistyduck.com/library/openssl-cookbook/) - panduan penggunaan OpenSSL untuk berbagai keperluan kriptografis. (free)


## Courses

-- University Courses --

- [Harvard](https://intensecrypto.org/public/) - kursus pengantar kriptografi yang padat dari Harvard.
- [Institut Teknologi Bandung](https://informatika.stei.itb.ac.id/~rinaldi.munir/Kriptografi/kriptografi.htm) - Rinaldi Munir. Materi perkuliahan kriptografi berbahasa Indonesia.
- [Stanford University](https://www.coursera.org/learn/crypto) — [Coursera](https://www.coursera.org/learn/crypto) | [Stanford](http://online.stanford.edu/course/cryptography) - Dan Boneh.
- [University of Maryland](https://www.coursera.org/learn/cryptography) - kursus berorientasi praktis di Coursera.
- [University of Washington](http://courses.cs.washington.edu/courses/csep590/06wi/) - aspek praktis kriptografi modern.

-- Public --

- [Applied Cryptography](https://www.udacity.com/course/applied-cryptography--cs387) - (free) belajar segala hal tentang membuat dan memecahkan puzzle di komputasi.
- [Crypto Strikes Back!](https://www.youtube.com/watch?v=ySQl0NhW1J0) - talk tentang kerentanan kriptografi di sistem dan bagaimana hal kecil dapat menjadi bencana.
- [Cryptography 101: Building Blocks](https://cryptography101.ca/crypto101-building-blocks/) - mencakup enkripsi simetris, hash function, MAC, signature, dan ECC.
- [Cybrary Cryptography](https://www.cybrary.it/course/cryptography/) - membahas bagaimana kriptografi menjadi pijakan penting dalam security.
- [Journey into Cryptography](https://www.khanacademy.org/computing/computer-science/cryptography) - Khan Academy. Pengantar kriptografi dari dasar.
- [Theory and Practice of Cryptography](https://www.youtube.com/watch?v=ZDnShu5V99s) - pengenalan kriptografi modern, aplikasi, dan praktik di Google.


## Challenges

-- Classic Cryptanalysis --

Berfokus kepada kriptanalisis atau pemecahan kode. Sebagian memberikan tantangan yang dapat dikerjakan dengan kertas dan pena.

- [Alan Turing Cryptography Competition](http://www.maths.manchester.ac.uk/cryptography_competition/).
- [TheCodeBreakers.EU](http://thecodebreakers.eu/) - kompetisi tahunan di bidang kriptologi dengan tema PD2.
- [Kryptos](https://www.cwu.edu/math/kryptos)
- [Mystery Twister C3](https://www.mysterytwisterc3.org/).
- [National Cipher Challenge](https://www.cipherchallenge.org/).

-- Modern Crypto Challenge --

- [Cryptohack](https://cryptohack.org/) - platform tantangan kriptografi modern yang interaktif.
- [Cryptopals](https://cryptopals.com/) - seri tantangan membahas kriptografi modern dari awal hingga akhir.

-- Other --

- [Underhanded Crypto Contest](https://underhandedcrypto.com/) - kompetisi untuk merancang algoritma yang memiliki backdoor tersembunyi.


## Forums

-- Online Board --

- [Cryptography Stack Exchange](http://crypto.stackexchange.com/) - Q&A untuk profesional dan penggemar kriptografi.
- [reddit r/cryptography](https://www.reddit.com/r/cryptography/) - diskusi teori dan praktik kriptografi.

-- Mailing List --

- [metzdowd.com](http://www.metzdowd.com/mailman/listinfo/cryptography) - mailing list moderat bertopik teknologi kriptografi.
- [Modern Crypto](https://moderncrypto.org/) - forum diskusi praktik kriptografi modern.
- [randombit.net](https://lists.randombit.net/mailman/listinfo/cryptography) - diskusi umum kriptografi dan aspek teknisnya.


## Blogs

- [A Few Thoughts on Cryptographic Engineering](http://blog.cryptographyengineering.com/) - beberapa pemikiran yang terlintas tentang kriptografi, oleh Matthew Green.
- [Bristol Cryptography Blog](http://bristolcrypto.blogspot.co.uk/) - blog resmi University of Bristol cryptography research group.
- [Charles Engelke's Blog](https://blog.engelke.com/tag/webcrypto/) - WebCrypto Blog Posts.
- [Root Labs rdist](https://rdist.root.org/) - blogpost oleh Nate Lawson dkk. tentang berbagai topik termasuk implementasi hardware, attack, DRM.
- [Salty Hash](https://blog.ironcorelabs.com) - mencakup beberapa topik terkait enkripsi, data control, privacy, dan security.
- [Schneier on Security](https://www.schneier.com/) - mencakup berbagai topik terkait kriptografi, kriptoanalisis, dan keamanan.


## Tools

-- Playground --

Tool interaktif untuk eksplorasi dan eksperimentasi algoritma kriptografi.

- [Boxentriq](https://www.boxentriq.com/code-breaking) - kumpulan tool untuk analisis dan pemecahan cipher klasik.
- [Cryptography Playground](https://vishwas1.github.io/crypto/index.html#/crypto) - tool untuk eksplorasi konsep dasar kriptografi seperti hashing, enkripsi simetris/asimetris, ZKP, dsb.
- [Cryptolab](http://manansingh.github.io/Cryptolab-Offline/cryptolab.html) - kumpulan tool analisis kriptografi yang dapat digunakan secara offline.
- [CrypTool Online](http://www.cryptool-online.org/) - berbagai cipher, metode enkripsi, dan tool analisis kriptografi berbasis web.
- [CrypTool](https://www.cryptool.org/en/) - produk open source untuk mendesain dan mempelajari komponen-komponen algoritma kriptografi secara visual.
- [CyberChef](https://gchq.github.io/CyberChef/) - web app serbaguna untuk enkripsi, encoding, kompresi, dan analisis data.
- [Elliptic Curve Calculator](https://paulmillr.com/noble/#demo) - kalkulasi public key dan signature pada kurva eliptis.

-- Knowledge Based --

- [factordb.com](http://factordb.com/) - menyimpan dan mencari faktorisasi dari berbagai bilangan.


## Web References

Situs referensi dan sumber pengetahuan kriptografi.

- [Applied Crypto Hardening](https://bettercrypto.org/) - panduan dan contoh konfigurasi terbaik untuk mengamankan server.
- [Garykessler — An Overview of Cryptography](http://www.garykessler.net/library/crypto.html) - ulasan komprehensif tentang kriptografi, cocok sebagai referensi cepat.
- [IACR — International Association for Cryptologic Research](https://www.iacr.org/) - organisasi non-profit yang memajukan penelitian kriptologi; menerbitkan paper dan mengadakan konferensi.
- [Learn Cryptography](https://learncryptography.com/) - sumber belajar yang menjelaskan cara kerja sistem kriptografi secara mudah dipahami.
