## Platform CSPRNG 

---

CSPRNG (Cryptographically Secure Pseudo Random Number Generator) adalah algoritma-algoritma random generator yang akan menghasilkan bilangan acak dengan ketentuan tertentu sehingga dapat secara aman digunakan dalam kegiatan yang berhubungan dengan kriptografi.

Beberapa provider menyediakan implementasi CSPRNG sehingga dapat digunakan secara langsung oleh aplikasi tanpa harus menggunakan pustaka pihak ketiga.

* Windows

    * RtlGenRandom()

* Linux

    * getrandom()
    * /dev/urandom (older linux kernel)

* OpenBSD 

    * getentropy()
    * arc4random_buf()

