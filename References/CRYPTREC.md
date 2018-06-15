# Crypto Reference

CRYPTREC (Cryptography Research and Evaluation Commitee) adalah sebuah komite yang dibentuk oleh pemerintah Jepang untuk mengevaluasi dan merekomendasikan teknik-teknik kriptografi bagi kebutuhan pemerintah dan industri.

## Selected Algorithm

Daftar rekomendasi pertama kali dikeluarkan pada tahun 2003 kemudian direvisi pada tahun 2013. Dalam versi revisi, CRYPTEC membagi algoritma penyandian yang direkomendasikan menjadi tiga kategori, yaitu:

* e-Government Recommended Ciphers List
* Candidate Recomended Ciphers List
* Monitored Ciphers List

Alasan pembagian kategori ini bukan karena kurangnya keamanan bagi sebagian algoritma. Rekomendasi ini berdasarkan popularitas dan pengadopsian sandi tersebut dalam berbagai produk komersial, projek open source, sistem pemerintahan, dan standard internasional. Jika sandi-sandi yang berada pada kategori "kandidat" mendapatkan lebih banyak pengakuan dan digunakan lebih luas, maka tak menutup kemungkinan CRYPTREC akan memindahkan sandi tersebut ke daftar "e-Government Recommended Ciphers List".

### e-Government Recommended Ciphers List

* Asymmetric Key Ciphers:
    * Signature:
        - DSA: NIST FIPS 186-2
        - ECDSA: Certicom
        - RSA-PSS: 
        - RSASA-PKCS1-v1_5
    * Confidentiality:
        - RSA-OAEP
    * Key Exchange:
        - DH: NIST SP 800-56A Revision 1
        - ECDH: NIST SP 800-56A Revision 1
* Symmetric Key Ciphers:
    * 64-bit Block Ciphers:
        - 3-key Triple DES: NIST SP 800-67 Revision 1
    * 128-bit Block Ciphers:
        - AES: NIST FIPS PUB 197
        - Camellia: Nippon Telegraph and Telephone, Mitsubishi Electric
    * Stream Ciphers:
        - KCipher-2: KDDI
* Hash Function
    - SHA-256: NIST FIPS PUB 180-4
    - SHA-384: NIST FIPS PUB 180-4
    - SHA-512: NIST FIPS PUB 180-4
* Modes of Operation
    * Encryption Modes
        - CBC: NIST SP 800-38A
        - CFB: NIST SP 800-38A
        - CTR: NIST SP 800-38A
        - OFB: NIST SP 800-38A
    * Authenticated Encryption Modes
        - CCM: NIST SP 800-38C
        - GCM: NIST SP 800-38D
* Message Authenticated Codes
    - CMAC: NIST SP 800-38B
    - HMAC: NIST  FIPS PUB 198-1
* Entity Authentication
    - ISO/IEC 9798-2: ISO/IEC 9798-2:2008
    - ISO/IEC 9798-3: ISO/IEC 9798-3:1998, ISO/IEC 9798-3:1998/Amd 1:2010

### Candidate Recommended Ciphers List

* Asymmetric Key Ciphers:
    * Signature: N/A
    * Confidentiality: N/A
    * Key Exchange:
        - PSEC-KEM: Nippon Telegraph and Telephone
* Symmetric Key Ciphers:
    * 64-bit Block Ciphers:
        - CIPHERUNICORN-E: NEC
        - Hierocrypt-L1: Toshiba
        - MISTY1: Mitsubishi Electric
    * 128-bit Block Ciphers:
        - CIPHERUNICORN-A: NEC
        - CLEFIA: Sony
        - Hierocrypt-3: Toshiba
        - SC2000: Fujitsu
    * Stream Ciphers:
        - MUGI: Hitachi
        - Enocoro-128v2: Hitachi
        - MULTI-S01: Hitachi
* Hash Function: N/A
* Modes of Operation:
    * Encryption Modes: N/A
    * Authenticated Encryption Modes: N/A
* Message Authenticated Codes
    - PC-MAC-AES: NEC
* Entity Authentication
    - ISO/IEC 9798-4: ISO/IEC 9798-4:1999

### Monitored Ciphers List

* Asymmetric Key Ciphers:
    * Signature: N/A
    * Confidentiality:
        - RSAES-PKCS1-v1_5
    * Key Exchange: N/A
* Symmetric Key Ciphers:
    * 64-bit Block Ciphers: N/A
    * 128-bit Block Ciphers: N/A
    * Stream Ciphers:
        - 128-bit RC4: RSA Laboratories
* Hash Function:
    - RIPEMD-160: Hans Dobbertin, Antoon Bosselaers, Bart Preneel
    - SHA-1: NIST FIPS PUB 180-4
* Modes of Operation:
    * Encryption Modes: N/A
    * Authenticated Encryption Modes: N/A
* Message Authenticated Codes
    - CBC-MAC: ISO/IEC 979701:2011
* Entity Authentication: N/A