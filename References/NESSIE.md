# Crypto Reference

NESSIE (New European Schemas for Signatures, Integrity, and Encryption) merupakan sebuah projek di kawasan Eropa yang bertujuan untuk mengidentifikasi dan merekomendasikan algoritma-algoritma kriptografi yang aman.

## Submission & Selected Algorithm

Referensi: [Springer](https://link.springer.com/content/pdf/10.1007/3-540-45664-3_21.pdf)

NESSIE mengidentifikasi dan mengevaluasi desain kriptografi yang terbagi menjadi beberapa kategori. Semua kandidat didapat melalui mekanisme Call for Submission.

Berikut adalah daftar kategori beserta algoritma yang telah terkumpul.

* Block ciphers
    * 64-bit block ciphers
        - CS-Cipher
        - Hierocrypt-L1
        - IDEA
        - Khazad
        - MISTY1
        - Nimbus
    * 128-bit block ciphers
        - Anubis
        - Camellia
        - Grand Cru
        - Hierocrypt-3
        - Noekeon
        - Q
        - SC2000
    * 160-bit block ciphers
        - SHACAL
    * variable-length block ciphers
        - NUSH: 64 / 128 / 256
        - RC6: >= 128
        - SAFER++ 64 / 128
* Synchronous Stream ciphers
    * BMGL
    * SNOW
    * SOBER-t16
    * SOBER-t32
* Message Authentication Code
    * Two-Track-MAC
    * UMAC
* Hash
    * Whirlpool
* Asymmetric-Key Cipher
    * ACE-Encrypt
    * ECIES
    * EPOC
    * PSEC
    * RSA-OAEP
* Asymmetric Digital Signature Schemes
    * ACE-Sign
    * ECDSA
    * ESIGN
    * FLASH
    * QUARTZ
    * RSA-PSS
    * SFLASH
* Asymmetric Identification Schemes
    * GPS

Dalam proses evaluasi, desainer sandi diperbolehkan untuk melakukan perubahan kecil terhadap algoritma mereka. Berdasarkan evaluasi yang dilakukan, terpilih beberapa algoritma dalam beberapa kategori sebagai berikut:

* block cipher 64-bit: 
    - IDEA: MediaCrypt
    - Khazad: Scopus Tecnologia & K.U.Leuven
    - MISTY1: Mitsubishi Electric
    - SAFER++64: Cylink Corp, ETH Zurich, National Academy of Science Armenia
* block cipher 128-bit:
    - Camellia: NTT & Mitsubishi Electric
    - RC6: RSA Laboratories
    - SAFER++128: Cylink Corp, ETH Zurich, National Academy of Science Armenia
* block cipher 160-bit:
    - SHACAL: Gemplus
* Synchronous Stream ciphers
    * BMGL: Royal Institute of Technology Stockholm & Ericsson Research
    * SNOW: Lund University
    * SOBER-t1: Qualcomm International
    * SOBER-t32: Qualcomm International
* Message Authentication Code
    * Two-Track-MAC: K.U.Leuven & Debis AG
    * UMAC: Intel Corp, University of Nevada, IBM Research Laboratory, Technion, University of California
* Hash
    * Whirlpool: Scopus Tecnologia, K.U.Leuven
* Asymmetric-Key Cipher
    * ACE-KEM: IBM Zurich Research Laboratory (dikembangkan dari ACE-Encrypt)
    * EPOC-2: NTT 
    * PSEC-KEM: NTT (dikembangkan dari PSEC-2)
    * RSA-OAEP: RSA Laboratories
* Asymmetric Digital Signature Schemes
    * ECDSA: Certicom Corp
    * ESIGN: NTT
    * QUARTZ: BULL CP8
    * RSA-PSS: RSA Laboratories
    * SFLASH: BULL CP8
* Asymmetric Identification Schemes
    * GPS: Ecole Normale Supreiure, CULL CP8, La Poste
