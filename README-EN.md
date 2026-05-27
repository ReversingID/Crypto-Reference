# Crypto Reference

[![Contributions Welcome](https://img.shields.io/badge/contributions-welcome-brightgreen.svg)](CONTRIBUTING-EN.md)

> Open repository of cryptography code and references for reverse engineering purposes.

Language: [Indonesia](README.md) | **[English](README-EN.md)**

---

## Table of Contents

- [About](#about)
- [What is Cryptography?](#what-is-cryptography)
- [Cryptography and Reverse Engineering](#cryptography-and-reverse-engineering)
- [Contents](#contents)
  - [Books](#books)
  - [Codes](#codes)
  - [References](#references)
  - [Tools](#tools)
- [Contributing](#contributing)

---

## About

This repository collects information and knowledge about cryptography implementations and related vulnerabilities. It contains references on practical cryptography usage, algorithm analysis, and insights primarily aimed at improving understanding during reverse engineering tasks.

This is a free and open repository. Anyone — from within or outside the [Reversing.ID](https://reversing.id) community — is welcome to access and use it.

---

## What is Cryptography?

Cryptography is the science of securing messages and communications under the assumption that adversarial third parties may be present.

Common uses of cryptography include:

- Protecting data confidentiality so it remains inaccessible to unauthorized parties.
- Ensuring data integrity — that no unauthorized modifications have occurred.
- Providing authentication — verifying that information comes from a legitimate source.

---

## Cryptography and Reverse Engineering

Reverse engineering and cryptography are closely linked.

During analysis, certain parts of a target often employ protection mechanisms on code or data. Cryptography forms the backbone of many modern protections — encryption in packers and application protectors, cryptosystems for serial number verification, file output encryption, and more.

A solid understanding of cryptographic concepts can significantly aid the reverse engineering process.

---

## Contents

### Books

The [`Books/`](Books/) directory contains freely available or openly licensed cryptography books and study materials.

| Title | Description |
|-------|-------------|
| [A Graduate Course in Applied Cryptography](Books/a-graduate-course-in-cryptography.pdf) | Covers many constructions for various cryptographic tasks |
| [Crypto 101](Books/crypto101.pdf) | Introductory cryptography for beginners |
| [Teori dan Aplikasi Kriptografi](Books/teori-dan-aplikasi-kriptografi.pdf) | Indonesian language cryptography textbook |
| [The Joy of Cryptography](Books/the-joy-of-cryptography.pdf) | Proof-based introduction to cryptography |

See also the [full external book list](References/README.md#books).

### Codes

The [`Codes/`](Codes/) directory contains cryptographic algorithm implementations in C. Each implementation is self-contained with no dependency on external cryptographic libraries.

**Ciphers**

| Category | Algorithms |
|----------|-----------|
| [Block Cipher](Codes/Cipher/Block/) | 3-Way, Anubis, Blowfish, Camellia, DES, KHAZAD, LEA, Lucifer, MARS, SAFER, TEA, Treyfer, XTEA, XXTEA, and more |
| [Classic — Substitution](Codes/Cipher/Classic/Substitution/) | ADFGVX, Affine, Atbash, AutoKey, Beaufort, Caesar, Hill, Playfair, ROT13, Vigenere, and more |
| [Classic — Transposition](Codes/Cipher/Classic/Transposition/) | Columnar-Permutation, Myszkowski, Rail-Fence, Route-Cipher |
| [Stream Cipher](Codes/Cipher/Stream/) | ChaCha20, Loiss, RC4, SAVILLE, SNOW, Salsa20 |

**Hash Functions**

| Category | Algorithms |
|----------|-----------|
| [Cryptographic Hash](Codes/Hash/Cryptographic/) | BLAKE, Keccak, MD family, RIPEMD, SHA family, Skein, Whirlpool, and more |
| [Non-Cryptographic Hash](Codes/Hash/Non-Cryptographic/) | APHash, DJBHash, FNV, Jenkins, MurmurHash, PearsonHash, and more |

See the [full implementation index](Codes/README.md).

### References

The [`References/`](References/) directory contains articles, analyses, and detailed documentation on cryptographic algorithms.

- [`Classical/`](References/Classical/) — Classical cryptography (substitution, transposition)
- [`Modern/`](References/Modern/) — Modern cryptography (block ciphers, stream ciphers, hash functions, asymmetric)
- [`Modern/Structure/`](References/Modern/Structure/) — Fundamental cryptographic structures (Feistel, SPN, Sponge, etc.)

See the [full references index](References/README.md).

### Tools

The [`Tools/`](Tools/) directory contains documentation on cryptographic analysis tools.

| Tool | Description |
|------|-------------|
| [CrypTool](Tools/CrypTool/) | Open-source software for learning and visually analyzing cryptographic algorithms |
| [Cryptol](Tools/cryptol/) | Domain-Specific Language for cryptographic algorithm specification and verification |

---

## Contributing

This repository is open to everyone. Contributions can include code implementations, references, analyses, or corrections to existing content.

Read [CONTRIBUTING-EN.md](CONTRIBUTING-EN.md) for full guidelines.
