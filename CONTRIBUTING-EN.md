# Contributing Guide

Language: [Indonesia](CONTRIBUTING.md) | **[English](CONTRIBUTING-EN.md)**

Thank you for your interest in contributing to Crypto Reference! This is an open project and contributions from anyone are welcome.

---

## Table of Contents

- [Types of Contributions](#types-of-contributions)
- [Code Contributions](#code-contributions)
- [Reference Contributions](#reference-contributions)
- [How to Contribute](#how-to-contribute)
- [Style Guide](#style-guide)
- [Contact](#contact)

---

## Types of Contributions

Accepted contributions include:

1. **Code** — Implementations of cipher, hash, or other cryptographic algorithms
2. **References** — Articles, analyses, notes, or case studies related to cryptography
3. **Documentation** — Explanations or notes about existing algorithms
4. **Fixes** — Bug fixes in existing code, or corrections to incorrect information

---

## Code Contributions

### General Rules

- Any programming language is accepted
- **Do not** use dedicated cryptographic libraries (e.g., OpenSSL, libsodium, Crypto++)
- Libraries for primitive computation (e.g., big number arithmetic, bitwise operations) are allowed
- Code must compile and run correctly

### File Placement

Place implementations in the appropriate category:

```
Codes/
├── Cipher/
│   ├── Block/                  ← Block ciphers
│   ├── Classic/
│   │   ├── Substitution/       ← Classical substitution ciphers
│   │   └── Transposition/      ← Classical transposition ciphers
│   └── Stream/                 ← Stream ciphers
└── Hash/
    ├── Cryptographic/          ← Cryptographic hash functions
    └── Non-Cryptographic/      ← Non-cryptographic hash functions
```

### Implementation Structure

Each implementation should ideally contain:

- The main implementation file (`.c` for C, or the appropriate extension)
- A header file if needed (`.h` for C)
- Brief comments explaining the algorithm and any references used

---

## Reference Contributions

- References can be academic papers, tutorials, analyses, or practical write-ups
- Place in the `References/` directory under the appropriate topic category
- Format in Markdown (`.md`)
- Include a brief description of the content

---

## How to Contribute

### Via GitHub Pull Request

1. Fork this repository
2. Create a new branch: `git checkout -b feature/contribution-name`
3. Make your changes
4. Commit with a descriptive message: `git commit -m "Add <algorithm name> implementation"`
5. Push to your fork: `git push origin feature/contribution-name`
6. Open a Pull Request to the `master` branch of this repository

### Via Direct Contact

If you prefer not to use GitHub, you can reach us through:

- **Email**: `pengurus [at] reversing.id`
- **Telegram**: [@ReversingID](https://t.me/ReversingID)

---

## Style Guide

- Documentation in Indonesian is preferred, but English is also accepted
- Directory and file naming follows existing conventions (CamelCase or kebab-case)
- Code comments can be in either Indonesian or English

---

## Contact

- **Email**: `pengurus [at] reversing.id`
- **Telegram**: [@ReversingID](https://t.me/ReversingID)
- **GitHub**: [ReversingID/Crypto-Reference](https://github.com/ReversingID/Crypto-Reference)
