<div align="center">

# ⚡ Ark Ang3l HashTool
### Multi-Core Cryptographic Hash Cracker, Identifier & Integrity Verifier

[![Python 3.8+](https://img.shields.io/badge/Python-3.8+-38bdf8?style=for-the-badge&logo=python&logoColor=white)](https://python.org)
[![Multiprocessing](https://img.shields.io/badge/Multiprocessing-Multi--Core-10b981?style=for-the-badge&logo=cpu&logoColor=white)](https://docs.python.org/3/library/multiprocessing.html)
[![License](https://img.shields.io/badge/License-MIT-f59e0b?style=for-the-badge)](LICENSE)

<br/>

[🌟 Features](#-key-features) •
[🔐 Supported Algorithms](#-supported-hash-algorithms) •
[🚀 Installation](#-installation--usage) •
[💻 CLI Menu](#-interactive-menu-options)

<br/>

```ascii
     _         _       _                   _____  _    _           _ _______          _ 
    / \   _ __| | __  / \   _ __   __ _ 3 / /| |  | |         | |__   __|        | |
   / _ \ | '__| |/ / / _ \ | '_ \ / _` | / / | |__| | __ _ ___| '_ \| | ___   ___ | |
  / ___ \| |  |   < / ___ \| | | | (_| |/ /  |  __  |/ _` / __| | | | |/ _ \ / _ \| |
 /_/   \_\_|  |_|\_/_/   \_\_| |_|\__, /_/   |_|  |_|\__,_\___|_| |_|_|\___/ \___/|_|
                                  |___/                                                 
                   CRYPTOGRAPHIC AUDIT & CRACKING TOOL // v2.0
```

</div>

---

## 🌟 Overview

**HashTool** is a multi-threaded, terminal-based cryptographic Swiss Army knife built for security analysts, penetration testers, and digital forensics investigators.

It combines **automatic hash type identification**, multi-core dictionary cracking utilizing all available CPU threads, rapid hash generation across 12 modern algorithms, and cryptographic file integrity verification.

---

## ✨ Key Features

- 🕵️ **Automatic Hash Identification:** Instantly identifies hash algorithms (MD5, SHA families, BLAKE2) by length, prefix, and structure.
- 🚀 **Multi-Core Dictionary Cracker:** Scales wordlist cracking dynamically across all available CPU logical cores via Python's `multiprocessing`.
- 🔐 **12+ Hash Algorithms:** Full support for standard SHA-2, SHA-3, BLAKE2, and legacy MD5/SHA-1.
- 📁 **File Integrity Audit:** Calculates and verifies file checksums to detect file tampering and verify downloads.
- 🎨 **Terminal UI & Colors:** Clean ANSI color-coded CLI with digital ASCII banners.

---

## 🔐 Supported Hash Algorithms

| Algorithm | Digest Length | Security Status | Primary Use Case |
| :--- | :---: | :---: | :--- |
| **MD5** | 32 hex / 128-bit | Deprecated | Legacy checksums & quick comparisons |
| **SHA-1** | 40 hex / 160-bit | Deprecated | Legacy Git commits & certificate chains |
| **SHA-224** | 56 hex / 224-bit | Secure | Truncated SHA-2 standard |
| **SHA-256** | 64 hex / 256-bit | Secure (Standard) | Digital signatures, Blockchain, OSINT |
| **SHA-384** | 96 hex / 384-bit | Secure | High-security government / TLS standard |
| **SHA-512** | 128 hex / 512-bit | High Security | Strong cryptographic password hashing |
| **SHA3-224 / 256 / 384 / 512** | 224-512 bit | Keccak Standard | Next-gen quantum-resistant standard |
| **BLAKE2s / BLAKE2b** | Variable | Ultra-Fast & Secure | High-speed cryptographic hashing |

---

## 🚀 Installation & Usage

### 1. Clone & Install Dependencies
```bash
git clone https://github.com/ark4ng3l/HashTool.git
cd HashTool
pip install colorama pyfiglet
```

### 2. Run HashTool
```bash
python hashtool.py
```

---

## 💻 Interactive Menu Options

```text
    [1] Hash Type Detector     -> Detects algorithm from raw hash string
    [2] Hash Generator         -> Generates digest for any custom text or string
    [3] Hash Cracker           -> Multi-core dictionary attack against hash
    [4] File Integrity Check   -> Computes cryptographic checksum of files
    [5] Exit                   -> Terminate application
```

### Example: Multi-Core Dictionary Attack
```text
Enter your choice: 3
Please input your hash to crack: 5d41402abc4b2a76b9719d911017c592
Please input your wordlist path: /usr/share/wordlists/rockyou.txt
Using 16 CPU cores for hash cracking...
Loaded 14344392 words from the wordlist.
Original text for hash '5d41402abc4b2a76b9719d911017c592' found: hello
```

---

## 📜 License

Distributed under the **MIT License**. See [LICENSE](LICENSE) for details.

<div align="center">
<b>Ark Ang3l HashTool</b> • Developed by <a href="https://github.com/ark4ng3l">@ark4ng3l</a>
</div>
