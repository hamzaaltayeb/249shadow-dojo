# 249shadow Cyber Lab — Cryptography Module

Welcome to the **Cryptography** training track of the **249shadow Cyber Lab**.

## Module Overview

Modern security operations and digital investigations frequently encounter data obfuscated through multi-stage encodings, legacy cryptographic algorithms, and combined transformation schemes. Threat actors and malware authors use these techniques to evade static file signatures, bypass network content inspection filters, and conceal sensitive configuration parameters.

This module introduces core concepts in data representation, classical cryptanalysis, and layered decoding methodologies:

1. **Hexadecimal & Base Representation:** Understanding how raw bytes map to ASCII-safe hexadecimal pairs and binary-to-text representations.
2. **Base64 Encoding:** Recognizing index table mappings, padding semantics (`=`), and standard 6-bit chunk processing.
3. **Classical Substitution Ciphers:** Analyzing alphabetic shifts (Caesar / ROT substitution), character frequency, and modular arithmetic operations.
4. **Encoding vs. Encryption:** Distinguishing between reversible, unkeyed data representation formats (encoding) and mathematically secured transformations requiring key material (encryption).

## Challenges in this Module

- **Hex + Base64 (Beginner):** Investigate an intercepted exfiltration artifact concealed behind two successive encoding layers.
- **Caesar + Base64 (Beginner–Intermediate):** Analyze a covert communication payload that blends transport-layer Base64 encoding with an inner classical alphabetic rotation cipher.

## Flag Convention

All challenges in this module issue flags following the community standard:

`249shadow{...}`

Submit recovered flags directly into the workspace action bar or via `dojo submit` in your terminal.
