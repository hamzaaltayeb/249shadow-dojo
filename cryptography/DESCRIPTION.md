# 249Shadow Cyber Lab — Cryptography Module

Welcome to the **Cryptography** track of the **249Shadow Cyber Lab**.

## Module Overview

Practical cryptography challenges focused on encoding, classical ciphers, and layered transformations.

In real-world security operations and digital forensic investigations, intercepted data and command-and-control communications frequently employ multi-tier encoding and cryptographic transformations. Threat actors often chain representation formats to bypass network intrusion detection systems, evade static signature analysis, or mask operational parameters.

This module challenges participants to dissect, analyze, and reverse layered transformation sequences:

1. **Layered Data Representation:** Analyzing binary-to-text schemes (Base64) encapsulated within byte-level hexadecimal representations.
2. **Classical Cipher Analysis:** Reversing polyalphabetic substitution ciphers (Vigenère) using contextual intelligence and repeating key recovery.
3. **Encoding vs. Encryption:** Distinguishing unkeyed deterministic representation formats from keyed cryptographic algorithms.

## Official Challenge Lineup

- **Signal in Transit (Easy — 50 Points):** Analyze an intercepted communication artifact wrapped in multiple representation layers.
- **Echoes of the Key (Medium — 100 Points):** Decipher an archived transmission secured by a classical repeating-key cipher and extract the key from operator field logs.

## Submission Instructions

Each challenge generates challenge artifacts dynamically inside your workspace environment at `/challenge/` (and linked to `/home/hacker/`). 

Submit recovered flags in the standard format:
`249shadow{...}`
