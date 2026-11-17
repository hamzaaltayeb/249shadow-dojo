# Echoes of the Key

<badge>Medium</badge> • 100 Points

## Scenario

During an audit of legacy communication relays, intelligence specialists extracted an archived message transmission accompanied by a field operator log. The exfiltrated data stream was passed through a standard transport encoding layer, but the underlying payload was safeguarded with a polyalphabetic classical cipher driven by a repeating alphabetic key.

The station log contains procedural notes recorded by the field operator before going off-grid. By piecing together the operator's clues, you can deduce the repeating key, peel back the transport encoding, decrypt the classical cipher, and recover the flag.

## Challenge Artifacts

Your workspace contains two recovered artifacts in `/challenge/` (and mirrored in `/home/hacker/`):
- `message.b64`: The protected transmission payload in its transport encoding.
- `operator-note.txt`: The recovered station log containing operational context and key derivation clues.

## Cryptographic Architecture & Rules

- **Nested Transformations:** The original message payload was transformed using two stages:
  $$\text{Payload} \overset{\text{Vigenère (Repeating Key)}}{\longrightarrow} \text{Ciphertext} \overset{\text{Base64}}{\longrightarrow} \text{message.b64}$$
- **Recovery Sequence:** To recover the original flag payload, reverse the operations in opposite order:
  $$\text{message.b64} \overset{\text{Base64 Decode}}{\longrightarrow} \text{Ciphertext} \overset{\text{Vigenère Decrypt (Key)}}{\longrightarrow} \text{Original Payload}$$
- **Vigenère Cipher Mechanics:**
  - Operates on ASCII alphabetic characters (`A–Z` and `a–z`), preserving original letter casing.
  - Digits (`0–9`), underscores (`_`), punctuation, and special symbols are **not** shifted and remain untouched.
  - The repeating-key index advances **only** when an alphabetic character is encrypted or decrypted.
  - Encryption formula: $C_i = (P_i + K_j) \bmod 26$
  - Decryption formula: $P_i = (C_i - K_j) \bmod 26$
- **Flag Format Preservation:** The cipher was applied strictly to the payload inside the flag wrapper. Once you have decrypted the payload, reconstruct the complete flag:
  `249shadow{<decrypted_payload>}`

## Progressive Hints

<details>
<summary>Hint 1: Transport Layer</summary>
The file <code>message.b64</code> is not the raw ciphertext. The file extension and characters represent a standard binary-to-text transport encoding. Decode this layer first to reveal the classical ciphertext.
</details>

<details>
<summary>Hint 2: Cipher Classification</summary>
Notice that the decoded message exhibits letter patterns and structure matching English text, but character frequencies are flattened across alphabetic positions. This is the hallmark of a polyalphabetic substitution cipher with a repeating codeword (the Vigenère cipher).
</details>

<details>
<summary>Hint 3: Key Derivation Clue</summary>
Carefully read <code>operator-note.txt</code>. The operator left a tactical riddle identifying the 6-letter codeword used for the repeating key. Consider what physical phenomenon accompanies you in light yet vanishes when all illumination is gone.
</details>
