# Signal in Transit

<badge>Easy</badge> • 50 Points

## Scenario

A communication fragment was recovered from an intercepted transmission during a perimeter monitoring sweep. Field telemetry indicates that before the data was recorded to disk, the sender transformed the message payload through multiple successive representation layers to obscure its structure.

An analyst isolated the resulting data stream into an artifact named `transmission.hex`. Your assignment is to inspect the artifact, identify each representation layer, reverse the transformations in the correct sequence, and reconstruct the original competition flag.

## Challenge Artifact

Your workspace contains the exfiltrated transmission file:
- `/challenge/transmission.hex` (also mirrored at `/home/hacker/transmission.hex`)

## Cryptographic Architecture & Rules

- **Multi-Layer Encoding:** The original plaintext payload was passed through exactly two standard encoding operations during transit:
  $$\text{Payload} \longrightarrow \text{Base64} \longrightarrow \text{Hexadecimal}$$
- **Reversal Order:** Because encodings act as nested envelopes, recovery requires reversing each layer in the strict inverse order of generation:
  $$\text{transmission.hex} \longrightarrow \text{Hex Decode} \longrightarrow \text{Base64 Decode} \longrightarrow \text{Original Payload}$$
- **Flag Format Preservation:** The artifact contains only the transformed message payload. The flag wrapper is **not** part of the encoded bytes:
  - If the decoded payload is `example_token_123`, the valid flag to submit is:
    `249shadow{example_token_123}`

## Tooling & Verification

No specialized third-party tools or external packages are required. A simple Python 3 script using only standard library modules (such as `bytes.fromhex()` and `base64.b64decode()`) or standard shell utilities is completely sufficient.

## Progressive Hints

<details>
<summary>Hint 1: Layered Encodings</summary>
The message is represented using two distinct encoding formats rather than keyed mathematical encryption. No secret key is required to reverse the transformations.
</details>

<details>
<summary>Hint 2: Outer Layer Identification</summary>
Inspect the character set inside <code>transmission.hex</code>. Notice that the entire content consists of pairs of hexadecimal ASCII characters (0–9 and a–f). What standard Python method or utility converts hexadecimal text back into raw bytes?
</details>

<details>
<summary>Hint 3: Inner Layer Identification</summary>
After converting the hexadecimal text back into bytes, examine the resulting ASCII string. The character distribution, alphabet (A–Z, a–z, 0–9, +, /), and potential padding (<code>=</code>) point to another ubiquitous binary-to-text encoding format.
</details>
