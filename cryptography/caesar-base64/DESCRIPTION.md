# Caesar + Base64

## Scenario

During a forensic investigation into an Advanced Persistent Threat (APT) campaign targeting the **249shadow Cyber Lab**, incident response analysts discovered a staging script configured to exfiltrate an authentication credential across an encrypted beacon. 

Before transmission, the adversary applied a multi-stage transformation: blending an ancient alphabetic substitution cipher with a modern transport encoding layer to defeat signature matching rules.

## Objective

Analyze the extracted file, dismantle the outer transport encoding layer, solve the inner classical substitution cipher to determine the alphabetic shift, and recover the flag.

## Artifact Location

The intercepted payload is located inside your challenge workspace at:

`/challenge/ciphertext.txt`

You can inspect the artifact using the workspace **Terminal** or **Code** editor.

## Tools Available

Standard command-line utilities and interpreters are available in your environment:
- `cat`, `head`, `wc`
- `base64`
- `tr`
- `python3`

## Flag Format

`249shadow{...}`

Submit the recovered flag in the top action bar to complete the challenge.

---

### Progressive Hints

<details>
<summary>Hint 1: Peeling the Outer Layer</summary>

Inspect `/challenge/ciphertext.txt`. Notice the standard Base64 character set (`[A-Za-z0-9+/=]`). 
Decode this outer layer first using:
```bash
cat /challenge/ciphertext.txt | base64 -d
```
</details>

<details>
<summary>Hint 2: Analyzing the Decoded Structure</summary>

After decoding Base64, inspect the resulting string carefully:
- It begins with the familiar prefix: `249shadow{` and ends with `}`.
- Digits, underscores (`_`), and punctuation are completely unchanged.
- The letters inside the curly braces `{...}` appear scrambled through a monoalphabetic substitution cipher.
</details>

<details>
<summary>Hint 3: Cryptanalysis of the Inner Cipher</summary>

The inner layer is a classical Caesar cipher (alphabetic rotation). In a Caesar cipher, every letter $c$ is shifted by a constant integer $k$:

$$c = (p + k) \pmod{26}$$

Since there are only 25 non-zero shifts, you can write a short Python loop to test all shifts from 1 to 25 and inspect the readable plaintext, or test common rotational offsets such as ROT13 ($k = 13$):

```bash
cat /challenge/ciphertext.txt | base64 -d | tr 'A-Za-z' 'N-ZA-Mn-za-m'
```
</details>
