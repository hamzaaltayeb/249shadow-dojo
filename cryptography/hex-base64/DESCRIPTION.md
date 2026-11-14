# Hex + Base64

## Scenario

During routine network egress monitoring, the **249shadow Security Operations Center (SOC)** detected an anomalous HTTP outbound request originating from a workstation in the research department. The payload was captured before leaving the perimeter, but preliminary inspection reveals that the exfiltrated string does not resemble standard plaintext text or protocol data.

Threat intelligence reports indicate that the attacker relied on basic multi-stage obfuscation to conceal internal tokens and system credentials from automated signature scanners.

## Objective

Investigate the captured file, determine the encoding schemes applied by the threat actor, reverse the transformation layers in the correct order, and recover the concealed verification flag.

## Artifact Location

The intercepted artifact is located inside your challenge workspace at:

`/challenge/encoded.txt`

You can inspect the artifact using the workspace **Terminal** or **Code** editor.

## Tools Available

Standard command-line utilities and scripting interpreters are available in your environment:
- `cat`, `head`, `tail`, `wc`
- `xxd`, `hexdump`
- `base64`
- `python3`

## Flag Format

`249shadow{...}`

Submit the recovered flag in the top action bar to complete the challenge.

---

### Progressive Hints

<details>
<summary>Hint 1: Inspecting the Raw Artifact (Outer Layer)</summary>

Examine the contents of `/challenge/encoded.txt`. Notice the restricted alphabet:
- Every character is either a decimal digit (`0-9`) or a lowercase hexadecimal letter (`a-f`).
- The length of the string is an even number of characters.
- Each adjacent pair of characters represents the hexadecimal byte value of an underlying ASCII character.

Consider using `xxd -r -p` or Python's `bytes.fromhex(...)` to reverse this outer layer.
</details>

<details>
<summary>Hint 2: Inspecting the Intermediate Layer</summary>

After decoding the hexadecimal stream, observe the output string:
- It contains uppercase letters, lowercase letters, and digits (`[A-Za-z0-9]`).
- It may end with one or two `=` padding characters.
- This 64-character alphabet is the hallmark of Base64 encoding.
</details>

<details>
<summary>Hint 3: Reversing the Pipeline</summary>

Pipeline the decoders together:
1. Decode the outer hexadecimal string into its ASCII text representation.
2. Decode that ASCII text as Base64 to reveal the original `249shadow{...}` flag.

Example one-liner in bash:
```bash
cat /challenge/encoded.txt | xxd -r -p | base64 -d
```
</details>
