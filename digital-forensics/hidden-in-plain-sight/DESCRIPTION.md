# Hidden in Plain Sight

<badge>Easy</badge> • 50 Points

## Scenario

An image file was recovered from a workstation during a routine digital investigation. The file appears ordinary, carries standard image dimensions, and renders without visual flaws in common image viewers. However, preliminary triage flagged the file for having an unexpected internal structure.

Your assignment as a digital forensics investigator is to examine the artifact, inspect its binary structure, identify the concealed data container, extract its contents, and recover the flag.

## Challenge Artifacts

Your workspace contains two evidence files:
- `/challenge/evidence_photo.jpg` (also mirrored at `/home/hacker/evidence_photo.jpg`)
- `/challenge/case-notes.txt` (also mirrored at `/home/hacker/case-notes.txt`)

## Forensic Architecture & Clues

- **Image Format:** Standard baseline JPEG files begin with the Start of Image (SOI) marker `\xFF\xD8` and terminate at the End of Image (EOI) marker `\xFF\xD9`.
- **Trailing Data:** Image decoders stop reading pixel data once the EOI marker is reached. Any bytes appended past this boundary remain invisible to regular image viewers.
- **Polyglot Container:** An archive format has been attached to the image. Inspect the byte sequence following the image data to identify standard archive magic bytes.
- **Flag Extraction:** The concealed archive contains `recovered_note.txt`, which preserves the exact competition flag.

## Tooling & Analysis Options

You can investigate and solve this challenge using:
- Command-line archive extractors (`unzip`)
- Python 3 standard library (`zipfile`, `io`, or binary slicing)
- Binary analysis tools (`binwalk`, `xxd`, `hexdump`, or `file`)

## Progressive Hints

<details>
<summary>Hint 1: File Extension vs. File Content</summary>
An ordinary file extension (.jpg) does not guarantee that a file contains only image data. Forensic examiners look beyond extensions into actual file magic numbers and internal sections.
</details>

<details>
<summary>Hint 2: Identifying the Archive Header</summary>
Look for the standard ZIP local file header signature <code>PK\x03\x04</code> (hexadecimal <code>50 4B 03 04</code>) after the JPEG end marker (<code>FF D9</code>).
</details>

<details>
<summary>Hint 3: Extraction Methods</summary>
Python's standard <code>zipfile</code> module can open polyglot files directly (<code>zipfile.ZipFile("evidence_photo.jpg")</code>), or you can extract the archive with <code>unzip evidence_photo.jpg</code>.
</details>
