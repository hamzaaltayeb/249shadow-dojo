# 249Shadow Cyber Lab — Digital Forensics Module

Welcome to the **Digital Forensics** track of the **249Shadow Cyber Lab**.

## Module Overview

Practical digital forensics challenges focused on artifact triage, file structure analysis, steganographic polyglots, and network traffic reconstruction.

In modern incident response and threat hunting operations, security analysts routinely investigate compromise indicators left behind on endpoint filesystems and captured along enterprise network boundaries. Threat actors frequently conceal sensitive files inside innocent-looking binary formats or split unauthorized data exfiltration across disparate network streams to evade basic pattern-matching detectors.

This module challenges participants to dissect, extract, and reassemble critical evidence:

1. **File Structure & Polyglot Analysis:** Investigating binary boundaries, standard format headers/trailers (such as JPEG SOI/EOI), identifying appended archive structures, and carving hidden compressed containers.
2. **Network Traffic Forensics:** Analyzing PCAP packet captures, performing DNS correlation, filtering application-layer protocols (HTTP/TCP), reconstructing fragmented communication streams, and ordering multi-part payloads.

## Official Challenge Lineup

- **Hidden in Plain Sight (Easy — 50 Points):** Investigate an innocent-looking image recovered from a workstation, identify an appended compressed archive, and extract the hidden flag.
- **Silent Exfiltration (Medium — 100 Points):** Analyze an enterprise network capture, isolate suspicious HTTP POST streams from routine background traffic, and reassemble a multi-part exfiltrated flag.

## Submission Instructions

Each challenge generates realistic evidence files dynamically inside your workspace environment at `/challenge/` (and mirrored to `/home/hacker/`).

Submit recovered flags in the standard format:
`249shadow{...}`
