# Silent Exfiltration

<badge>Medium</badge> • 100 Points

## Scenario

During off-peak hours, network monitoring sensors triggered an alert on workstation `10.10.42.105` for unusual outbound traffic patterns. Forensic responders captured an isolated slice of packet traffic from the perimeter monitoring switch.

The capture contains a blend of background network noise, ordinary DNS lookups, benign internal intranet requests, a routine telemetry heartbeat, and covert multi-part HTTP POST transfers carrying an unauthorized data transmission.

Your objective as a network forensics investigator is to analyze the packet capture, differentiate covert exfiltration traffic from benign noise, reconstruct the segmented TCP sessions, correlate the multi-part data fragments, and reconstruct the competition flag.

## Challenge Artifacts

Your workspace contains two evidence files:
- `/challenge/incident-traffic.pcap` (also mirrored at `/home/hacker/incident-traffic.pcap`)
- `/challenge/incident-brief.txt` (also mirrored at `/home/hacker/incident-brief.txt`)

## Network Architecture & Rules

- **Simulated Environment:** All traffic takes place across simulated private and documentation IP subnets.
- **Protocol Stack:** Ethernet II, IPv4, UDP (DNS), and TCP (HTTP).
- **Decoys & Noise:** Not all outbound HTTP requests carry exfiltrated data. Differentiate benign internal requests and decoy status heartbeats from the actual exfiltration endpoint.
- **Multi-Part Fragmentation:** The flag was divided into multiple distinct fragments and sent across separate HTTP POST sessions. No single packet contains the full flag.
- **Out-of-Order Transfer:** The fragments were deliberately transmitted out of sequence. Each transfer contains explicit sequence metadata (`chunk_index` / `X-Chunk-Index`) and a common transfer session ID (`transfer_id` / `X-Transfer-ID`).
- **No Cryptographic Encoding:** The payload fragments are sent as plain text without Base64 encoding or classical cipher transformations. This challenge tests network forensics and stream reassembly.

## Tooling & Analysis Options

You can inspect and reassemble the capture using:
- **Wireshark / TShark:** Filter by protocol (`dns`, `http`, `http.request.method == "POST"`), follow TCP streams, and examine request headers and payloads.
- **Python 3 Standard Library:** Parse PCAP headers using `struct`, extract HTTP stream payloads, and reassemble chunks by index.
- **Shell Utilities:** Examine strings and streams using `strings`, `grep`, or `tcpdump`.

## Progressive Hints

<details>
<summary>Hint 1: Mapping the Network Hosts</summary>
Inspect DNS queries in the capture (filter: <code>dns</code>). Compare the destinations for internal intranet traffic, legitimate software updates, and suspicious external relay endpoints.
</details>

<details>
<summary>Hint 2: Filtering HTTP POST Transmissions</summary>
Filter for outbound HTTP POST requests (<code>http.request.method == "POST"</code>). Notice which host receives multiple structured requests vs. routine system telemetry.
</details>

<details>
<summary>Hint 3: Correlating Chunks by Index</summary>
Examine the HTTP headers and JSON bodies transmitted to the external relay. Notice the shared <code>transfer_id</code> and the <code>chunk_index</code> parameter. Sort the chunks numerically from 1 to the total count, then concatenate their payloads.
</details>
