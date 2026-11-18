# Trust Boundary

**Difficulty:** Medium · **Points:** 100 · **Category:** Network Security

---

## Scenario

A network engineer recently updated the firewall policy on **edge-fw**, a perimeter
router separating the User Network from the Management Network.

A security review flagged potential issues with the access-control configuration.
You have been given read access to the firewall documentation and change log.

A local gateway simulation is running at `127.0.0.1:8881`.  
You can submit routing queries to it and observe whether traffic would be permitted
or denied under the current ACL.

---

## Objective

Reach the management console at `10.10.3.10:8443` from a user workstation
(`10.10.1.0/24`), bypassing the intended access controls.

If your packet is permitted, the management console will return a diagnostic token.

---

## Network Topology

```
  [USERS-NET]          [TRANSIT-NET]         [MGMT-NET]
  10.10.1.0/24  ──fa0/0──  edge-fw  ──fa0/1──  10.10.3.0/24
                        10.10.2.0/24
```

Review the topology and ACL files in your home directory.

---

## Gateway Protocol

Send a plain-text query to `127.0.0.1:8881`:

```
REQUEST source=<ip> dest=<ip> port=<port> proto=<tcp|udp>
```

Example:

```python
import socket

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(('127.0.0.1', 8881))
s.recv(1024)                     # discard banner
s.send(b'REQUEST source=10.10.1.50 dest=10.10.3.10 port=8443 proto=tcp\n')
print(s.recv(4096).decode())
```

The gateway returns either:

```
PERMIT: <management console response>
```

or

```
DENY: rule <N> — <reason>
```

---

## Files in Your Home Directory

| File | Description |
|------|-------------|
| `network-topology.txt` | Full network topology diagram |
| `routing-table.txt` | edge-fw routing table |
| `edge-firewall-acl.conf` | Current ACL configuration |
| `change-log.txt` | Recent firewall change history |

---

> Read the ACL and change log carefully.
> Think about *where* and *in which direction* the ACL is applied.
