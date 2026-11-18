# Port Authority

**Difficulty:** Easy · **Points:** 50 · **Category:** Network Security

---

## Scenario

During a network assessment of an internal infrastructure, your team discovered a
diagnostic host at `127.0.0.1`. Intelligence suggests that the host is running a
legacy diagnostic service that was never decommissioned — and that it leaks sensitive
information to anyone who knows how to ask.

Your scope: `127.0.0.1`, port range `31000–31999`.

A network-scope briefing file has been placed in your home directory.

---

## Objective

1. **Discover** the listening diagnostic service on `127.0.0.1` within the documented port range.
2. **Interact** with the service to retrieve the flag.

---

## Hints

No `nmap` or `nc` is required. You can scan and interact using Python alone.

### Port scanner (Python)

```python
import socket

for port in range(31000, 32000):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(0.1)
        s.connect(('127.0.0.1', port))
        banner = s.recv(1024).decode(errors='replace')
        print(f"[OPEN] {port}: {banner.strip()}")
        s.close()
        break
    except Exception:
        pass
```

### Interacting with the service (Python)

```python
import socket

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(('127.0.0.1', <PORT>))
print(s.recv(1024).decode())   # read banner
s.send(b'HELP\n')
print(s.recv(4096).decode())   # read help text
```

---

## Files in Your Home Directory

| File | Description |
|------|-------------|
| `network-scope.txt` | Authorized target scope and port range |
| `incident-note.txt` | Discovery context from the initial assessment |

---

> **Rules:** Interact only with `127.0.0.1` within the documented port range.
> This is an authorized assessment exercise.
