#!/usr/bin/env python3
"""
Trust Boundary — Gateway + Management Service
249Shadow CTF · Medium · 100 pts

Network topology (simulated):
  USERS-NET (10.10.1.0/24) ──fa0/0── edge-fw ──fa0/1── MGMT-NET (10.10.3.0/24)

ACL "MGMT-PROTECT" is documented as applied to fa0/1 INBOUND
(i.e., traffic flowing FROM management side INTO the router).

VULNERABILITY: The ACL was accidentally applied on fa0/1 (facing MGMT-NET)
in the INBOUND direction, which only inspects traffic ORIGINATING from
10.10.3.0/24 (management hosts going outbound). It does NOT inspect traffic
flowing FROM fa0/0 (users) TOWARD fa0/1 (management). That direction is
completely unfiltered — any source from USERS-NET can reach MGMT-NET.

The gateway simulates this by applying the ACL only on fa0/1-inbound
(src = 10.10.3.x going outbound), leaving fa0/0→fa0/1 (user→mgmt) wide open.

Protocol on 127.0.0.1:8881:
  Banner, then accept lines like:
    REQUEST source=<ip> dest=<ip> port=<port> proto=<tcp|udp>
  Reply:
    PERMIT: <mgmt console response with flag>
    DENY: rule <N> — <reason>
"""

import ipaddress
import os
import pathlib
import socket
import threading


# ── flag ─────────────────────────────────────────────────────────────────────

def load_flag() -> str:
    p = pathlib.Path("/flag")
    if p.exists():
        try:
            return p.read_text(encoding="utf-8").strip()
        except Exception:
            pass
    flag = os.environ.get("FLAG", "").strip()
    return flag if flag else "249shadow{network_test_fixture_01}"


FLAG = load_flag()

GATEWAY_PORT = 8881

# ── network definitions ───────────────────────────────────────────────────────

USERS_NET   = ipaddress.ip_network("10.10.1.0/24")
TRANSIT_NET = ipaddress.ip_network("10.10.2.0/24")
MGMT_NET    = ipaddress.ip_network("10.10.3.0/24")

MGMT_CONSOLE_IP   = ipaddress.ip_address("10.10.3.10")
MGMT_CONSOLE_PORT = 8443


# ── ACL engine ────────────────────────────────────────────────────────────────
# ACL "MGMT-PROTECT" (applied fa0/1 INBOUND — traffic FROM management side)
# This only checks packets whose SOURCE is in MGMT-NET going the other way.
# It does NOT apply to user→mgmt traffic (that comes in on fa0/0 inbound).

ACL_RULES = [
    # (rule_id, action, src_net_or_None, dst_net_or_None, dst_port_or_None, proto_or_None, description)
    (10, "DENY",   MGMT_NET, None,       None, None,  "Block mgmt hosts from initiating outbound sessions"),
    (20, "PERMIT", None,     None,       None, None,  "Implicit permit all (fa0/1 inbound — existing sessions)"),
]


def _in_net(ip_str: str, net) -> bool:
    try:
        return ipaddress.ip_address(ip_str) in net
    except ValueError:
        return False


def evaluate_acl(src_ip: str, dst_ip: str, dst_port: int, proto: str) -> tuple[bool, str]:
    """
    Evaluate ACL 'MGMT-PROTECT' applied fa0/1 INBOUND.
    Traffic from USERS-NET toward MGMT-NET arrives on fa0/0 inbound and is
    forwarded — it is NOT subject to this ACL at all.
    Returns (permitted: bool, reason: str).
    """
    src = ipaddress.ip_address(src_ip)
    dst = ipaddress.ip_address(dst_ip)

    # Determine ingress interface
    if src in USERS_NET:
        ingress = "fa0/0"
    elif src in TRANSIT_NET:
        ingress = "fa0/1"   # unlikely but transit could initiate
    elif src in MGMT_NET:
        ingress = "fa0/1"
    else:
        ingress = "unknown"

    # ACL is applied only on fa0/1 INBOUND
    if ingress != "fa0/1":
        # ACL not applied — traffic passes without inspection
        return True, f"No ACL on {ingress} inbound — traffic unfiltered"

    # Apply fa0/1-inbound ACL rules
    for rule_id, action, src_net, dst_net, dst_port_match, proto_match, desc in ACL_RULES:
        if src_net is not None and src not in src_net:
            continue
        if dst_net is not None and dst not in dst_net:
            continue
        if dst_port_match is not None and dst_port != dst_port_match:
            continue
        if proto_match is not None and proto.lower() != proto_match.lower():
            continue
        return (action == "PERMIT"), f"rule {rule_id} — {desc}"

    return False, "implicit deny all"


def mgmt_console_response() -> str:
    return (
        "HTTP/1.1 200 OK\r\n"
        "Content-Type: text/plain\r\n"
        "\r\n"
        "=== NGDS Management Console ===\r\n"
        "Host: 10.10.3.10\r\n"
        "Service: Management API v2.1\r\n"
        "Session: AUTHENTICATED (unauthenticated access via ACL bypass)\r\n"
        f"Token: {FLAG}\r\n"
        "================================\r\n"
    )


# ── request parser ────────────────────────────────────────────────────────────

def parse_request(line: str) -> dict | None:
    """Parse: REQUEST source=<ip> dest=<ip> port=<port> proto=<tcp|udp>"""
    line = line.strip()
    if not line.upper().startswith("REQUEST"):
        return None
    params: dict = {}
    for token in line.split()[1:]:
        if "=" in token:
            k, _, v = token.partition("=")
            params[k.lower()] = v
    required = {"source", "dest", "port", "proto"}
    if not required.issubset(params):
        return None
    try:
        params["port"] = int(params["port"])
    except ValueError:
        return None
    return params


BANNER = (
    "edge-fw Gateway Simulator v1.0\r\n"
    "Submit: REQUEST source=<ip> dest=<ip> port=<port> proto=<tcp|udp>\r\n"
)

HELP = (
    "Usage: REQUEST source=<ip> dest=<ip> port=<port> proto=<tcp|udp>\r\n"
    "       QUIT — disconnect\r\n"
)


# ── connection handler ────────────────────────────────────────────────────────

def handle_client(conn: socket.socket):
    try:
        conn.settimeout(60)
        conn.sendall(BANNER.encode())
        buf = b""
        while True:
            try:
                chunk = conn.recv(512)
            except (OSError, ConnectionResetError):
                break
            if not chunk:
                break
            buf += chunk
            while b"\n" in buf:
                line, buf = buf.split(b"\n", 1)
                text = line.strip().decode(errors="replace")
                if not text:
                    continue
                upper = text.upper()
                if upper in ("QUIT", "EXIT", "BYE"):
                    conn.sendall(b"Goodbye.\r\n")
                    return
                if upper in ("HELP", "?"):
                    conn.sendall(HELP.encode())
                    continue
                params = parse_request(text)
                if params is None:
                    conn.sendall(
                        b"ERROR: Invalid syntax. Use: REQUEST source=<ip> dest=<ip> port=<port> proto=<tcp|udp>\r\n"
                    )
                    continue
                try:
                    permitted, reason = evaluate_acl(
                        params["source"], params["dest"], params["port"], params["proto"]
                    )
                except Exception as exc:
                    conn.sendall(f"ERROR: {exc}\r\n".encode())
                    continue

                if permitted:
                    response = f"PERMIT: {reason}\r\n{mgmt_console_response()}"
                    conn.sendall(response.encode())
                else:
                    conn.sendall(f"DENY: {reason}\r\n".encode())
    except Exception:
        pass
    finally:
        try:
            conn.close()
        except Exception:
            pass


# ── server ────────────────────────────────────────────────────────────────────

def run_server():
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", GATEWAY_PORT))
    srv.listen(16)
    while True:
        try:
            conn, _ = srv.accept()
            t = threading.Thread(target=handle_client, args=(conn,), daemon=True)
            t.start()
        except Exception:
            pass


if __name__ == "__main__":
    run_server()
