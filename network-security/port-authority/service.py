#!/usr/bin/env python3
"""
Port Authority — TCP Diagnostic Service
249Shadow CTF · Easy · 50 pts

Binds to 127.0.0.1 on a deterministic port derived from the flag.
Port range: 31000–31999 (documented in network-scope.txt).

Supported commands (sent as plain text lines):
  HELP      – list available commands
  STATUS    – service health status
  VERSION   – firmware / build information
  DIAG      – run full diagnostic (leaks the flag)
"""

import hashlib
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

# ── port selection (deterministic, hashlib-based) ─────────────────────────────

PORT_RANGE_START = 31000
PORT_RANGE_SIZE  = 1000          # 31000–31999

def _port_for_flag(flag: str) -> int:
    digest = int(hashlib.sha256(flag.encode()).hexdigest(), 16)
    return PORT_RANGE_START + (digest % PORT_RANGE_SIZE)

SERVICE_PORT = _port_for_flag(FLAG)


# ── responses ─────────────────────────────────────────────────────────────────

BANNER = (
    "NGDS Diagnostic Shell v1.2 — Authorized Access Only\r\n"
    "Type HELP for available commands.\r\n"
)

HELP_TEXT = (
    "Available commands:\r\n"
    "  HELP      Display this help message\r\n"
    "  STATUS    Show service health status\r\n"
    "  VERSION   Show firmware and build information\r\n"
    "  DIAG      Run full diagnostic report\r\n"
    "  QUIT      Disconnect\r\n"
)

STATUS_TEXT = (
    "Service status: OPERATIONAL\r\n"
    "Uptime: 847 days\r\n"
    "Active connections: 1\r\n"
    "Diagnostic mode: ENABLED\r\n"
)

VERSION_TEXT = (
    "NGDS (Network Gateway Diagnostic Shell)\r\n"
    "Build: 20220314-stable\r\n"
    "Platform: internal-arm-v7\r\n"
    "Maintainer: netops@internal (DEPRECATED - DO NOT USE IN PROD)\r\n"
)


def diag_text() -> str:
    return (
        "=== FULL DIAGNOSTIC REPORT ===\r\n"
        "Host:     127.0.0.1\r\n"
        "Service:  NGDS v1.2\r\n"
        "Result:   ALL SYSTEMS NOMINAL\r\n"
        "AuthKey:  " + FLAG + "\r\n"
        "==============================\r\n"
    )


# ── connection handler ────────────────────────────────────────────────────────

def handle_client(conn: socket.socket, addr):
    try:
        conn.settimeout(60)
        conn.sendall(BANNER.encode())
        buf = b""
        while True:
            try:
                chunk = conn.recv(256)
            except (OSError, ConnectionResetError):
                break
            if not chunk:
                break
            buf += chunk
            while b"\n" in buf:
                line, buf = buf.split(b"\n", 1)
                cmd = line.strip().decode(errors="replace").upper()
                if cmd == "HELP":
                    conn.sendall(HELP_TEXT.encode())
                elif cmd == "STATUS":
                    conn.sendall(STATUS_TEXT.encode())
                elif cmd == "VERSION":
                    conn.sendall(VERSION_TEXT.encode())
                elif cmd == "DIAG":
                    conn.sendall(diag_text().encode())
                elif cmd in ("QUIT", "EXIT", "BYE"):
                    conn.sendall(b"Goodbye.\r\n")
                    return
                elif cmd == "":
                    pass
                else:
                    conn.sendall(f"Unknown command: {cmd!r}. Type HELP.\r\n".encode())
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
    srv.bind(("127.0.0.1", SERVICE_PORT))
    srv.listen(16)
    while True:
        try:
            conn, addr = srv.accept()
            t = threading.Thread(target=handle_client, args=(conn, addr), daemon=True)
            t.start()
        except Exception:
            pass


if __name__ == "__main__":
    run_server()
