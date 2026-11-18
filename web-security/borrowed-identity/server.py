#!/usr/bin/env python3
"""
249Shadow Cyber Lab — Challenge 01: Borrowed Identity (Easy)
Official Web Security Challenge Server (IDOR / BOLA)
"""

import argparse
import hashlib
import html
import http.server
import json
import os
import pathlib
import secrets
import socketserver
import sqlite3
import sys
import urllib.parse

# In-memory session storage: {token: user_id}
SESSIONS = {}

DB_PATH = None


def get_db():
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn


def hash_password(password: str) -> str:
    return hashlib.sha256(password.encode("utf-8")).hexdigest()


def init_database(db_file: str, flag: str):
    p = pathlib.Path(db_file)
    p.parent.mkdir(parents=True, exist_ok=True)

    conn = sqlite3.connect(db_file)
    cursor = conn.cursor()

    cursor.execute("DROP TABLE IF EXISTS records")
    cursor.execute("DROP TABLE IF EXISTS users")

    cursor.execute("""
        CREATE TABLE users (
            id INTEGER PRIMARY KEY,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            full_name TEXT NOT NULL,
            role TEXT NOT NULL,
            clearance_level TEXT NOT NULL
        )
    """)

    cursor.execute("""
        CREATE TABLE records (
            id INTEGER PRIMARY KEY,
            owner_id INTEGER NOT NULL,
            title TEXT NOT NULL,
            classification TEXT NOT NULL,
            content TEXT NOT NULL,
            date_created TEXT NOT NULL,
            FOREIGN KEY (owner_id) REFERENCES users(id)
        )
    """)

    # Seed users
    # User 1: Authorized analyst (credentials provided in case-file.txt)
    cursor.execute(
        "INSERT INTO users VALUES (?, ?, ?, ?, ?, ?)",
        (1, "j.morrison", hash_password("Password2026!"), "John Morrison", "Junior Security Analyst", "Level 1")
    )
    # User 2: Target executive account (unguessable random password)
    cursor.execute(
        "INSERT INTO users VALUES (?, ?, ?, ?, ?, ?)",
        (2, "k.vance", hash_password(secrets.token_hex(32)), "Katherine Vance", "Chief Forensic Inspector", "Level 4")
    )

    # Seed records
    # Records 101, 102: Assigned to j.morrison
    cursor.execute(
        "INSERT INTO records VALUES (?, ?, ?, ?, ?, ?)",
        (
            101,
            1,
            "Routine Perimeter Log Review — Station 4",
            "INTERNAL // UNRESTRICTED",
            "Standard boundary monitoring completed. No anomalies detected across inbound telemetry nodes. All firewall rules matching baseline policy.",
            "2026-11-10"
        )
    )
    cursor.execute(
        "INSERT INTO records VALUES (?, ?, ?, ?, ?, ?)",
        (
            102,
            1,
            "Workstation Asset Audit — Operations Division",
            "INTERNAL // UNRESTRICTED",
            "Physical asset verification completed for workstations WKSTN-01 through WKSTN-18. All terminal firmware signatures verified against approved baseline hashes.",
            "2026-11-14"
        )
    )

    # Record 105: Target classified brief belonging to Katherine Vance (Contains FLAG)
    cursor.execute(
        "INSERT INTO records VALUES (?, ?, ?, ?, ?, ?)",
        (
            105,
            2,
            "SPECIAL INVESTIGATION: Operation Shadow Veil Final Brief",
            "TOP SECRET // LEVEL-4 EYES ONLY",
            f"Operation Shadow Veil complete. Intercepted clandestine communications deciphered. Decryption master recovery key confirmed: {flag}",
            "2026-11-18"
        )
    )

    conn.commit()
    conn.close()


def get_current_user(headers):
    cookie_header = headers.get("Cookie", "")
    session_token = None
    for cookie in cookie_header.split(";"):
        cookie = cookie.strip()
        if cookie.startswith("session="):
            session_token = cookie.split("session=", 1)[1].strip()
            break

    if not session_token:
        # Also support Authorization: Bearer <token>
        auth_header = headers.get("Authorization", "")
        if auth_header.startswith("Bearer "):
            session_token = auth_header.split("Bearer ", 1)[1].strip()

    if not session_token or session_token not in SESSIONS:
        return None

    user_id = SESSIONS[session_token]
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT id, username, full_name, role, clearance_level FROM users WHERE id = ?", (user_id,))
    row = cursor.fetchone()
    conn.close()
    if row:
        return dict(row)
    return None


# Clean 249Shadow CSS Theme
HTML_HEAD = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>249Shadow // Records Management Portal</title>
<style>
  :root {
    --bg-dark: #0a0e14;
    --bg-surface: #121824;
    --bg-surface-elevated: #1a2332;
    --border-color: rgba(0, 229, 255, 0.22);
    --border-subtle: rgba(255, 255, 255, 0.08);
    --accent-cyan: #00e5ff;
    --accent-amber: #ffaa00;
    --accent-green: #00e676;
    --accent-red: #ff3860;
    --text-white: #f0f6fc;
    --text-secondary: #8b9bb4;
    --text-muted: #57657a;
    --font-mono: 'Space Mono', 'Consolas', 'Courier New', monospace;
    --font-sans: system-ui, -apple-system, 'Segoe UI', Roboto, sans-serif;
  }
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body {
    background: var(--bg-dark);
    color: var(--text-white);
    font-family: var(--font-sans);
    line-height: 1.6;
    min-height: 100vh;
    display: flex;
    flex-direction: column;
  }
  .header {
    background: var(--bg-surface);
    border-bottom: 1px solid var(--border-color);
    padding: 14px 28px;
    display: flex;
    justify-content: space-between;
    align-items: center;
  }
  .brand {
    display: flex;
    align-items: center;
    gap: 12px;
    text-decoration: none;
    color: var(--text-white);
    font-family: var(--font-mono);
    font-size: 1.15rem;
    font-weight: 700;
    letter-spacing: 0.5px;
  }
  .brand-badge {
    color: var(--accent-cyan);
    background: rgba(0, 229, 255, 0.1);
    border: 1px solid var(--accent-cyan);
    padding: 2px 8px;
    border-radius: 3px;
    font-size: 0.8rem;
  }
  .nav-user {
    display: flex;
    align-items: center;
    gap: 16px;
    font-size: 0.9rem;
  }
  .nav-user span { color: var(--text-secondary); }
  .nav-user strong { color: var(--accent-cyan); font-family: var(--font-mono); }
  .btn {
    display: inline-block;
    background: var(--accent-cyan);
    color: #000;
    padding: 8px 16px;
    border-radius: 4px;
    font-weight: 700;
    text-decoration: none;
    font-size: 0.88rem;
    border: none;
    cursor: pointer;
    font-family: var(--font-mono);
    transition: all 0.2s ease;
  }
  .btn:hover { background: #33ebff; transform: translateY(-1px); }
  .btn-outline {
    background: transparent;
    color: var(--text-secondary);
    border: 1px solid var(--border-subtle);
  }
  .btn-outline:hover { color: var(--accent-red); border-color: var(--accent-red); background: rgba(255,56,96,0.08); }
  .container {
    max-width: 1000px;
    width: 100%;
    margin: 40px auto;
    padding: 0 20px;
    flex: 1;
  }
  .card {
    background: var(--bg-surface);
    border: 1px solid var(--border-color);
    border-radius: 6px;
    padding: 28px;
    box-shadow: 0 4px 20px rgba(0,0,0,0.4);
  }
  .card-title {
    font-family: var(--font-mono);
    font-size: 1.35rem;
    color: var(--accent-cyan);
    margin-bottom: 8px;
    display: flex;
    align-items: center;
    gap: 10px;
  }
  .card-subtitle {
    color: var(--text-secondary);
    font-size: 0.92rem;
    margin-bottom: 24px;
  }
  .form-group { margin-bottom: 20px; }
  .form-group label {
    display: block;
    margin-bottom: 8px;
    color: var(--text-secondary);
    font-size: 0.85rem;
    font-family: var(--font-mono);
    text-transform: uppercase;
  }
  .form-control {
    width: 100%;
    background: var(--bg-surface-elevated);
    border: 1px solid var(--border-subtle);
    border-radius: 4px;
    padding: 10px 14px;
    color: var(--text-white);
    font-size: 0.95rem;
    font-family: var(--font-sans);
    outline: none;
    transition: border-color 0.2s;
  }
  .form-control:focus { border-color: var(--accent-cyan); }
  .alert {
    padding: 12px 16px;
    border-radius: 4px;
    margin-bottom: 20px;
    font-size: 0.9rem;
    border: 1px solid transparent;
  }
  .alert-danger {
    background: rgba(255, 56, 96, 0.12);
    border-color: rgba(255, 56, 96, 0.3);
    color: #ff6b8b;
  }
  .table {
    width: 100%;
    border-collapse: collapse;
    margin-top: 10px;
  }
  .table th {
    text-align: left;
    padding: 12px 14px;
    background: var(--bg-surface-elevated);
    color: var(--text-secondary);
    font-family: var(--font-mono);
    font-size: 0.8rem;
    text-transform: uppercase;
    border-bottom: 1px solid var(--border-color);
  }
  .table td {
    padding: 14px;
    border-bottom: 1px solid var(--border-subtle);
    font-size: 0.92rem;
  }
  .badge {
    display: inline-block;
    padding: 3px 8px;
    border-radius: 3px;
    font-size: 0.75rem;
    font-family: var(--font-mono);
    font-weight: 700;
  }
  .badge-unrestricted {
    background: rgba(0, 229, 255, 0.1);
    color: var(--accent-cyan);
    border: 1px solid rgba(0, 229, 255, 0.3);
  }
  .badge-secret {
    background: rgba(255, 170, 0, 0.12);
    color: var(--accent-amber);
    border: 1px solid rgba(255, 170, 0, 0.4);
  }
  .badge-top-secret {
    background: rgba(255, 56, 96, 0.15);
    color: var(--accent-red);
    border: 1px solid rgba(255, 56, 96, 0.5);
    animation: pulse 2s infinite;
  }
  @keyframes pulse {
    0%, 100% { opacity: 1; }
    50% { opacity: 0.75; }
  }
  .record-detail {
    background: var(--bg-surface-elevated);
    border: 1px solid var(--border-subtle);
    border-radius: 4px;
    padding: 20px;
    margin-top: 16px;
    font-family: var(--font-mono);
    font-size: 0.92rem;
    white-space: pre-wrap;
    word-break: break-all;
    line-height: 1.6;
    color: #c9d1d9;
  }
  .footer {
    text-align: center;
    padding: 20px;
    color: var(--text-muted);
    font-size: 0.8rem;
    border-top: 1px solid var(--border-subtle);
    font-family: var(--font-mono);
  }
</style>
</head>
<body>
"""

HTML_FOOT = """
<footer class="footer">
  <div>249SHADOW CYBER LAB &bull; INTERNAL INVESTIGATION RECORDS SYSTEM &bull; ACCESS STRICTLY AUDITED</div>
</footer>
</body>
</html>
"""


class RecordsPortalHandler(http.server.BaseHTTPRequestHandler):
    def send_html(self, content: str, status_code=200, headers=None):
        body = content.encode("utf-8")
        self.send_response(status_code)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        if headers:
            for k, v in headers.items():
                self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def send_json(self, data: dict, status_code=200, headers=None):
        body = json.dumps(data, indent=2).encode("utf-8")
        self.send_response(status_code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        if headers:
            for k, v in headers.items():
                self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def send_redirect(self, location: str, headers=None):
        self.send_response(302)
        self.send_header("Location", location)
        self.send_header("Content-Length", "0")
        if headers:
            for k, v in headers.items():
                self.send_header(k, v)
        self.end_headers()

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path
        query = urllib.parse.parse_qs(parsed.query)

        # Healthcheck endpoint
        if path == "/healthz":
            return self.send_json({"status": "ready"})

        user = get_current_user(self.headers)

        if path == "/":
            if user:
                return self.send_redirect("/dashboard")
            return self.send_redirect("/login")

        if path == "/login":
            if user:
                return self.send_redirect("/dashboard")
            return self.render_login()

        if path == "/logout":
            cookie_header = self.headers.get("Cookie", "")
            for cookie in cookie_header.split(";"):
                if "session=" in cookie:
                    token = cookie.split("session=", 1)[1].strip()
                    SESSIONS.pop(token, None)
            headers = {"Set-Cookie": "session=; Path=/; Expires=Thu, 01 Jan 1970 00:00:00 GMT"}
            return self.send_redirect("/login", headers=headers)

        # Protected routes below: require authenticated user
        if not user:
            if path.startswith("/api/"):
                return self.send_json({"error": "Unauthorized. Please authenticate first."}, status_code=401)
            return self.send_redirect("/login")

        if path == "/dashboard":
            return self.render_dashboard(user)

        if path == "/record" or path.startswith("/api/record"):
            record_id = None
            if "id" in query:
                try:
                    record_id = int(query["id"][0])
                except ValueError:
                    pass
            elif path.startswith("/api/record/"):
                parts = path.split("/api/record/", 1)[1].split("/")
                if parts and parts[0].isdigit():
                    record_id = int(parts[0])

            if record_id is None:
                return self.send_html(self.page_wrap("Invalid Request", "<p>Missing or invalid record ID.</p>"), status_code=400)

            return self.render_record(user, record_id, is_api=path.startswith("/api/"))

        self.send_html(self.page_wrap("404 Not Found", "<p>The requested resource was not found on this server.</p>"), status_code=404)

    def do_POST(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path

        content_length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_length)

        if path == "/login":
            username = ""
            password = ""
            content_type = self.headers.get("Content-Type", "")

            if "application/json" in content_type:
                try:
                    data = json.loads(body.decode("utf-8"))
                    username = data.get("username", "").strip()
                    password = data.get("password", "")
                except Exception:
                    return self.send_json({"error": "Invalid JSON"}, status_code=400)
            else:
                data = urllib.parse.parse_qs(body.decode("utf-8"))
                username = data.get("username", [""])[0].strip()
                password = data.get("password", [""])[0]

            conn = get_db()
            cursor = conn.cursor()
            cursor.execute(
                "SELECT id, username, full_name, role FROM users WHERE username = ? AND password_hash = ?",
                (username, hash_password(password))
            )
            row = cursor.fetchone()
            conn.close()

            if row:
                token = secrets.token_hex(24)
                SESSIONS[token] = row["id"]
                cookie_str = f"session={token}; Path=/; SameSite=Lax; HttpOnly"
                if "application/json" in content_type:
                    return self.send_json(
                        {"status": "success", "token": token, "redirect": "/dashboard"},
                        headers={"Set-Cookie": cookie_str}
                    )
                return self.send_redirect("/dashboard", headers={"Set-Cookie": cookie_str})
            else:
                if "application/json" in content_type:
                    return self.send_json({"error": "Invalid analyst username or password."}, status_code=401)
                return self.render_login(error="Invalid analyst credentials. Check your assigned case file.")

        self.send_html(self.page_wrap("404 Not Found", "<p>Endpoint not found.</p>"), status_code=404)

    def render_login(self, error=None):
        error_box = f'<div class="alert alert-danger">{html.escape(error)}</div>' if error else ""
        content = f"""
        <div class="header">
          <a href="/login" class="brand">
            <span class="brand-badge">[ 249SHADOW ]</span>
            <span>Personnel &amp; Records Archive</span>
          </a>
        </div>
        <div class="container" style="max-width: 480px; margin-top: 70px;">
          <div class="card">
            <div class="card-title">Analyst Authentication</div>
            <div class="card-subtitle">Enter your assigned division credentials to access case records.</div>
            {error_box}
            <form method="POST" action="/login">
              <div class="form-group">
                <label>Analyst Username</label>
                <input type="text" name="username" class="form-control" placeholder="e.g. j.morrison" required autofocus>
              </div>
              <div class="form-group">
                <label>Security Password</label>
                <input type="password" name="password" class="form-control" placeholder="&bull;&bull;&bull;&bull;&bull;&bull;&bull;&bull;" required>
              </div>
              <button type="submit" class="btn" style="width: 100%;">Authenticate Session</button>
            </form>
          </div>
        </div>
        """
        self.send_html(HTML_HEAD + content + HTML_FOOT)

    def render_dashboard(self, user):
        conn = get_db()
        cursor = conn.cursor()
        # Legitimate query for dashboard: shows records assigned to current user
        cursor.execute(
            "SELECT id, title, classification, date_created FROM records WHERE owner_id = ? ORDER BY id ASC",
            (user["id"],)
        )
        records = cursor.fetchall()
        conn.close()

        rows_html = ""
        for r in records:
            badge_class = "badge-unrestricted"
            rows_html += f"""
            <tr>
              <td style="font-family: var(--font-mono); color: var(--accent-cyan); font-weight: 700;">#{r['id']}</td>
              <td><strong>{html.escape(r['title'])}</strong></td>
              <td><span class="badge {badge_class}">{html.escape(r['classification'])}</span></td>
              <td style="color: var(--text-secondary); font-size: 0.85rem;">{html.escape(r['date_created'])}</td>
              <td><a href="/record?id={r['id']}" class="btn" style="padding: 4px 10px; font-size: 0.78rem;">View Record</a></td>
            </tr>
            """

        content = f"""
        <div class="header">
          <a href="/dashboard" class="brand">
            <span class="brand-badge">[ 249SHADOW ]</span>
            <span>Personnel &amp; Records Archive</span>
          </a>
          <div class="nav-user">
            <span>Operator: <strong>{html.escape(user['full_name'])}</strong> ({html.escape(user['role'])})</span>
            <span class="badge badge-unrestricted">{html.escape(user['clearance_level'])}</span>
            <a href="/logout" class="btn btn-outline" style="padding: 4px 10px; font-size: 0.8rem;">Logout</a>
          </div>
        </div>
        <div class="container">
          <div class="card">
            <div class="card-title">Assigned Case Files &amp; Operational Reports</div>
            <div class="card-subtitle">Active investigative records assigned to your operational division.</div>
            
            <table class="table">
              <thead>
                <tr>
                  <th>Record ID</th>
                  <th>Document Title</th>
                  <th>Classification</th>
                  <th>Date Filed</th>
                  <th>Action</th>
                </tr>
              </thead>
              <tbody>
                {rows_html}
              </tbody>
            </table>
          </div>
        </div>
        """
        self.send_html(HTML_HEAD + content + HTML_FOOT)

    def render_record(self, user, record_id: int, is_api: bool = False):
        conn = get_db()
        cursor = conn.cursor()
        # =========================================================================
        # INTENDED IDOR / BOLA FLAW:
        # The query retrieves the record by ID without checking if owner_id == user['id']!
        # Authenticated users can retrieve records belonging to other personnel.
        # =========================================================================
        cursor.execute("""
            SELECT r.id, r.owner_id, r.title, r.classification, r.content, r.date_created,
                   u.full_name as author_name, u.role as author_role, u.clearance_level
            FROM records r
            JOIN users u ON r.owner_id = u.id
            WHERE r.id = ?
        """, (record_id,))
        record = cursor.fetchone()
        conn.close()

        if not record:
            if is_api:
                return self.send_json({"error": f"Record #{record_id} not found"}, status_code=404)
            return self.send_html(self.page_wrap("Record Not Found", f"<p>Record #{record_id} could not be located in the archive.</p>"), status_code=404)

        if is_api:
            return self.send_json({
                "id": record["id"],
                "owner_id": record["owner_id"],
                "author": record["author_name"],
                "role": record["author_role"],
                "title": record["title"],
                "classification": record["classification"],
                "date_created": record["date_created"],
                "content": record["content"]
            })

        badge_class = "badge-unrestricted"
        border_override = ""
        if "TOP SECRET" in record["classification"]:
            badge_class = "badge-top-secret"
            border_override = "border-color: rgba(255, 56, 96, 0.5);"
        elif "SECRET" in record["classification"] or "RESTRICTED" in record["classification"]:
            badge_class = "badge-secret"
            border_override = "border-color: rgba(255, 170, 0, 0.4);"

        content = f"""
        <div class="header">
          <a href="/dashboard" class="brand">
            <span class="brand-badge">[ 249SHADOW ]</span>
            <span>Personnel &amp; Records Archive</span>
          </a>
          <div class="nav-user">
            <span>Operator: <strong>{html.escape(user['full_name'])}</strong></span>
            <a href="/dashboard" class="btn btn-outline" style="padding: 4px 10px; font-size: 0.8rem;">&larr; Back to Dashboard</a>
            <a href="/logout" class="btn btn-outline" style="padding: 4px 10px; font-size: 0.8rem;">Logout</a>
          </div>
        </div>
        <div class="container">
          <div class="card" style="{border_override}">
            <div style="display: flex; justify-content: space-between; align-items: flex-start; margin-bottom: 16px;">
              <div>
                <span class="badge {badge_class}" style="margin-bottom: 8px;">{html.escape(record['classification'])}</span>
                <h1 style="font-family: var(--font-mono); font-size: 1.4rem; color: var(--text-white);">{html.escape(record['title'])}</h1>
              </div>
              <div style="text-align: right; font-family: var(--font-mono); font-size: 0.85rem; color: var(--text-secondary);">
                <div>RECORD IDENTIFIER: <strong style="color: var(--accent-cyan);">#{record['id']}</strong></div>
                <div>FILED: {html.escape(record['date_created'])}</div>
              </div>
            </div>

            <div style="display: flex; gap: 24px; padding: 12px 0; border-top: 1px solid var(--border-subtle); border-bottom: 1px solid var(--border-subtle); font-size: 0.88rem; color: var(--text-secondary);">
              <div>AUTHOR: <strong style="color: var(--text-white);">{html.escape(record['author_name'])}</strong></div>
              <div>TITLE / POSITION: <strong style="color: var(--text-white);">{html.escape(record['author_role'])}</strong></div>
              <div>REQUIRED CLEARANCE: <strong style="color: var(--accent-amber);">{html.escape(record['clearance_level'])}</strong></div>
            </div>

            <div style="margin-top: 24px;">
              <div style="font-family: var(--font-mono); font-size: 0.8rem; text-transform: uppercase; color: var(--text-secondary); margin-bottom: 8px;">Declassified Operational Record Payload:</div>
              <div class="record-detail">{html.escape(record['content'])}</div>
            </div>
          </div>
        </div>
        """
        self.send_html(HTML_HEAD + content + HTML_FOOT)

    def page_wrap(self, title, inner_html):
        return f"""{HTML_HEAD}
        <div class="header">
          <a href="/" class="brand">
            <span class="brand-badge">[ 249SHADOW ]</span>
            <span>Personnel &amp; Records Archive</span>
          </a>
        </div>
        <div class="container" style="max-width: 600px;">
          <div class="card">
            <div class="card-title">{html.escape(title)}</div>
            {inner_html}
            <div style="margin-top: 20px;">
              <a href="/dashboard" class="btn">&larr; Return to Dashboard</a>
            </div>
          </div>
        </div>
        {HTML_FOOT}"""

    def log_message(self, format, *args):
        # Do not print flags or sensitive payload data to stdout/stderr
        pass


class ThreadedHTTPServer(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True
    allow_reuse_address = True


def main():
    global DB_PATH

    parser = argparse.ArgumentParser(description="249Shadow Borrowed Identity Server")
    parser.add_argument("--host", default="0.0.0.0", help="Binding host")
    parser.add_argument("--port", type=int, default=5000, help="Binding port")
    parser.add_argument("--db", default=None, help="SQLite database path")
    parser.add_argument("--flag", default=None, help="Instance flag value")
    args = parser.parse_args()

    # Determine runtime flag
    flag = args.flag
    if not flag:
        flag_path = pathlib.Path("/flag")
        if flag_path.exists():
            try:
                flag = flag_path.read_text(encoding="utf-8").strip()
            except Exception:
                pass
    if not flag:
        flag = os.environ.get("FLAG", "").strip()
    if not flag:
        flag = "249shadow{websec_test_fixture_01}"

    # Determine DB path
    if args.db:
        DB_PATH = args.db
    else:
        # Default secure location
        default_dir = pathlib.Path("/var/lib/249shadow/borrowed-identity")
        if default_dir.parent.exists() or os.geteuid() == 0:
            DB_PATH = str(default_dir / "records.db")
        else:
            DB_PATH = str(pathlib.Path(__file__).parent / "records.db")

    init_database(DB_PATH, flag)

    server = ThreadedHTTPServer((args.host, args.port), RecordsPortalHandler)
    print(f"[+] Borrowed Identity service listening on http://{args.host}:{args.port}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[*] Shutting down server.")
        server.server_close()


if __name__ == "__main__":
    main()
