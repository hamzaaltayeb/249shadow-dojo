#!/usr/bin/env python3
"""
Broken Records - 249shadow DOJO Web Security Challenge
Vulnerability: Insecure Direct Object Reference (IDOR)
"""

import html
import http.cookies
from http.server import HTTPServer, BaseHTTPRequestHandler
import json
import os
import re
import secrets
from socketserver import ThreadingMixIn
import sys
import urllib.parse

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 5000

# User credentials and metadata
USERS = {
    "hacker": {
        "password": "password123",
        "name": "Alex Vance",
        "role": "Junior SOC Analyst",
        "clearance": "Tier 3",
        "department": "Security Operations Center",
        "records": [104, 105],
    },
    "sarah": {
        "password": "password456",
        "name": "Sarah Connor",
        "role": "Operations Specialist",
        "clearance": "Tier 2",
        "department": "Physical Operations",
        "records": [103],
    },
    "marcus": {
        "password": "password789",
        "name": "Marcus Vance",
        "role": "Systems Engineer",
        "clearance": "Tier 2",
        "department": "Infrastructure & Systems",
        "records": [102],
    },
    "elena": {
        "password": "password000",
        "name": "Dr. Elena Rostova",
        "role": "Chief Archivist",
        "clearance": "Tier 1",
        "department": "Cyber Threat Intelligence",
        "records": [101],
    },
    "director": {
        "password": secrets.token_hex(24),
        "name": "Directorate Administrator",
        "role": "Chief Security Officer",
        "clearance": "Level 5 (Directorate Only)",
        "department": "Executive Directorate",
        "records": [100],
    },
}

# In-memory active sessions: token -> username
SESSIONS = {}


def load_flag():
    """Dynamically load and format the challenge flag from /flag."""
    raw_flag = ""
    flag_path = "/flag"
    if os.path.exists(flag_path):
        try:
            with open(flag_path, "r", encoding="utf-8") as f:
                raw_flag = f.read().strip()
        except Exception:
            raw_flag = ""

    if not raw_flag:
        raw_flag = os.environ.get("FLAG", "249shadow{idor_broken_records_access_granted_4821}")

    # Normalize flag format to 249shadow{...}
    m = re.match(r"^pwn\.college\{(.+)\}$", raw_flag)
    if m:
        return f"249shadow{{{m.group(1)}}}"
    elif raw_flag.startswith("249shadow{"):
        return raw_flag
    else:
        return f"249shadow{{{raw_flag}}}"


def get_records():
    """Return all archive records, dynamically binding the current flag to Record 100."""
    flag_value = load_flag()
    return {
        100: {
            "id": 100,
            "title": "Executive Security Audit & Cryptographic Master Key",
            "department": "Executive Directorate",
            "owner": "Directorate Administrator",
            "owner_user": "director",
            "classification": "TOP SECRET // LEVEL 5",
            "date": "2026-11-01",
            "summary": "Classified internal audit report and cryptographic verification key.",
            "content": f"""================================================================================
CLASSIFIED ARCHIVE RECORD #100 - EXECUTIVE OVERSIGHT
================================================================================

DOCUMENT CLASSIFICATION: TOP SECRET // DIRECTORATE EYES ONLY
ARCHIVE REFERENCE: 249-AUDIT-2026-ALPHA
CLEARANCE REQUIRED: LEVEL 5 (EXECUTIVE STAFF ONLY)

MEMORANDUM SUMMARY:
During the recent perimeter and application security audit, our external
security evaluators noted that several internal document portals suffer
from Broken Object Level Authorization (IDOR). Specifically, handlers
rely on client-provided document identifiers without validating whether
the authenticated user's authorization tier permits access.

CRITICAL ASSET / VALIDATION FLAG:
{flag_value}

NOTICE:
Access to this record is strictly restricted to Directorate Administrators.
Any unauthorized retrieval, extraction, or viewing of this file is
logged and monitored by the 249shadow Security Operations Center.
================================================================================""",
        },
        101: {
            "id": 101,
            "title": "Cryptographic Key Rotation Protocol",
            "department": "Cyber Threat Intelligence",
            "owner": "Dr. Elena Rostova",
            "owner_user": "elena",
            "classification": "Confidential",
            "date": "2026-10-15",
            "summary": "Procedures for rotating infrastructure authentication certificates.",
            "content": """Standard operating procedure for quarterly key exchange. All subordinate
nodes must synchronize via secure channel before the first Monday of each quarter.
Note: Master archive references start at index 100.""",
        },
        102: {
            "id": 102,
            "title": "Database Migration & Schema Maintenance",
            "department": "Infrastructure & Systems",
            "owner": "Marcus Vance",
            "owner_user": "marcus",
            "classification": "Internal",
            "date": "2026-10-28",
            "summary": "Record schema update logs and legacy index preservation.",
            "content": """PostgreSQL migration completed successfully. Legacy record identifiers 100
through 105 were migrated into the active archive schema. Automated backups are
archived daily at 0200 UTC.""",
        },
        103: {
            "id": 103,
            "title": "Physical Facility Security & Keycard Audit",
            "department": "Physical Operations",
            "owner": "Sarah Connor",
            "owner_user": "sarah",
            "classification": "Internal",
            "date": "2026-11-05",
            "summary": "Keycard access roster and perimeter checkpoint status.",
            "content": """Facility access credentials verified. Tier 3 keycards issued to SOC analysts.
Physical access to server vaults remains restricted to Level 5 Directorate personnel.""",
        },
        104: {
            "id": 104,
            "title": "Workstation Assignment & Security Clearance - Hacker",
            "department": "Security Operations Center",
            "owner": "Alex Vance",
            "owner_user": "hacker",
            "classification": "Restricted - Tier 3",
            "date": "2026-11-10",
            "summary": "Onboarding dossier and workstation clearance for analyst 'hacker'.",
            "content": """Personnel Dossier:
Employee: Alex Vance
System Username: hacker
Role: Junior SOC Analyst
Assigned Station: SOC-WS-09
Assigned Record IDs: 104, 105

Clearance Notice:
Your Tier 3 credentials permit access to assigned operational records and shift logs.
To request elevated access to higher-tier department records (such as Executive Record #100),
submit Form 249-SEC to your supervisor.""",
        },
        105: {
            "id": 105,
            "title": "SOC Analyst Shift Log & Triage Notes",
            "department": "Security Operations Center",
            "owner": "Alex Vance",
            "owner_user": "hacker",
            "classification": "Restricted - Tier 3",
            "date": "2026-11-12",
            "summary": "Incident triage log and shift handover report.",
            "content": """Shift Handover Log - Analyst: Alex Vance (hacker)
- Shift Time: 00:00 - 08:00 UTC
- Telemetry: Normal baseline activity across all monitored segments.
- Archive Lookup: Tested record retrieval portal using record ID 104 and 105.
- Observation: System administrators noted in Record #102 that legacy archives begin at Record #100.
- Handover to day shift completed without incidents.""",
        },
    }


COMMON_CSS = """
:root {
    --bg-main: #0b0f19;
    --bg-card: #151d30;
    --bg-card-hover: #1c2640;
    --border-color: #273553;
    --text-primary: #e2e8f0;
    --text-secondary: #94a3b8;
    --accent-blue: #38bdf8;
    --accent-green: #34d399;
    --accent-red: #f87171;
    --accent-amber: #fbbf24;
}
* { box-sizing: border-box; margin: 0; padding: 0; }
body {
    background-color: var(--bg-main);
    color: var(--text-primary);
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
    line-height: 1.6;
    padding: 20px;
    min-height: 100vh;
}
.container {
    max-width: 900px;
    margin: 0 auto;
}
header {
    background: var(--bg-card);
    border: 1px solid var(--border-color);
    border-radius: 8px;
    padding: 16px 24px;
    margin-bottom: 24px;
    display: flex;
    justify-content: space-between;
    align-items: center;
    flex-wrap: wrap;
    gap: 12px;
}
.logo-title {
    font-size: 1.25rem;
    font-weight: 700;
    color: var(--accent-blue);
    display: flex;
    align-items: center;
    gap: 10px;
}
.nav-links {
    display: flex;
    align-items: center;
    gap: 16px;
}
.nav-links a {
    color: var(--text-secondary);
    text-decoration: none;
    font-size: 0.9rem;
    transition: color 0.2s;
}
.nav-links a:hover {
    color: var(--accent-blue);
}
.card {
    background: var(--bg-card);
    border: 1px solid var(--border-color);
    border-radius: 8px;
    padding: 24px;
    margin-bottom: 20px;
}
.card-title {
    font-size: 1.15rem;
    font-weight: 600;
    margin-bottom: 12px;
    color: var(--text-primary);
    display: flex;
    align-items: center;
    justify-content: space-between;
}
.badge {
    display: inline-block;
    padding: 4px 10px;
    border-radius: 4px;
    font-size: 0.75rem;
    font-weight: 700;
    text-transform: uppercase;
    letter-spacing: 0.5px;
}
.badge-tier3 { background: #451a03; color: #fde68a; border: 1px solid #78350f; }
.badge-level5 { background: #450a0a; color: #fca5a5; border: 1px solid #7f1d1d; }
.badge-internal { background: #172554; color: #93c5fd; border: 1px solid #1e3a8a; }
.badge-confidential { background: #064e3b; color: #6ee7b7; border: 1px solid #047857; }

.lookup-bar {
    display: flex;
    gap: 10px;
    margin-top: 15px;
    margin-bottom: 20px;
}
input[type="text"], input[type="password"] {
    flex: 1;
    background: #0f172a;
    border: 1px solid var(--border-color);
    color: var(--text-primary);
    padding: 10px 14px;
    border-radius: 6px;
    font-size: 0.95rem;
}
input:focus {
    outline: none;
    border-color: var(--accent-blue);
}
button, .btn {
    background: #0284c7;
    color: #ffffff;
    border: none;
    padding: 10px 18px;
    border-radius: 6px;
    font-size: 0.95rem;
    font-weight: 600;
    cursor: pointer;
    text-decoration: none;
    display: inline-flex;
    align-items: center;
    justify-content: center;
    transition: background-color 0.2s;
}
button:hover, .btn:hover {
    background: #0369a1;
}
.btn-secondary {
    background: #334155;
    color: #e2e8f0;
}
.btn-secondary:hover {
    background: #475569;
}
.btn-danger {
    background: #dc2626;
}
.btn-danger:hover {
    background: #b91c1c;
}
.table-records {
    width: 100%;
    border-collapse: collapse;
    margin-top: 10px;
}
.table-records th, .table-records td {
    padding: 12px 14px;
    text-align: left;
    border-bottom: 1px solid var(--border-color);
}
.table-records th {
    color: var(--text-secondary);
    font-size: 0.85rem;
    text-transform: uppercase;
    letter-spacing: 0.5px;
}
.table-records tr:hover td {
    background: var(--bg-card-hover);
}
.pre-content {
    background: #090d16;
    border: 1px solid #1e293b;
    border-radius: 6px;
    padding: 18px;
    color: #38bdf8;
    font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", "Courier New", monospace;
    font-size: 0.9rem;
    white-space: pre-wrap;
    word-break: break-all;
    overflow-x: auto;
    margin-top: 15px;
}
.alert {
    padding: 14px 18px;
    border-radius: 6px;
    margin-bottom: 20px;
    font-size: 0.95rem;
}
.alert-error {
    background: #450a0a;
    border: 1px solid #991b1b;
    color: #fca5a5;
}
.alert-info {
    background: #082f49;
    border: 1px solid #0369a1;
    color: #7dd3fc;
}
.meta-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
    gap: 15px;
    margin: 15px 0;
    padding: 15px;
    background: #0f172a;
    border-radius: 6px;
    border: 1px solid var(--border-color);
}
.meta-item .meta-label {
    font-size: 0.75rem;
    color: var(--text-secondary);
    text-transform: uppercase;
}
.meta-item .meta-val {
    font-size: 0.95rem;
    font-weight: 600;
    color: var(--text-primary);
}
"""

COMMON_JS = """
<script>
(function() {
    try {
        var params = new URLSearchParams(window.location.search);
        var tok = params.get('_tok') || sessionStorage.getItem('_tok');
        if (params.get('_tok')) {
            sessionStorage.setItem('_tok', params.get('_tok'));
        }
        var p = window.location.pathname;
        if (p.endsWith('/login') || p.endsWith('/logout')) {
            if (p.endsWith('/logout')) {
                sessionStorage.removeItem('_tok');
            }
        } else if (tok) {
            document.querySelectorAll('a').forEach(function(a) {
                var href = a.getAttribute('href');
                if (href && !href.startsWith('#') && !href.startsWith('javascript:') && href.indexOf('_tok=') === -1) {
                    var sep = href.indexOf('?') !== -1 ? '&' : '?';
                    a.setAttribute('href', href + sep + '_tok=' + encodeURIComponent(tok));
                }
            });
            document.querySelectorAll('form').forEach(function(f) {
                if (!f.querySelector('input[name="_tok"]')) {
                    var inp = document.createElement('input');
                    inp.type = 'hidden';
                    inp.name = '_tok';
                    inp.value = tok;
                    f.appendChild(inp);
                }
            });
        }
    } catch(e) {}
})();
</script>
"""


class ThreadedHTTPServer(ThreadingMixIn, HTTPServer):
    daemon_threads = True
    allow_reuse_address = True


class RequestHandler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        # Clean logging
        sys.stderr.write(f"[{self.log_date_time_string()}] {self.address_string()} - {format % args}\n")

    def get_cookie(self, key):
        cookie_header = self.headers.get("Cookie")
        if not cookie_header:
            return None
        c = http.cookies.SimpleCookie()
        try:
            c.load(cookie_header)
            if key in c:
                return c[key].value
        except Exception:
            return None
        return None

    def get_current_user(self):
        # 1. Check Cookie session_id
        session_id = self.get_cookie("session_id")
        if session_id and session_id in SESSIONS:
            username = SESSIONS[session_id]
            if username in USERS:
                return username

        # 2. Check Authorization header (Bearer token or token)
        auth_header = self.headers.get("Authorization")
        if auth_header:
            parts = auth_header.split()
            token = parts[1] if len(parts) == 2 else parts[0]
            if token in SESSIONS:
                username = SESSIONS[token]
                if username in USERS:
                    return username

        # 3. Check X-Session-ID header
        x_sess = self.headers.get("X-Session-ID")
        if x_sess and x_sess in SESSIONS:
            username = SESSIONS[x_sess]
            if username in USERS:
                return username

        # 4. Check _tok URL query parameter (for iframe/cross-site cookie workaround)
        try:
            parsed = urllib.parse.urlparse(self.path)
            query = urllib.parse.parse_qs(parsed.query)
            url_tok = query.get("_tok", [""])[0]
            if url_tok and url_tok in SESSIONS:
                username = SESSIONS[url_tok]
                if username in USERS:
                    return username
        except Exception:
            pass

        return None

    def send_html(self, content, status=200, headers=None):
        data = content.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        if headers:
            for k, v in headers.items():
                self.send_header(k, v)
        self.end_headers()
        self.wfile.write(data)

    def send_json(self, data_dict, status=200, headers=None):
        data = json.dumps(data_dict, indent=2).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        if headers:
            for k, v in headers.items():
                self.send_header(k, v)
        self.end_headers()
        self.wfile.write(data)

    def redirect(self, location, headers=None):
        self.send_response(302)
        self.send_header("Location", location)
        if headers:
            for k, v in headers.items():
                self.send_header(k, v)
        self.end_headers()

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path
        query = urllib.parse.parse_qs(parsed.query)

        current_user = self.get_current_user()

        # Root redirect
        if path == "/":
            if current_user:
                self.redirect("dashboard")
            else:
                self.redirect("login")
            return

        # Auth-redirect: converts a _tok URL param into a proper cookie, then redirects to dashboard.
        # Used by form login to work around SameSite=Lax cross-site iframe cookie restrictions.
        if path == "/auth-redirect":
            tok = query.get("_tok", [""])[0]
            if tok and tok in SESSIONS:
                self.redirect(f"dashboard?_tok={tok}", headers={
                    "Set-Cookie": f"session_id={tok}; Path=/; HttpOnly"
                })
            else:
                self.redirect("login")
            return

        # Login page
        if path == "/login":
            if current_user:
                tok_param = f"?_tok={query.get('_tok', [''])[0]}" if query.get("_tok") else ""
                self.redirect(f"dashboard{tok_param}")
                return
            error_param = query.get("error", [""])[0]
            self.render_login_page(error_msg="Authentication required to access archive." if error_param == "auth_required" else None)
            return

        # Logout
        if path == "/logout":
            session_id = self.get_cookie("session_id") or query.get("_tok", [""])[0]
            if session_id and session_id in SESSIONS:
                del SESSIONS[session_id]
            self.redirect("login", headers={"Set-Cookie": "session_id=; Max-Age=0; Path=/"})
            return

        # JSON API: GET /api/records
        if path in ("/api/records", "/api/record"):
            if not current_user:
                self.send_json({"error": "Unauthorized: Authentication required"}, status=401)
                return

            records = get_records()
            rec_id_str = query.get("id", [""])[0]
            if rec_id_str:
                try:
                    rec_id = int(rec_id_str)
                except ValueError:
                    self.send_json({"error": "Invalid record ID"}, status=400)
                    return

                # IDOR VULNERABILITY: No ownership check!
                if rec_id in records:
                    self.send_json(records[rec_id], status=200)
                else:
                    self.send_json({"error": f"Record #{rec_id} not found"}, status=404)
                return
            else:
                # Return list of user's own records by default
                user_info = USERS[current_user]
                user_records = [records[rid] for rid in user_info["records"] if rid in records]
                self.send_json({"accessible_records": user_records}, status=200)
                return

        # Dashboard page
        if path == "/dashboard":
            if not current_user:
                self.redirect("login?error=auth_required")
                return
            self.render_dashboard(current_user)
            return

        # Record detail page: /record or /records or /record/<id>
        if path in ("/record", "/records") or path.startswith("/record/"):
            if not current_user:
                self.redirect("login?error=auth_required")
                return

            # Extract record ID from path (/record/104) or query string (?id=104)
            record_id = None
            if path.startswith("/record/") and len(path) > len("/record/"):
                id_part = path[len("/record/"):].strip("/")
                try:
                    record_id = int(id_part)
                except ValueError:
                    record_id = None

            if record_id is None:
                id_param = query.get("id", [""])[0]
                if id_param:
                    try:
                        record_id = int(id_param)
                    except ValueError:
                        record_id = None

            if record_id is None:
                self.redirect("dashboard")
                return

            records = get_records()
            # IDOR VULNERABILITY:
            # We look up the requested record without verifying if current_user owns it!
            if record_id in records:
                self.render_record_page(current_user, records[record_id])
            else:
                self.render_not_found_page(current_user, record_id)
            return

        # 404 for any other path
        self.send_html("<h1>404 Not Found</h1>", status=404)

    def do_POST(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path

        content_length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_length).decode("utf-8", errors="replace")

        # JSON Login API
        if path == "/api/login":
            try:
                data = json.loads(body)
                username = data.get("username", "").strip()
                password = data.get("password", "").strip()
            except Exception:
                self.send_json({"error": "Invalid JSON format"}, status=400)
                return

            if username in USERS and USERS[username]["password"] == password:
                token = secrets.token_hex(16)
                SESSIONS[token] = username
                self.send_json({
                    "success": True,
                    "session": token,
                    "user": {
                        "username": username,
                        "name": USERS[username]["name"],
                        "role": USERS[username]["role"],
                        "clearance": USERS[username]["clearance"],
                    }
                }, headers={"Set-Cookie": f"session_id={token}; Path=/; HttpOnly"})
            else:
                self.send_json({"error": "Invalid credentials"}, status=401)
            return

        # Form Login
        if path == "/login":
            form_data = urllib.parse.parse_qs(body)
            username = form_data.get("username", [""])[0].strip()
            password = form_data.get("password", [""])[0].strip()

            if username in USERS and USERS[username]["password"] == password:
                token = secrets.token_hex(16)
                SESSIONS[token] = username
                # Redirect with _tok in URL and Set-Cookie for full cross-site iframe compatibility
                self.redirect(f"dashboard?_tok={token}", headers={
                    "Set-Cookie": f"session_id={token}; Path=/; HttpOnly"
                })
            else:
                self.render_login_page(error_msg="Invalid username or password.")
            return

        self.send_html("<h1>404 Not Found</h1>", status=404)

    def render_login_page(self, error_msg=None):
        error_html = f'<div class="alert alert-error">{html.escape(error_msg)}</div>' if error_msg else ''
        content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Login - 249shadow Records Archive</title>
    <style>{COMMON_CSS}</style>
</head>
<body>
    <div class="container" style="max-width: 480px; margin-top: 60px;">
        <div style="text-align: center; margin-bottom: 25px;">
            <h1 style="color: var(--accent-blue); font-size: 1.8rem; margin-bottom: 8px;">249shadow Archive</h1>
            <p style="color: var(--text-secondary); font-size: 0.95rem;">Department of Records & Document Management</p>
        </div>

        {error_html}

        <div class="card">
            <h2 class="card-title" style="margin-bottom: 20px;">Staff Authentication</h2>
            <form method="POST" action="login">
                <div style="margin-bottom: 16px;">
                    <label style="display: block; font-size: 0.85rem; color: var(--text-secondary); margin-bottom: 6px;">Username</label>
                    <input type="text" name="username" placeholder="e.g. hacker" required autofocus style="width: 100%;">
                </div>
                <div style="margin-bottom: 24px;">
                    <label style="display: block; font-size: 0.85rem; color: var(--text-secondary); margin-bottom: 6px;">Password</label>
                    <input type="password" name="password" placeholder="Enter password" required style="width: 100%;">
                </div>
                <button type="submit" style="width: 100%;">Authenticate Session</button>
            </form>
        </div>

        <div class="alert alert-info" style="font-size: 0.85rem;">
            <strong>System Notice:</strong> Internal access only.<br>
            Staff credentials: <code>hacker</code> / <code>password123</code>
        </div>
    </div>
    {COMMON_JS}
</body>
</html>"""
        self.send_html(content)

    def render_dashboard(self, username):
        user_info = USERS[username]
        records = get_records()

        records_rows = ""
        for rid in user_info["records"]:
            if rid in records:
                rec = records[rid]
                badge_class = "badge-tier3" if "Tier 3" in rec["classification"] else "badge-internal"
                records_rows += f"""
                <tr>
                    <td><strong>#{rec['id']}</strong></td>
                    <td>{html.escape(rec['title'])}</td>
                    <td><span class="badge {badge_class}">{html.escape(rec['classification'])}</span></td>
                    <td>{html.escape(rec['date'])}</td>
                    <td><a href="record?id={rec['id']}" class="btn" style="padding: 6px 12px; font-size: 0.85rem;">View Record</a></td>
                </tr>
                """

        content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Dashboard - 249shadow Records Archive</title>
    <style>{COMMON_CSS}</style>
</head>
<body>
    <div class="container">
        <header>
            <div class="logo-title">
                <span>📁 249shadow Archive</span>
            </div>
            <div class="nav-links">
                <span>User: <strong>{html.escape(user_info['name'])}</strong> ({html.escape(username)})</span>
                <span class="badge badge-tier3">{html.escape(user_info['clearance'])}</span>
                <a href="logout" style="color: var(--accent-red);">Logout</a>
            </div>
        </header>

        <div class="card">
            <h2 class="card-title">Direct Record Identifier Lookup</h2>
            <p style="color: var(--text-secondary); font-size: 0.9rem;">
                Authorized personnel may query archive files directly by record identifier:
            </p>
            <form method="GET" action="record" class="lookup-bar">
                <input type="text" name="id" placeholder="Enter Record ID (e.g. 104)" required>
                <button type="submit">Lookup Record</button>
            </form>
        </div>

        <div class="card">
            <h2 class="card-title">Assigned Personnel & Department Records</h2>
            <p style="color: var(--text-secondary); font-size: 0.9rem; margin-bottom: 12px;">
                The following records are provisioned under your department profile ({html.escape(user_info['department'])}):
            </p>
            <table class="table-records">
                <thead>
                    <tr>
                        <th>ID</th>
                        <th>Document Title</th>
                        <th>Classification</th>
                        <th>Date</th>
                        <th>Action</th>
                    </tr>
                </thead>
                <tbody>
                    {records_rows}
                </tbody>
            </table>
        </div>

        <div class="card" style="font-size: 0.85rem; color: var(--text-secondary);">
            <strong>Archive Policy Notice:</strong> Document identifiers are sequentially assigned starting from the Directorate master catalog. Cross-department inquiries require written authorization from the Chief Information Security Officer.
        </div>
    </div>
    {COMMON_JS}
</body>
</html>"""
        self.send_html(content)

    def render_record_page(self, username, record):
        user_info = USERS[username]

        classification = record["classification"]
        badge_class = "badge-internal"
        if "LEVEL 5" in classification or "TOP SECRET" in classification:
            badge_class = "badge-level5"
        elif "Tier 3" in classification:
            badge_class = "badge-tier3"
        elif "Confidential" in classification:
            badge_class = "badge-confidential"

        content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Record #{record['id']} - 249shadow Records Archive</title>
    <style>{COMMON_CSS}</style>
</head>
<body>
    <div class="container">
        <header>
            <div class="logo-title">
                <a href="dashboard" style="color: var(--accent-blue); text-decoration: none;">📁 249shadow Archive</a>
                <span style="color: var(--text-secondary); font-size: 0.9rem;">/ Record #{record['id']}</span>
            </div>
            <div class="nav-links">
                <span>User: <strong>{html.escape(user_info['name'])}</strong></span>
                <a href="dashboard">Dashboard</a>
                <a href="logout" style="color: var(--accent-red);">Logout</a>
            </div>
        </header>

        <div class="card">
            <div class="card-title">
                <span>{html.escape(record['title'])}</span>
                <span class="badge {badge_class}">{html.escape(classification)}</span>
            </div>

            <div class="meta-grid">
                <div class="meta-item">
                    <div class="meta-label">Record Identifier</div>
                    <div class="meta-val">#{record['id']}</div>
                </div>
                <div class="meta-item">
                    <div class="meta-label">Department</div>
                    <div class="meta-val">{html.escape(record['department'])}</div>
                </div>
                <div class="meta-item">
                    <div class="meta-label">Owner / Author</div>
                    <div class="meta-val">{html.escape(record['owner'])}</div>
                </div>
                <div class="meta-item">
                    <div class="meta-label">Archived Date</div>
                    <div class="meta-val">{html.escape(record['date'])}</div>
                </div>
            </div>

            <p style="color: var(--text-secondary); margin-bottom: 8px;"><strong>Summary:</strong> {html.escape(record['summary'])}</p>

            <div class="pre-content">{html.escape(record['content'])}</div>

            <div style="margin-top: 25px; display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 10px;">
                <a href="dashboard" class="btn btn-secondary">← Return to Dashboard</a>

                <form method="GET" action="record" style="display: flex; gap: 8px; align-items: center;">
                    <span style="font-size: 0.85rem; color: var(--text-secondary);">Query Record ID:</span>
                    <input type="text" name="id" value="{record['id']}" style="width: 90px; padding: 6px 10px;" required>
                    <button type="submit" style="padding: 6px 14px; font-size: 0.85rem;">Go</button>
                </form>
            </div>
        </div>
    </div>
    {COMMON_JS}
</body>
</html>"""
        self.send_html(content)

    def render_not_found_page(self, username, record_id):
        user_info = USERS[username]
        content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Record Not Found - 249shadow Records Archive</title>
    <style>{COMMON_CSS}</style>
</head>
<body>
    <div class="container">
        <header>
            <div class="logo-title">
                <a href="dashboard" style="color: var(--accent-blue); text-decoration: none;">📁 249shadow Archive</a>
            </div>
            <div class="nav-links">
                <span>User: <strong>{html.escape(user_info['name'])}</strong></span>
                <a href="dashboard">Dashboard</a>
                <a href="logout" style="color: var(--accent-red);">Logout</a>
            </div>
        </header>

        <div class="card" style="text-align: center; padding: 40px 20px;">
            <h2 style="color: var(--accent-red); margin-bottom: 12px;">Archive Record #{record_id} Not Found</h2>
            <p style="color: var(--text-secondary); max-width: 500px; margin: 0 auto 24px auto;">
                The requested document identifier was not found in the active archive repository index. Please verify the ID number.
            </p>
            <form method="GET" action="record" class="lookup-bar" style="max-width: 350px; margin: 0 auto 20px auto;">
                <input type="text" name="id" placeholder="Try Record ID (e.g. 104)" required>
                <button type="submit">Lookup</button>
            </form>
            <a href="dashboard" class="btn btn-secondary">Return to Dashboard</a>
        </div>
    </div>
    {COMMON_JS}
</body>
</html>"""
        self.send_html(content, status=404)


def main():
    server_address = ("0.0.0.0", PORT)
    httpd = ThreadedHTTPServer(server_address, RequestHandler)
    print(f"[*] Broken Records web server listening on 0.0.0.0:{PORT}")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        httpd.server_close()


if __name__ == "__main__":
    main()
