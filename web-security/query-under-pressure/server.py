#!/usr/bin/env python3
"""
249Shadow Cyber Lab — Challenge 02: Query Under Pressure (Medium)
Official Web Security Challenge Server (SQL Injection - UNION based)
"""

import argparse
import html
import http.server
import json
import os
import pathlib
import socketserver
import sqlite3
import sys
import urllib.parse

DB_PATH = None


def get_db():
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    # Enforce read-only database query mode
    try:
        conn.execute("PRAGMA query_only = ON")
    except Exception:
        pass
    return conn


def init_database(db_file: str, flag: str):
    p = pathlib.Path(db_file)
    p.parent.mkdir(parents=True, exist_ok=True)

    conn = sqlite3.connect(db_file)
    cursor = conn.cursor()

    cursor.execute("DROP TABLE IF EXISTS public_documents")
    cursor.execute("DROP TABLE IF EXISTS restricted_archives")

    # Table 1: Public document collection
    cursor.execute("""
        CREATE TABLE public_documents (
            id INTEGER PRIMARY KEY,
            title TEXT NOT NULL,
            department TEXT NOT NULL,
            summary TEXT NOT NULL,
            publication_date TEXT NOT NULL
        )
    """)

    # Table 2: Restricted archive (Contains FLAG)
    cursor.execute("""
        CREATE TABLE restricted_archives (
            archive_id INTEGER PRIMARY KEY,
            classification TEXT NOT NULL,
            project_codename TEXT NOT NULL,
            clearance_required TEXT NOT NULL,
            secret_payload TEXT NOT NULL
        )
    """)

    # Seed public documents
    public_docs = [
        (
            1,
            "Network Perimeter Defense Architecture 2026",
            "Cyber Defense Division",
            "Standard operating procedures for edge firewall configurations, ingress packet inspection, and DMZ network isolation.",
            "2026-01-15"
        ),
        (
            2,
            "Incident Response Playbook: Ransomware Containment",
            "Security Operations Center",
            "Phased triage protocols for rapid host isolation, memory capture preservation, and revoked credential cycling.",
            "2026-03-22"
        ),
        (
            3,
            "Cryptographic Standard Selection Guidelines",
            "Applied Cryptography Unit",
            "Approved cipher suite configurations, TLS 1.3 parameters, and asymmetric key lifecycle management specifications.",
            "2026-05-18"
        ),
        (
            4,
            "Satellite Uplink Telemetry Analysis Protocols",
            "Signal Intelligence Division",
            "Orbital telemetry monitoring and RF signal anomaly verification procedures across regional communication nodes.",
            "2026-07-09"
        ),
        (
            5,
            "Hardware Security Module Maintenance Schedule",
            "Infrastructure Security",
            "Quarterly physical audit routines, tamper-evident seal verification, and key-wrapping validation guidelines.",
            "2026-09-30"
        ),
        (
            6,
            "Internal Threat Modeling & Microservice Review",
            "Security Engineering",
            "STRIDE framework application requirements for containerized microservices and inter-service authentication tokens.",
            "2026-10-14"
        ),
    ]
    cursor.executemany("INSERT INTO public_documents VALUES (?, ?, ?, ?, ?)", public_docs)

    # Seed restricted archives
    restricted_data = [
        (
            1,
            "RESTRICTED",
            "PROJECT-AEGIS",
            "LEVEL-3",
            "Decommissioned sensor telemetry nodes archived to off-grid vault. Frequency hopping keys rotated."
        ),
        (
            2,
            "TOP SECRET",
            "OPERATION-NIGHTFALL",
            "LEVEL-4",
            f"Classified Operation Nightfall recovery payload: {flag}"
        ),
    ]
    cursor.executemany("INSERT INTO restricted_archives VALUES (?, ?, ?, ?, ?)", restricted_data)

    conn.commit()
    conn.close()


HTML_HEAD = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>249Shadow // Archival Document Search Engine</title>
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
  }
  .brand-badge {
    color: var(--accent-cyan);
    background: rgba(0, 229, 255, 0.1);
    border: 1px solid var(--accent-cyan);
    padding: 2px 8px;
    border-radius: 3px;
    font-size: 0.8rem;
  }
  .container {
    max-width: 1050px;
    width: 100%;
    margin: 36px auto;
    padding: 0 20px;
    flex: 1;
  }
  .card {
    background: var(--bg-surface);
    border: 1px solid var(--border-color);
    border-radius: 6px;
    padding: 28px;
    box-shadow: 0 4px 20px rgba(0,0,0,0.4);
    margin-bottom: 24px;
  }
  .card-title {
    font-family: var(--font-mono);
    font-size: 1.35rem;
    color: var(--accent-cyan);
    margin-bottom: 8px;
  }
  .card-subtitle {
    color: var(--text-secondary);
    font-size: 0.92rem;
    margin-bottom: 20px;
  }
  .search-box {
    display: flex;
    gap: 12px;
    margin-bottom: 16px;
  }
  .search-input {
    flex: 1;
    background: var(--bg-surface-elevated);
    border: 1px solid var(--border-subtle);
    border-radius: 4px;
    padding: 12px 16px;
    color: var(--text-white);
    font-size: 1rem;
    font-family: var(--font-mono);
    outline: none;
    transition: border-color 0.2s;
  }
  .search-input:focus { border-color: var(--accent-cyan); }
  .btn {
    background: var(--accent-cyan);
    color: #000;
    padding: 12px 24px;
    border-radius: 4px;
    font-weight: 700;
    text-decoration: none;
    font-size: 0.92rem;
    border: none;
    cursor: pointer;
    font-family: var(--font-mono);
    transition: all 0.2s ease;
  }
  .btn:hover { background: #33ebff; }
  .keywords {
    display: flex;
    align-items: center;
    gap: 8px;
    flex-wrap: wrap;
    font-size: 0.82rem;
    color: var(--text-muted);
    font-family: var(--font-mono);
  }
  .keyword-tag {
    background: var(--bg-surface-elevated);
    border: 1px solid var(--border-subtle);
    padding: 2px 8px;
    border-radius: 3px;
    color: var(--accent-cyan);
    text-decoration: none;
  }
  .keyword-tag:hover { border-color: var(--accent-cyan); }
  .alert-error {
    background: rgba(255, 56, 96, 0.12);
    border: 1px solid rgba(255, 56, 96, 0.4);
    color: #ff6b8b;
    padding: 14px 18px;
    border-radius: 4px;
    margin-bottom: 20px;
    font-family: var(--font-mono);
    font-size: 0.88rem;
    white-space: pre-wrap;
    word-break: break-all;
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
    vertical-align: top;
  }
  .doc-id {
    font-family: var(--font-mono);
    color: var(--accent-cyan);
    font-weight: 700;
  }
  .doc-title {
    font-weight: 700;
    color: var(--text-white);
    margin-bottom: 4px;
  }
  .doc-dept {
    font-size: 0.82rem;
    color: var(--accent-amber);
    font-family: var(--font-mono);
  }
  .doc-summary {
    font-size: 0.9rem;
    color: var(--text-secondary);
    line-height: 1.5;
    word-break: break-word;
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
<div class="header">
  <a href="/" class="brand">
    <span class="brand-badge">[ 249SHADOW ]</span>
    <span>Archival Document Search Engine</span>
  </a>
  <div style="font-family: var(--font-mono); font-size: 0.82rem; color: var(--text-muted);">
    ENGINE: <span style="color: var(--accent-cyan);">SQLITE3 v3.46.1</span> &bull; STATUS: <span style="color: var(--accent-green);">ONLINE</span>
  </div>
</div>
"""

HTML_FOOT = """
<footer class="footer">
  <div>249SHADOW CYBER LAB &bull; ENTERPRISE SEARCH REPOSITORY &bull; STRICT QUERY ISOLATION ENFORCED</div>
</footer>
</body>
</html>
"""


class SearchPortalHandler(http.server.BaseHTTPRequestHandler):
    def send_html(self, content: str, status_code=200):
        body = content.encode("utf-8")
        self.send_response(status_code)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def send_json(self, data, status_code=200):
        body = json.dumps(data, indent=2).encode("utf-8")
        self.send_response(status_code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path
        query = urllib.parse.parse_qs(parsed.query)

        if path == "/healthz":
            return self.send_json({"status": "ready"})

        is_api = path.startswith("/api/")

        if path in ("/", "/search", "/api/search"):
            search_term = query.get("q", [""])[0]
            return self.handle_search(search_term, is_api=is_api)

        self.send_html(f"{HTML_HEAD}<div class='container'><div class='card'><h1>404 Not Found</h1></div></div>{HTML_FOOT}", status_code=404)

    def do_POST(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path

        content_length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_length)

        search_term = ""
        content_type = self.headers.get("Content-Type", "")
        if "application/json" in content_type:
            try:
                data = json.loads(body.decode("utf-8"))
                search_term = str(data.get("q", ""))
            except Exception:
                pass
        else:
            data = urllib.parse.parse_qs(body.decode("utf-8"))
            search_term = data.get("q", [""])[0]

        is_api = path.startswith("/api/") or "application/json" in self.headers.get("Accept", "")
        return self.handle_search(search_term, is_api=is_api)

    def handle_search(self, search_term: str, is_api: bool = False):
        if not search_term.strip():
            # Default state: display initial public documents
            conn = get_db()
            cursor = conn.cursor()
            cursor.execute("SELECT id, title, department, summary FROM public_documents ORDER BY id ASC")
            default_rows = [list(r) for r in cursor.fetchall()]
            conn.close()

            if is_api:
                return self.send_json({"query": "", "results": default_rows, "count": len(default_rows)})
            return self.render_portal(default_rows, search_term="")

        # =========================================================================
        # INTENDED VULNERABILITY (SQL INJECTION):
        # The query is formed by concatenating user search input directly into the SQL string.
        # The participant can use UNION-based injection to discover columns and query tables.
        # =========================================================================
        sql_query = f"SELECT id, title, department, summary FROM public_documents WHERE title LIKE '%{search_term}%' OR summary LIKE '%{search_term}%' ORDER BY id ASC"

        error_message = None
        results = []

        conn = get_db()
        cursor = conn.cursor()
        try:
            cursor.execute(sql_query)
            raw_rows = cursor.fetchall()
            for r in raw_rows:
                results.append(list(r))
        except sqlite3.Error as e:
            error_message = f"Database Query Syntax Error: {e}"
        finally:
            conn.close()

        if is_api:
            if error_message:
                return self.send_json({"error": error_message, "query": search_term}, status_code=400)
            return self.send_json({"query": search_term, "results": results, "count": len(results)})

        return self.render_portal(results, search_term=search_term, error=error_message)

    def render_portal(self, results, search_term="", error=None):
        error_box = f'<div class="alert-error"><strong>DATABASE EXCEPTION:</strong>\n{html.escape(error)}</div>' if error else ""

        rows_html = ""
        if results:
            for r in results:
                # Handle varying number of columns safely
                doc_id = html.escape(str(r[0])) if len(r) > 0 else "-"
                title = html.escape(str(r[1])) if len(r) > 1 else "-"
                dept = html.escape(str(r[2])) if len(r) > 2 else "-"
                summary = html.escape(str(r[3])) if len(r) > 3 else "-"

                rows_html += f"""
                <tr>
                  <td class="doc-id">#{doc_id}</td>
                  <td>
                    <div class="doc-title">{title}</div>
                    <div class="doc-dept">{dept}</div>
                  </td>
                  <td class="doc-summary">{summary}</td>
                </tr>
                """
        elif not error:
            rows_html = """
            <tr>
              <td colspan="3" style="text-align: center; color: var(--text-muted); padding: 30px;">
                No archival records matched your query terms.
              </td>
            </tr>
            """

        content = f"""
        <div class="container">
          <div class="card">
            <div class="card-title">Central Archival Document Search</div>
            <div class="card-subtitle">Query internal public records, operational guides, and architectural standards.</div>

            <form method="GET" action="/search">
              <div class="search-box">
                <input type="text" name="q" class="search-input" placeholder="Search archive (e.g. perimeter, incident, telemetry)..." value="{html.escape(search_term)}" autofocus>
                <button type="submit" class="btn">Execute Search</button>
              </div>
            </form>

            <div class="keywords">
              <span>SUGGESTED QUERY TAGS:</span>
              <a href="/search?q=perimeter" class="keyword-tag">perimeter</a>
              <a href="/search?q=incident" class="keyword-tag">incident</a>
              <a href="/search?q=cryptographic" class="keyword-tag">cryptographic</a>
              <a href="/search?q=telemetry" class="keyword-tag">telemetry</a>
              <a href="/search?q=microservice" class="keyword-tag">microservice</a>
            </div>
          </div>

          {error_box}

          <div class="card">
            <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 12px;">
              <h2 style="font-family: var(--font-mono); font-size: 1.1rem; color: var(--accent-cyan);">Archival Query Results</h2>
              <span style="font-family: var(--font-mono); font-size: 0.8rem; color: var(--text-muted);">{len(results)} RECORDS FOUND</span>
            </div>

            <table class="table">
              <thead>
                <tr>
                  <th style="width: 100px;">Index</th>
                  <th style="width: 320px;">Document &bull; Division</th>
                  <th>Executive Summary / Payload</th>
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

    def log_message(self, format, *args):
        # Do not print query payloads or flags to logs
        pass


class ThreadedHTTPServer(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True
    allow_reuse_address = True


def main():
    global DB_PATH

    parser = argparse.ArgumentParser(description="249Shadow Query Under Pressure Server")
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
        default_dir = pathlib.Path("/var/lib/249shadow/query-under-pressure")
        if default_dir.parent.exists() or os.geteuid() == 0:
            DB_PATH = str(default_dir / "documents.db")
        else:
            DB_PATH = str(pathlib.Path(__file__).parent / "documents.db")

    init_database(DB_PATH, flag)

    server = ThreadedHTTPServer((args.host, args.port), SearchPortalHandler)
    print(f"[+] Query Under Pressure service listening on http://{args.host}:{args.port}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[*] Shutting down server.")
        server.server_close()


if __name__ == "__main__":
    main()
