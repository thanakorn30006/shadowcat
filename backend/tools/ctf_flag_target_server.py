#!/usr/bin/env python3
"""
SHADOW CAT — Mock CTF Flag Target Server
Simulates an intentionally vulnerable Web & Netcat challenge environment
designed specifically to test ShadowSolve's Web Hunt, Burp Repeater, WAF Detector,
Vulnerability Scanner, JS Hunter, and Netcat Auto-Solver.

Port 8888: Web Target (HTML, HTTP Headers, LFI, SSTI, SQLi, .env, robots.txt, JS assets)
Port 9999: Netcat TCP Target (Interactive arithmetic challenge)
"""

import sys
import threading
import socket
import urllib.parse
from http.server import HTTPServer, BaseHTTPRequestHandler

WEB_PORT = 8888
NC_PORT = 9999

# Flags Dictionary
FLAGS = {
    "web_html": "flag{web_hunt_html_comment_unlocked_9921}",
    "web_header": "flag{burp_repeater_header_exfiltration_7712}",
    "robots": "flag{robots_recon_scout_8819}",
    "hidden_path": "flag{hidden_endpoint_crawler_success_3341}",
    "dotenv": "flag{exposed_dotenv_credential_leaked_5521}",
    "git": "flag{git_head_repository_source_dump_2209}",
    "lfi": "flag{lfi_directory_traversal_mastery_6631}",
    "ssti": "flag{ssti_template_injection_rce_9982}",
    "sqli": "flag{sqli_error_fingerprint_bypass_4410}",
    "js_token": "flag{js_hunter_token_leak_8820}",
    "netcat": "flag{netcat_socket_ai_math_solver_1109}"
}

class CTFWebHandler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        # Clean logging
        sys.stdout.write(f"[*] Web Target Request: {self.command} {self.path}\n")

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path
        query = urllib.parse.parse_qs(parsed.query)

        # 1. Exposed .env
        if path == "/.env":
            content = f"""# Production Configuration
DB_HOST=127.0.0.1
DB_PORT=5432
DB_USER=admin_operator
DB_PASSWORD=SuperSecretOperatorPass123!
DATABASE_URL=postgres://admin_operator:SuperSecret@127.0.0.1:5432/cyber_db
SECRET_KEY=e4d9c7f21a8b301c9842f1a6
FLAG={FLAGS['dotenv']}
"""
            self._send_response_data(200, content, "text/plain")
            return

        # 2. Exposed .git/HEAD
        if path == "/.git/HEAD":
            content = f"ref: refs/heads/main\n# Commits archive: {FLAGS['git']}\n"
            self._send_response_data(200, content, "text/plain")
            return

        # 3. Robots.txt
        if path == "/robots.txt":
            content = f"""User-agent: *
Disallow: /super-secret-vault-api/
# Flag for curious crawlers: {FLAGS['robots']}
"""
            self._send_response_data(200, content, "text/plain")
            return

        # 4. Hidden Vault Endpoint
        if path.startswith("/super-secret-vault-api"):
            content = f"""<html><body>
<h1>Restricted Vault Access Granted</h1>
<p>Authorized Operator Token Verified.</p>
<code>{FLAGS['hidden_path']}</code>
</body></html>"""
            self._send_response_data(200, content, "text/html")
            return

        # 5. JavaScript Asset for JS Hunter
        if path == "/static/app.js" or path == "/app.js":
            content = f"""// Tactical Frontend Client Asset
const API_BASE = "/api/v2/internal/flag";
const TARGET_ROUTE = "/super-secret-vault-api/data";
const AUTH_TOKEN = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.payload.sig";
const LEAKED_FLAG = "{FLAGS['js_token']}";

function fetchTelemetry() {{
    fetch(API_BASE, {{
        headers: {{ "Authorization": "Bearer " + AUTH_TOKEN }}
    }}).then(res => res.json());
}}
"""
            self._send_response_data(200, content, "application/javascript")
            return

        # 6. LFI Probe Check (file, page, path query params)
        file_param = query.get("file", [""])[0] or query.get("page", [""])[0] or query.get("path", [""])[0]
        if "passwd" in file_param:
            content = f"""root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
operator:x:1000:1000:Operator,,,:/home/operator:/bin/bash
shadowcat:x:1337:1337:CTF Challenge Holder:/var/ctf:/bin/sh
# Traversal Evidence Flag: {FLAGS['lfi']}
"""
            self._send_response_data(200, content, "text/plain")
            return

        # 7. SSTI Probe Check (name, q query params)
        name_param = query.get("name", [""])[0] or query.get("q", [""])[0]
        if "{{7777*7}}" in name_param or "7777*7" in name_param:
            content = f"""<html><body>
<h2>Welcome Operator, search result for: 54439</h2>
<p>SSTI Evaluated Successfully!</p>
<div>Flag: {FLAGS['ssti']}</div>
</body></html>"""
            self._send_response_data(200, content, "text/html")
            return

        # 8. SQLi Error Probe Check (id query param)
        id_param = query.get("id", [""])[0]
        if "'" in id_param or "OR" in id_param.upper():
            content = f"""<html><body>
<h1>Database Error</h1>
<p style="color:red;">Error: you have an error in your sql syntax near '{id_param}' at line 1</p>
<!-- Database Fingerprint Flag: {FLAGS['sqli']} -->
</body></html>"""
            self._send_response_data(200, content, "text/html")
            return

        # 9. Default Index Page
        content = f"""<!DOCTYPE html>
<html>
<head>
    <title>Cyber CTF Mock Target — Vulnerable Portal</title>
    <script src="/static/app.js"></script>
</head>
<body style="font-family: monospace; background: #0b0f19; color: #10b981; padding: 40px;">
    <h1>[+] SHADOW CAT TARGET PRACTICE LAB</h1>
    <p>Target Portal running on port {WEB_PORT}.</p>
    <p>Explore this target using ShadowSolve Web Hunt, Burp Repeater, and Active Scanner.</p>

    <!-- CTF CHALLENGE HINT: Hidden HTML Source Comment -->
    <!-- Flag: {FLAGS['web_html']} -->

    <ul>
        <li><a href="/robots.txt" style="color: #38bdf8;">/robots.txt (Crawler direct)</a></li>
        <li><a href="/static/app.js" style="color: #38bdf8;">/static/app.js (JavaScript client asset)</a></li>
        <li><a href="/.env" style="color: #38bdf8;">/.env (Configuration file)</a></li>
        <li><a href="/?file=/etc/passwd" style="color: #38bdf8;">/?file=/etc/passwd (LFI Parameter)</a></li>
        <li><a href="/?name=John" style="color: #38bdf8;">/?name=John (Template Expression)</a></li>
        <li><a href="/?id=1" style="color: #38bdf8;">/?id=1 (Database Query)</a></li>
    </ul>
</body>
</html>"""
        self._send_response_data(200, content, "text/html")

    def do_POST(self):
        # Repeater echo response
        content_len = int(self.headers.get('Content-Length', 0))
        body = self.rfile.read(content_len).decode('utf-8', errors='ignore') if content_len > 0 else ""
        resp = f"""[REPEATER TARGET ACKNOWLEDGED]
Received POST request on {self.path}
Payload Length: {len(body)} bytes
Payload Content: {body}

Header Verification Flag: {FLAGS['web_header']}
"""
        self._send_response_data(200, resp, "text/plain")

    def _send_response_data(self, status_code, content, content_type):
        self.send_response(status_code)
        self.send_header("Content-Type", f"{content_type}; charset=utf-8")
        # Hidden flag in response header
        self.send_header("X-Flag-Vault", FLAGS["web_header"])
        self.send_header("X-Powered-By", "PHP/7.4.33-vulnerable-ctf")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(content.encode("utf-8"))

def run_netcat_server():
    """Runs Netcat challenge on TCP port 9999."""
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        server.bind(("127.0.0.1", NC_PORT))
        server.listen(5)
        print(f"[*] Netcat Target Lab listening on 127.0.0.1:{NC_PORT}")
        while True:
            client, addr = server.accept()
            try:
                client.settimeout(10)
                client.sendall(b"=== CTF MATH CHALLENGE ===\nSolve: 42 + 58\nAnswer: ")
                data = client.recv(1024).decode('utf-8', errors='ignore').strip()
                if data == "100":
                    client.sendall(f"\n[CORRECT] Access Granted! Flag: {FLAGS['netcat']}\n".encode('utf-8'))
                else:
                    client.sendall(f"\n[INCORRECT] Received '{data}', expected '100'. Try again.\n".encode('utf-8'))
            except Exception:
                pass
            finally:
                client.close()
    except Exception as e:
        print(f"[!] Netcat Server Error: {e}")

if __name__ == "__main__":
    print("=" * 60)
    print("[+] LAUNCHING SHADOW CAT CTF TARGET PRACTICE SERVERS")
    print("=" * 60)
    print(f"[*] Web Target Port:    http://127.0.0.1:{WEB_PORT}")
    print(f"[*] Netcat Target Port: 127.0.0.1:{NC_PORT}")
    print("=" * 60)
    print("Available Flags inside this Target Lab:")
    for key, val in FLAGS.items():
        print(f"   [{key:12s}] -> {val}")
    print("=" * 60)

    # Start Netcat daemon thread
    nc_thread = threading.Thread(target=run_netcat_server, daemon=True)
    nc_thread.start()

    # Start Web Server
    web_server = HTTPServer(("127.0.0.1", WEB_PORT), CTFWebHandler)
    print(f"[*] Web Server running. Press Ctrl+C to terminate.")
    try:
        web_server.serve_forever()
    except KeyboardInterrupt:
        print("\n[*] Shutting down target lab.")
        web_server.server_close()
