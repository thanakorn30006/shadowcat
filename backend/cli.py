#!/usr/bin/env python3
"""SHADOW CAT — Command-Line Interface (CLI) Entry Point.

Invoked via terminal command:
    $ shadowcat
    $ shadowcat --port 8080 --no-browser
"""

from __future__ import annotations

import argparse
import sys
import threading
import time
import webbrowser
from pathlib import Path

import uvicorn

def _open_browser(url: str, delay: float = 1.2) -> None:
    def _worker():
        time.sleep(delay)
        webbrowser.open(url)
    
    t = threading.Thread(target=_worker, daemon=True)
    t.start()

def main() -> None:
    parser = argparse.ArgumentParser(
        prog="shadowcat",
        description="[+] SHADOW CAT — Autonomous Cyber Operations & Tactical CTF Suite",
    )
    parser.add_argument(
        "--host",
        type=str,
        default="127.0.0.1",
        help="Host address to bind (default: 127.0.0.1 — loopback only)",
    )
    parser.add_argument(
        "--lan",
        action="store_true",
        help="Expose on the local network (binds 0.0.0.0). WARNING: the API has no "
             "authentication — only use on a trusted network.",
    )
    parser.add_argument(
        "-p", "--port",
        type=int,
        default=8000,
        help="Port to listen on (default: 8000)",
    )
    parser.add_argument(
        "--no-browser",
        action="store_true",
        help="Do not automatically launch web browser on startup",
    )
    parser.add_argument(
        "--reload",
        action="store_true",
        help="Enable auto-reload for developers",
    )

    args = parser.parse_args()

    # Secure by default: bind loopback unless --lan is explicitly passed.
    host = "0.0.0.0" if args.lan else args.host

    # Ensure backend directory is in sys.path
    backend_dir = Path(__file__).resolve().parent
    if str(backend_dir) not in sys.path:
        sys.path.insert(0, str(backend_dir))

    url = f"http://localhost:{args.port}"

    print("==========================================================")
    print("[+] SHADOW CAT — Autonomous Cyber Operations Suite")
    print(f"[*] Binding to: {host}:{args.port}")
    print(f"[*] Web Interface: {url}")
    print(f"[*] API Docs:      {url}/docs")
    if host == "0.0.0.0":
        print("[!] WARNING: bound to 0.0.0.0 — the suite is reachable from the local")
        print("[!] network and the API has NO authentication. Use only on a trusted LAN.")
    print("==========================================================")

    if not args.no_browser:
        _open_browser(url)

    uvicorn.run(
        "main:app",
        host=host,
        port=args.port,
        reload=args.reload,
        app_dir=str(backend_dir),
    )

if __name__ == "__main__":
    main()
