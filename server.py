#!/usr/bin/env python3
"""Minimalistický server: statické súbory + /api/rules (obsah RULES_FILE)."""
import os, time, pathlib
from http.server import ThreadingHTTPServer, SimpleHTTPRequestHandler

CANDIDATES = ["/data/iptables.rules", "/data/nftables.rules", "/data/nft.rules", "/data/ruleset.nft"]


def rules_path():
    """RULES_FILE z prostredia, inak prvý existujúci súbor z CANDIDATES."""
    env = os.environ.get("RULES_FILE")
    if env:
        return env
    for p in CANDIDATES:
        if os.path.exists(p):
            return p
    return CANDIDATES[0]
STATIC = pathlib.Path(__file__).parent / "static"
PORT = int(os.environ.get("PORT", "8080"))


class Handler(SimpleHTTPRequestHandler):
    def __init__(self, *a, **k):
        super().__init__(*a, directory=str(STATIC), **k)

    def do_GET(self):
        if self.path.split("?")[0] == "/api/rules":
            try:
                path = rules_path()
                data = open(path, "rb").read()
                mtime = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(os.path.getmtime(path)))
            except OSError:
                self.send_error(404, "rules file not found")
                return
            self.send_response(200)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Rules-File", os.path.basename(path))
            self.send_header("X-Rules-Mtime", mtime)
            self.end_headers()
            self.wfile.write(data)
            return
        super().do_GET()

    def end_headers(self):
        self.send_header("Cache-Control", "no-store")
        super().end_headers()


if __name__ == "__main__":
    print(f"listening on :{PORT}, rules file: {rules_path()}")
    ThreadingHTTPServer(("0.0.0.0", PORT), Handler).serve_forever()
