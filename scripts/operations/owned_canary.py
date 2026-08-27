#!/usr/bin/env python3
"""Minimal localhost-only HTTP canary for production egress verification."""

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


class Handler(BaseHTTPRequestHandler):
    server_version = "LeakyCompute-Owned-Canary/1.0"

    def do_GET(self):  # noqa: N802 - BaseHTTPRequestHandler API
        if self.path != "/leakycompute-owned-canary":
            self.send_error(404)
            return
        body = b'{"leakycompute_canary":"owned"}\n'
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, fmt, *args):
        print("owned-canary:", fmt % args, flush=True)


if __name__ == "__main__":
    ThreadingHTTPServer(("127.0.0.1", 18788), Handler).serve_forever()
