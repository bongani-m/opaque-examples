"""Code D (server): a tiny OPAQUE server on the standard library.

Four endpoints, raw bytes in and out; the user name goes in the query string.
Records live in a dict, so they vanish on restart. A teaching server: no TLS,
no rate limiting, no fake records for unknown users (see the post's
"footguns" section for why a real one needs all three).

    python server.py [port]
"""
import secrets
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

import opaque

CONTEXT = b"opaque-examples-v1"
SERVER_ID = "example.com"

records: dict[str, bytes] = {}       # user -> OPAQUE record
pending_reg: dict[str, bytes] = {}   # user -> server registration secret
pending_login: dict[str, tuple[str, bytes, bytes]] = {}  # session -> (user, expected KE3, session key)


class Handler(BaseHTTPRequestHandler):
    def do_POST(self) -> None:
        url = urlparse(self.path)
        q = parse_qs(url.query)
        user = q.get("user", [""])[0]
        body = self.rfile.read(int(self.headers.get("Content-Length", 0)))
        try:
            status, out = self.route(url.path, user, q, body)
        except (ValueError, KeyError):
            status, out = 401, b"authentication failed"
        self.send_response(status)
        self.send_header("Content-Length", str(len(out)))
        self.end_headers()
        self.wfile.write(out)

    def route(self, path: str, user: str, q: dict, body: bytes) -> tuple[int, bytes]:
        ids = opaque.Ids(user, SERVER_ID)
        if path == "/register/start":
            sec, response = opaque.CreateRegistrationResponse(body)
            pending_reg[user] = sec
            return 200, response
        if path == "/register/finish":
            records[user] = opaque.StoreUserRecord(pending_reg.pop(user), body)
            return 200, b"registered"
        if path == "/login/start":
            ke2, session_key, expected_ke3 = opaque.CreateCredentialResponse(
                body, records[user], ids, CONTEXT)
            session = secrets.token_hex(16)
            pending_login[session] = (user, expected_ke3, session_key)
            return 200, session.encode() + b"\n" + ke2
        if path == "/login/finish":
            user, expected_ke3, session_key = pending_login.pop(q["session"][0])
            opaque.UserAuth(expected_ke3, body)  # raises ValueError on a bad MAC
            print(f"{user} authenticated, session key {session_key[:8].hex()}...", flush=True)
            return 200, b"user authenticated"
        return 404, b"not found"

    def log_message(self, *args) -> None:
        pass


if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8765
    print(f"listening on 127.0.0.1:{port}", flush=True)
    ThreadingHTTPServer(("127.0.0.1", port), Handler).serve_forever()
