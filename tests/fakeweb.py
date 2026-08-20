#!/usr/bin/env python3
"""A tiny web server standing in for a log archive and an image host.

Serves what the two import doors and the image quick-look actually meet in
the wild: a directory listing of log files, the log files themselves in
several client formats, a real PNG, and a few things that are not logs or not
pictures, so the refusals can be tested as well as the happy path.

    python3 tests/fakeweb.py --port 8900
"""

import argparse
import struct
import threading
import zlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse

EXPORT_LOG = """--- Logs for 2026-08-17 (#mychannel) ---
2026-08-17 09:15 <alice> morning all
2026-08-17 09:16 <bob> alice: morning
2026-08-17 09:16 <bob> did the firmware land?
2026-08-17 09:17 * carol waves
2026-08-17 09:18 alice changed the topic of #mychannel to: release day
2026-08-17 09:19 dave has joined
2026-08-17 09:20 <alice> yes, tagged an hour ago
2026-08-17 09:21 dave has quit (Ping timeout)
"""

ZNC_LOG = """[10:05:01] <alice> back from lunch
[10:05:30] * bob stretches
[10:06:00] *** joins: newcomer (~n@example)
[10:06:20] <newcomer> hello everyone
"""

WEECHAT_LOG = (
    "2026-08-19 11:00:00\talice\tweechat line one\n"
    "2026-08-19 11:00:30\tbob\tweechat line two\n"
    "2026-08-19 11:01:00\t-->\tsomeone (~s@x) has joined #mychannel\n"
)

NOT_A_LOG = "just some prose about nothing in particular\nand a second line\n"

INDEX = """<!doctype html><html><head><title>Logs</title></head><body>
<h1>Index of /logs</h1>
<ul>
  <li><a href="mychannel-chat.txt">mychannel-chat.txt</a></li>
  <li><a href="mychannel_20260818.log">mychannel_20260818.log</a></li>
  <li><a href="notes.html">notes.html</a></li>
  <li><a href="../secret.txt">../secret.txt</a></li>
  <li><a href="https://elsewhere.invalid/other.txt">off-site</a></li>
</ul></body></html>
"""


def tiny_png(width=8, height=8, rgb=(90, 140, 240), gradient=False):
    """A real PNG, built here so the tests need no binary fixture."""
    raw = b""
    for y in range(height):
        if gradient:
            row = b""
            for x in range(width):
                clamp = lambda v: max(0, min(255, v))
                row += bytes((
                    clamp(rgb[0] + (x * 90) // max(1, width)),
                    clamp(rgb[1] + (y * 70) // max(1, height)),
                    clamp(rgb[2] - (x * 60) // max(1, width)),
                ))
            raw += b"\x00" + row
            continue
        raw += b"\x00" + bytes(rgb) * width
    def chunk(tag, data):
        body = tag + data
        return struct.pack(">I", len(data)) + body + \
            struct.pack(">I", zlib.crc32(body) & 0xFFFFFFFF)
    return (b"\x89PNG\r\n\x1a\n"
            + chunk(b"IHDR", struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0))
            + chunk(b"IDAT", zlib.compress(raw))
            + chunk(b"IEND", b""))


ROUTES = {
    "/logs/": ("text/html; charset=utf-8", INDEX),
    "/logs/index.html": ("text/html; charset=utf-8", INDEX),
    "/logs/mychannel-chat.txt": ("text/plain; charset=utf-8", EXPORT_LOG),
    "/logs/mychannel_20260818.log": ("text/plain; charset=utf-8", ZNC_LOG),
    "/logs/notes.html": ("text/html; charset=utf-8", "<html><body>notes</body></html>"),
    "/secret.txt": ("text/plain; charset=utf-8", "this must never be pulled in\n"),
    "/weechat/#mychannel.weechatlog": ("text/plain; charset=utf-8", WEECHAT_LOG),
    "/plain/notalog.txt": ("text/plain; charset=utf-8", NOT_A_LOG),
}


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _send(self, code, ctype, body):
        if isinstance(body, str):
            body = body.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        try:
            self.wfile.write(body)
        except OSError:
            pass

    def do_GET(self):
        path = urlparse(self.path).path
        if path in ("/img/shot.png", "/img/shot.png?"):
            return self._send(200, "image/png",
                              tiny_png(1280, 800, (40, 70, 150), gradient=True))
        if path == "/img/wide.png":
            return self._send(200, "image/png",
                              tiny_png(1600, 400, (150, 60, 40), gradient=True))
        if path == "/img/small.png":
            return self._send(200, "image/png", tiny_png(8, 8))
        if path == "/img/notreally.txt":
            return self._send(200, "text/plain", "not a picture")
        if path == "/img/missing.png":
            return self._send(404, "text/plain", "gone")
        if path == "/redirect":
            self.send_response(302)
            self.send_header("Location", "/logs/mychannel-chat.txt")
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        if path in ROUTES:
            ctype, body = ROUTES[path]
            return self._send(200, ctype, body)
        self._send(404, "text/plain", "not here")


class FakeWeb:
    def __init__(self, host="127.0.0.1", port=0):
        self.httpd = ThreadingHTTPServer((host, port), Handler)
        self.port = self.httpd.server_address[1]
        self.base = f"http://{host}:{self.port}"

    def start(self):
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()
        return self

    def stop(self):
        self.httpd.shutdown()


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--port", type=int, default=8900)
    a = ap.parse_args()
    web = FakeWeb(port=a.port).start()
    print(f"fake web on {web.base}  (try {web.base}/logs/ and {web.base}/img/shot.png)")
    try:
        threading.Event().wait()
    except KeyboardInterrupt:
        web.stop()


if __name__ == "__main__":
    main()
