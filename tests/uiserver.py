#!/usr/bin/env python3
"""Start the whole stack against a fake network, then run the browser test.

Brings up tests/fakeircd.py, `archive.py serve`, `archive.py live` and a small
control endpoint the browser test pokes to make other people talk in the
channel. Then runs tests/ui.mjs against it and passes its exit code on.

    python3 tests/uiserver.py            # run the browser test
    python3 tests/uiserver.py --hold     # leave it running to poke at by hand
"""

import argparse
import json
import os
import subprocess
import sys
import tempfile
import threading
import time
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse, parse_qs

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))

from fakeircd import FakeIRCd                                  # noqa: E402


def control_server(ircd, port=0):
    """Lets the browser test make the network do things."""

    class H(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_GET(self):
            u = urlparse(self.path)
            q = {k: v[0] for k, v in parse_qs(u.query).items()}
            out = {"ok": True}
            try:
                if u.path == "/inject":
                    ircd.inject(q.get("nick", "someone"),
                                q.get("chan", "#mychannel"),
                                q.get("text", "hello"), q.get("kind", "msg"))
                elif u.path == "/join":
                    ircd.inject_join(q.get("nick", "someone"),
                                     q.get("chan", "#mychannel"))
                elif u.path == "/quit":
                    ircd.inject_quit(q.get("nick", "someone"),
                                     q.get("why", "Ping timeout"))
                elif u.path == "/seen":
                    out["seen"] = [{"nick": n, "target": t, "text": x}
                                   for n, t, x, _ in ircd.seen]
                elif u.path == "/port":
                    out["port"] = ircd.port
                else:
                    out = {"ok": False, "error": "unknown"}
            except Exception as exc:
                out = {"ok": False, "error": str(exc)}
            body = json.dumps(out).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    httpd = ThreadingHTTPServer(("127.0.0.1", port), H)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    return httpd


def drain(proc, sink):
    for raw in iter(proc.stdout.readline, b""):
        sink.append(raw.decode("utf-8", "replace").rstrip())


def wait_for(fn, timeout=30, step=0.25):
    end = time.time() + timeout
    while time.time() < end:
        try:
            if fn():
                return True
        except Exception:
            pass
        time.sleep(step)
    return False


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--hold", action="store_true",
                    help="leave the stack running instead of testing")
    ap.add_argument("--shots", action="store_true",
                    help="capture screenshots instead of testing")
    ap.add_argument("--port", type=int, default=8766)
    ap.add_argument("--db", default="")
    a = ap.parse_args()

    tmp = Path(a.db or tempfile.mkdtemp(prefix="aurora-ui-"))
    dbpath = tmp if a.db else tmp / "archive.db"
    base = f"http://127.0.0.1:{a.port}"

    ircd = FakeIRCd(port=0).start()
    ctrl = control_server(ircd)
    ctrl_url = f"http://127.0.0.1:{ctrl.server_address[1]}"

    env = {**os.environ, "PYTHONUNBUFFERED": "1"}
    logs = {"serve": [], "live": []}
    serve = subprocess.Popen(
        [sys.executable, str(ROOT / "archive.py"), "--db", str(dbpath),
         "serve", "--host", "127.0.0.1", "--port", str(a.port)],
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, env=env)
    threading.Thread(target=drain, args=(serve, logs["serve"]), daemon=True).start()
    live = subprocess.Popen(
        [sys.executable, str(ROOT / "archive.py"), "--db", str(dbpath), "live"],
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, env=env)
    threading.Thread(target=drain, args=(live, logs["live"]), daemon=True).start()

    up = wait_for(lambda: urllib.request.urlopen(base + "/api/meta", timeout=3).status == 200)
    print(f"serve   {base}")
    print(f"ircd    127.0.0.1:{ircd.port}")
    print(f"control {ctrl_url}")
    print(f"db      {dbpath}")
    if not up:
        print("server did not come up:", "\n".join(logs["serve"]))
        return 1

    rc = 0
    try:
        if a.hold:
            print("\nHolding. Ctrl+C to stop.")
            while True:
                time.sleep(1)
        else:
            env2 = {**env, "NODE_PATH": subprocess.run(
                ["npm", "root", "-g"], capture_output=True, text=True).stdout.strip()}
            script = "shots.mjs" if a.shots else "ui.mjs"
            rc = subprocess.call(
                ["node", str(ROOT / "tests" / script), base, ctrl_url,
                 str(ircd.port)], env=env2)
    except KeyboardInterrupt:
        pass
    finally:
        for proc in (live, serve):
            proc.terminate()
            try:
                proc.wait(timeout=8)
            except subprocess.TimeoutExpired:
                proc.kill()
        ircd.stop()
        ctrl.shutdown()
    if rc:
        print("\nlive log tail:")
        for l in logs["live"][-20:]:
            print("   ", l)
    return rc


if __name__ == "__main__":
    sys.exit(main())
