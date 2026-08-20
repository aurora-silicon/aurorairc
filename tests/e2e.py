#!/usr/bin/env python3
"""End-to-end dry run: a real server, a real archivist, an emulated network.

Walks the whole pipeline the way the browser does - setup wizard, invites and
passes, sign-in with two-factor, search history, saved searches, channel
administration, live capture and sending - against tests/fakeircd.py rather
than a real IRC network. Nothing here touches the outside world.

    python3 tests/e2e.py
"""

import http.cookiejar
import json
import os
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))

from fakeircd import FakeIRCd                                  # noqa: E402
from ircarchive import auth as A, db                           # noqa: E402

PASS = "\033[32m✓\033[0m"
FAIL = "\033[31m✗\033[0m"

failures = []
checks = 0


def check(label, ok, detail=""):
    global checks
    checks += 1
    print(f"  {PASS if ok else FAIL} {label}" + (f"  — {detail}" if detail and not ok else ""))
    if not ok:
        failures.append(label + (f" ({detail})" if detail else ""))
    return ok


def head(title):
    print(f"\n\033[1m{title}\033[0m")


class Client:
    """The browser: a cookie jar, a CSRF token, and JSON in both directions."""

    def __init__(self, base):
        self.base = base
        self.jar = http.cookiejar.CookieJar()
        self.opener = urllib.request.build_opener(
            urllib.request.HTTPCookieProcessor(self.jar))
        self.csrf = ""

    def get(self, path, **params):
        url = self.base + path
        if params:
            from urllib.parse import urlencode
            url += "?" + urlencode(params, doseq=True)
        req = urllib.request.Request(url)
        try:
            with self.opener.open(req, timeout=30) as r:
                return json.loads(r.read().decode())
        except urllib.error.HTTPError as e:
            return json.loads(e.read().decode() or "{}")

    def post(self, path, body=None, headers=None):
        data = json.dumps(body or {}).encode()
        req = urllib.request.Request(self.base + path, data=data, method="POST")
        req.add_header("Content-Type", "application/json")
        if self.csrf:
            req.add_header("X-CSRF", self.csrf)
        for k, v in (headers or {}).items():
            req.add_header(k, v)
        try:
            with self.opener.open(req, timeout=40) as r:
                out = json.loads(r.read().decode())
        except urllib.error.HTTPError as e:
            out = json.loads(e.read().decode() or "{}")
        if isinstance(out, dict) and out.get("csrf"):
            self.csrf = out["csrf"]
        return out


def wait_for(fn, timeout=25, step=0.25, what="condition"):
    end = time.time() + timeout
    while time.time() < end:
        try:
            v = fn()
        except Exception:
            v = None
        if v:
            return v
        time.sleep(step)
    return None


def drain(proc, name, sink):
    for raw in iter(proc.stdout.readline, b""):
        sink.append(raw.decode("utf-8", "replace").rstrip())
    return


def main():
    tmp = Path(tempfile.mkdtemp(prefix="aurora-e2e-"))
    dbpath = tmp / "archive.db"
    port = 8765
    base = f"http://127.0.0.1:{port}"

    ircd = FakeIRCd(port=0).start()
    print(f"fake ircd on 127.0.0.1:{ircd.port}, db at {dbpath}")

    env = {**os.environ, "PYTHONUNBUFFERED": "1"}
    serve = subprocess.Popen(
        [sys.executable, str(ROOT / "archive.py"), "--db", str(dbpath),
         "serve", "--host", "127.0.0.1", "--port", str(port)],
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, env=env)
    serve_log = []
    threading.Thread(target=drain, args=(serve, "serve", serve_log), daemon=True).start()

    live = None
    live_log = []
    c = Client(base)

    try:
        if not wait_for(lambda: c.get("/api/meta").get("channels") is not None,
                        what="server"):
            print("server never came up:", "\n".join(serve_log))
            return 1

        # ---------------------------------------------------------- static
        head("The page itself")
        with urllib.request.urlopen(base + "/", timeout=10) as r:
            page = r.read().decode()
        check("index.html is served", "<title>AuroraIRC</title>" in page)
        for needed in ("id=\"wizard\"", "id=\"setpanel\"", "id=\"tip\"",
                       "id=\"qsave\"", "id=\"look-controls\"", "id=\"show-events\""):
            check(f"page carries {needed}", needed in page)

        # ----------------------------------------------------------- setup
        head("Setup wizard")
        s = c.get("/api/session")
        check("a fresh archive needs setup", s.get("setupNeeded") is True)

        r = c.post("/api/setup", {"username": "ry", "password": "short",
                                  "appName": "Aurora Test"})
        check("a short password is refused", "error" in r, str(r))

        r = c.post("/api/setup", {"username": "ryan", "password": "correct horse 9",
                                  "nick": "ryan_", "appName": "Aurora Test"})
        check("owner account is created", r.get("signedIn") is True, str(r))
        check("session carries a CSRF token", bool(c.csrf))
        check("the wizard's server name is applied",
              c.get("/api/meta").get("appName") == "Aurora Test")

        r = c.post("/api/setup", {"username": "second", "password": "correct horse 9"})
        check("setup closes after the first run", "error" in r)

        # ------------------------------------------------------- 2fa + keys
        head("Second factor, enrolled from the setup flow")
        beg = c.post("/api/me/totp", {"action": "begin"})
        secret = beg.get("secret")
        check("a TOTP secret is issued", bool(secret))
        bad = c.post("/api/me/totp", {"action": "confirm", "code": "000000"})
        check("a wrong code is refused", "error" in bad)
        good = c.post("/api/me/totp",
                      {"action": "confirm", "code": A.totp_codes(secret)[1]})
        check("the right code turns it on", good.get("enabled") is True, str(good))

        # ------------------------------------------------------ network test
        head("IRC network setup, verified before it is saved")
        bad = c.post("/api/networks/test",
                     {"host": "127.0.0.1", "port": 1, "tls": False, "timeout": 4})
        check("an unreachable host reports a failure", bad.get("ok") is False)
        ok = c.post("/api/networks/test", {"host": "127.0.0.1", "port": ircd.port,
                                           "tls": False, "nick": "aurora",
                                           "timeout": 8})
        check("a live host registers and reports back", ok.get("ok") is True, str(ok))

        net = c.post("/api/networks", {"name": "test", "host": "127.0.0.1",
                                       "port": ircd.port, "tls": False,
                                       "nick": "aurora"})
        check("the network is created", bool(net.get("id")), str(net))
        nid = net["id"]
        for chan in ("mychannel", "another"):
            r = c.post("/api/networks/channels", {"network_id": nid, "channel": chan})
            check(f"#{chan} is added", chan in (r.get("channels") or []), str(r))

        # ---------------------------------------------------------- invites
        head("Invites and passes")
        r = c.post("/api/invites", {"role": "member", "uses": 3, "label": "launch crew"})
        token = r.get("token")
        check("a pass for three is minted", r.get("uses") == 3 and bool(token), str(r))
        check("the invite carries no username field", "username" not in r)

        single = c.post("/api/invites", {"role": "member"}).get("token")
        check("a single invite is minted too", bool(single))

        bad = c.post("/api/invites", {"role": "member", "uses": 9999})
        check("an absurd pass size is refused", "error" in bad)

        joiner = Client(base)
        r = joiner.post("/api/redeem", {"token": token, "username": "alice",
                                        "password": "another good one"})
        check("alice joins on the pass", r.get("signedIn") is True, str(r))
        bob = Client(base)
        r = bob.post("/api/redeem", {"token": token, "username": "bob",
                                     "password": "another good one"})
        check("bob joins on the same pass", r.get("signedIn") is True, str(r))

        invs = c.get("/api/invites")["invites"]
        pas = next(i for i in invs if i["token"] == token)
        check("the pass counts two uses", pas["uses"] == 2, str(pas["uses"]))
        check("it names who joined",
              [j["name"] for j in pas["joiners"]] == ["alice", "bob"], str(pas["joiners"]))
        check("it is still live with one seat left", pas["live"] and pas["maxUses"] == 3)

        d = c.get("/api/users/detail", username="alice")
        check("alice's provenance names the inviter", d.get("invitedBy") == "ryan", str(d))
        check("and the link she came in on", (d.get("invite") or {}).get("isPass") is True)
        check("and when she joined", bool(d.get("joinedAt")))
        d = c.get("/api/users/detail", username="ryan")
        check("the founder is marked as such", d.get("joinMethod") == "setup", str(d))
        check("and is root", d.get("root") is True)

        r = c.post("/api/invites/revoke", {"token": token})
        check("the pass can be revoked", "error" not in r, str(r))
        carol = Client(base)
        r = carol.post("/api/redeem", {"token": token, "username": "carol",
                                       "password": "another good one"})
        check("a revoked pass refuses the next joiner", "error" in r, str(r))
        d = c.get("/api/users/detail", username="alice")
        check("revoking does not orphan who already joined",
              d.get("invitedBy") == "ryan")

        r = c.post("/api/users/create", {"username": "dave",
                                         "password": "another good one",
                                         "role": "member"})
        check("an account can be created directly", bool(r.get("id")), str(r))
        d = c.get("/api/users/detail", username="dave")
        check("and is recorded as created by hand", d.get("joinMethod") == "manual")

        # --------------------------------------------------------- sign-in
        head("Sign-in with a second factor")
        again = Client(base)
        r = again.post("/api/login", {"username": "ryan", "password": "correct horse 9"})
        check("the password alone asks for a code", r.get("totpRequired") is True, str(r))
        check("and does not sign anyone in", not r.get("signedIn"))
        r = again.post("/api/login", {"username": "ryan", "password": "correct horse 9",
                                      "totp": "000000"})
        check("a wrong code is refused", "error" in r and not r.get("totpRequired"))
        r = again.post("/api/login", {"username": "ryan", "password": "correct horse 9",
                                      "totp": A.totp_codes(secret)[1]})
        check("the right code signs in", r.get("signedIn") is True, str(r))
        check("the role comes back", (r.get("user") or {}).get("role") == "owner")

        # ---------------------------------------------- history and searches
        head("Search history and saved searches")
        anon = Client(base)
        check("anonymous history is empty", anon.get("/api/history")["history"] == [])
        r = anon.post("/api/history", {"action": "record", "query": "nope"})
        check("anonymous cannot write history", "error" in r)

        for q in ("#mychannel hello", "@alice", "#mychannel hello"):
            r = c.post("/api/history", {"action": "record", "query": q})
        hist = [h["query"] for h in c.get("/api/history")["history"]]
        check("history keeps one row per query", hist.count("#mychannel hello") == 1, str(hist))
        check("newest first", hist[0] == "#mychannel hello", str(hist))
        r = c.post("/api/history", {"action": "clear", "query": "@alice"})
        check("one entry can be forgotten",
              "@alice" not in [h["query"] for h in r["history"]])
        r = c.post("/api/history", {"action": "clear"})
        check("and the lot", r["history"] == [])

        r = c.post("/api/searches", {"name": "Release chatter",
                                     "query": "#mychannel release",
                                     "extra": {"order": "asc", "kinds": []}})
        check("a search can be saved from the bar",
              any(x["name"] == "Release chatter" for x in r["searches"]), str(r))

        # ------------------------------------------------------------ live
        head("Live capture")
        live = subprocess.Popen(
            [sys.executable, str(ROOT / "archive.py"), "--db", str(dbpath), "live"],
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, env=env)
        threading.Thread(target=drain, args=(live, "live", live_log), daemon=True).start()

        st = wait_for(lambda: c.get("/api/session")["live"]["connected"], timeout=30,
                      what="archivist")
        check("the archivist connects and reports in", bool(st),
              "\n".join(live_log[-12:]))
        chans = c.get("/api/session")["live"]["channels"]
        check("it has joined both channels",
              sorted(chans) == ["#another", "#mychannel"], str(chans))
        check("the fake network saw the joins",
              len(ircd._members("#mychannel")) >= 1)

        ircd.inject("someone", "#mychannel", "first line from the network")
        ircd.inject("someone", "#mychannel", "and a second")
        ircd.inject("otherperson", "#mychannel", "waves", kind="action")
        ircd.inject("someone", "#mychannel", "New topic here", kind="topic")
        ircd.inject_join("newcomer", "#mychannel")
        ircd.inject_quit("newcomer", "Ping timeout")

        got = wait_for(lambda: c.get("/api/messages", channel="mychannel",
                                     limit=50)["total"] >= 4, timeout=20)
        msgs = c.get("/api/messages", channel="mychannel", limit=50)
        check("messages are recorded", got and msgs["total"] >= 4, str(msgs["total"]))
        texts = [m["text"] for m in msgs["messages"]]
        check("plain messages land", "first line from the network" in texts, str(texts))
        check("actions land as actions",
              any(m["kind"] == 1 and m["text"] == "waves" for m in msgs["messages"]))
        check("topics land as topics",
              any(m["kind"] == 2 for m in msgs["messages"]))

        evs = wait_for(lambda: c.get("/api/events", **{"from": 0, "to": int(time.time()) + 10})
                       ["events"] or None, timeout=10)
        kinds = {e["kind"] for e in (evs or [])}
        check("joins are recorded as presence, not conversation", 0 in kinds, str(kinds))
        check("quits too", 2 in kinds, str(kinds))
        check("presence never reaches the message table",
              all("has joined" not in m["text"] for m in msgs["messages"]))

        # ---------------------------------------------------------- sending
        head("Sending, under the user's own nick")
        bad = anon.post("/api/send", {"channel": "#mychannel", "text": "hi"})
        check("anonymous cannot send", "error" in bad)
        bad = c.post("/api/send", {"channel": "#nope", "text": "hi"})
        check("an unconfigured channel is refused", "error" in bad, str(bad))

        r = c.post("/api/send", {"channel": "#mychannel", "text": "hello from the web"})
        qid = r.get("queued")
        check("the message is queued", bool(qid), str(r))
        check("queued under the sender's nick, not the archivist's",
              r.get("nick") == "ryan_", str(r))

        sent = wait_for(lambda: c.get("/api/send/status", id=qid).get("state") == "sent",
                        timeout=40)
        check("the live process sends it", bool(sent),
              c.get("/api/send/status", id=qid).get("error") or "\n".join(live_log[-10:]))
        check("the fake network saw it from ryan_",
              any(n == "ryan_" and t == "hello from the web"
                  for n, _, t, _ in ircd.seen), str(ircd.seen[-3:]))

        back = wait_for(lambda: any(
            m["text"] == "hello from the web" and m["nick"] == "ryan_"
            for m in c.get("/api/messages", channel="mychannel", limit=80)["messages"]),
            timeout=25)
        check("and it comes back through the archivist, attributed to the sender",
              bool(back))
        rows = [m for m in c.get("/api/messages", channel="mychannel", limit=80)["messages"]
                if m["text"] == "hello from the web"]
        check("recorded exactly once", len(rows) == 1, str(len(rows)))

        # ------------------------------------------------- channel admin live
        head("Channel changes apply to a running archivist")
        c.post("/api/networks/channels",
               {"network_id": nid, "channel": "another", "archived": False})
        gone = wait_for(lambda: "#another" not in
                        c.get("/api/session")["live"]["channels"], timeout=25)
        check("pausing a channel makes the archivist leave it", bool(gone))
        c.post("/api/networks/channels",
               {"network_id": nid, "channel": "another", "archived": True})
        rejoined = wait_for(lambda: "#another" in
                            c.get("/api/session")["live"]["channels"], timeout=25)
        check("resuming makes it join again", bool(rejoined))

        # --------------------------------------------------------- searching
        head("Search, context and tags")
        found = c.get("/api/messages", q="network")
        check("full-text search finds a line", found["total"] >= 1, str(found["total"]))
        mid = msgs["messages"][0]["id"]
        ctx = c.get("/api/context", id=mid, span=5)
        check("context comes back around a message", ctx["focus"] == mid)
        loc = c.get("/api/locate", id=mid, in_channel="1")
        check("locate places it in its own channel", loc["index"] >= 0, str(loc))
        r = c.post("/api/message/tag", {"message_id": mid, "tag": "important", "on": True})
        check("a message can be tagged",
              any(t["name"] == "important" for t in r["tags"]), str(r))
        tagged = c.get("/api/messages", tag="important")
        check("and found by tag", tagged["total"] == 1, str(tagged["total"]))
        by_colour = c.get("/api/messages", tag="red")
        check("and by the tag's colour", by_colour["total"] == 1)

        # ------------------------------------------------------------- MCP
        head("MCP endpoint")
        raw = Client(base)
        r = raw.post("/mcp", {"jsonrpc": "2.0", "id": 1, "method": "tools/list"})
        check("MCP refuses an unauthenticated caller", "error" in r, str(r))
        tok = c.post("/api/tokens", {"action": "create", "name": "test agent"})
        check("an agent token can be minted", bool(tok.get("token")))
        agent = Client(base)
        r = agent.post("/mcp", {"jsonrpc": "2.0", "id": 1, "method": "tools/list"},
                       headers={"Authorization": "Bearer " + tok["token"]})
        names = [t["name"] for t in r.get("result", {}).get("tools", [])]
        check("tools/list works with a token", "search_messages" in names, str(r)[:200])
        r = agent.post("/mcp", {"jsonrpc": "2.0", "id": 2, "method": "tools/call",
                                "params": {"name": "search_messages",
                                           "arguments": {"q": "network"}}},
                       headers={"Authorization": "Bearer " + tok["token"]})
        payload = json.loads(r["result"]["content"][0]["text"])
        check("an agent can search", payload.get("total", 0) >= 1, str(payload)[:200])
        check("agents get no tool that could send",
              not any("send" in n for n in names), str(names))

        # ------------------------------------------------------ permissions
        head("Permissions")
        r = joiner.get("/api/users")
        check("a member cannot list users", "error" in r, str(r))
        r = joiner.post("/api/invites", {"role": "member"})
        check("a member cannot mint invites", "error" in r)
        r = joiner.get("/api/users/detail", username="ryan")
        check("a member cannot read provenance", "error" in r)
        r = joiner.post("/api/networks/test", {"host": "127.0.0.1", "port": ircd.port})
        check("a member cannot probe networks", "error" in r)
        r = joiner.post("/api/send", {"channel": "#mychannel", "text": "member speaking"})
        check("but a member can send", bool(r.get("queued")), str(r))
        noc = Client(base)
        noc.jar = joiner.jar                      # same cookie, no CSRF token
        r = noc.post("/api/send", {"channel": "#mychannel", "text": "csrf?"})
        check("a cookie without the CSRF token is refused", "error" in r, str(r))

        # ------------------------------------------------------ root safety
        head("Root account")
        alice_owner = c.post("/api/users/update", {"username": "alice", "role": "owner"})
        check("alice can be promoted", "error" not in alice_owner)
        r = joiner.post("/api/users/update", {"username": "ryan", "role": "member"})
        check("another owner cannot demote root", "error" in r, str(r))
        r = joiner.post("/api/users/update", {"username": "ryan", "delete": True})
        check("nor delete root", "error" in r)

    finally:
        for proc in (live, serve):
            if proc:
                proc.terminate()
                try:
                    proc.wait(timeout=8)
                except subprocess.TimeoutExpired:
                    proc.kill()
        ircd.stop()

    print(f"\n{checks - len(failures)}/{checks} checks passed")
    if failures:
        print("\nFailed:")
        for f in failures:
            print("  -", f)
        print("\nlive log tail:")
        for l in live_log[-25:]:
            print("   ", l)
        return 1
    print("Everything passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
