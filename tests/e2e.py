#!/usr/bin/env python3
"""End-to-end dry run: a real server, a real archivist, an emulated network.

Walks the whole pipeline the way the browser does - setup wizard, invites and
passes, sign-in with two-factor, search history, saved searches, channel
administration, live capture and sending - against tests/fakeircd.py rather
than a real IRC network. Nothing here touches the outside world.

    python3 tests/e2e.py
"""

import base64
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
from fakeweb import FakeWeb                                    # noqa: E402
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

    def raw(self, path):
        """A response with its bytes and headers intact, for the image proxy."""
        req = urllib.request.Request(self.base + path)
        try:
            with self.opener.open(req, timeout=30) as r:
                return r.status, {k.lower(): v for k, v in r.getheaders()}, r.read()
        except urllib.error.HTTPError as e:
            return e.code, {k.lower(): v for k, v in e.headers.items()}, e.read()

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
    web = FakeWeb().start()
    print(f"fake ircd on 127.0.0.1:{ircd.port}, fake web on {web.base}, db at {dbpath}")

    env = {**os.environ, "PYTHONUNBUFFERED": "1"}
    serve = subprocess.Popen(
        [sys.executable, str(ROOT / "archive.py"), "--db", str(dbpath),
         "serve", "--host", "127.0.0.1", "--port", str(port),
         "--allow-local-fetch"],
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
                       "id=\"qsave\"", "id=\"look-controls\"", "id=\"img-toggle\"",
                       "id=\"help-btn\"", "id=\"look-local\"",
                       "id=\"show-events\""):
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
        r = c.post("/api/invites", {"role": "user", "uses": 3, "label": "launch crew"})
        token = r.get("token")
        check("a pass for three is minted", r.get("uses") == 3 and bool(token), str(r))
        check("the invite carries no username field", "username" not in r)

        single = c.post("/api/invites", {"role": "user"}).get("token")
        check("a single invite is minted too", bool(single))

        bad = c.post("/api/invites", {"role": "user", "uses": 9999})
        check("an absurd pass size is refused", "error" in bad)

        joiner = Client(base)
        r = joiner.post("/api/redeem", {"token": token, "username": "alice",
                                        "password": "another good one",
                                        "nick": "alice_irc"})
        check("alice joins on the pass", r.get("signedIn") is True, str(r))
        check("an invite records the requested IRC nick",
              (r.get("user") or {}).get("nick") == "alice_irc", str(r))
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
        check("and is the owner", d.get("owner") is True)

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
                                         "role": "user", "nick": "dave_irc"})
        check("an account can be created directly", bool(r.get("id")), str(r))
        d = c.get("/api/users/detail", username="dave")
        check("and is recorded as created by hand", d.get("joinMethod") == "manual")

        nick = c.get("/api/nick/check", nick="ryan_")
        check("nick availability spots another Aurora account",
              nick.get("taken") is True and nick.get("account") is True, str(nick))
        clash = c.post("/api/users/create", {"username": "nickclaim",
                       "password": "another good one", "role": "user",
                       "nick": "ryan_"})
        check("a known IRC nick conflict warns instead of silently claiming",
              bool(clash.get("nickConflict")), str(clash))
        claimed = c.post("/api/users/create", {"username": "nickclaim",
                         "password": "another good one", "role": "user",
                         "nick": "ryan_", "claimNick": True})
        check("an explicit ownership claim may override the warning",
              bool(claimed.get("id")), str(claimed))
        invalid = c.get("/api/nick/check", nick="9not-a-nick")
        check("invalid IRC nicks are rejected before account creation",
              "error" in invalid, str(invalid))

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
        check("the role comes back", (r.get("user") or {}).get("role") == "admin")

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

        # ----------------------------------------- people and IRC commands
        head("People profiles and IRC commands")
        ircd.inject_join("profile_guest", "#mychannel")
        prof = wait_for(lambda: p if (p := c.get(
            "/api/person", nick="profile_guest", channel="mychannel")).get(
                "presence", {}).get("state") == "online" else None,
            timeout=10)
        check("a live JOIN appears in the person's channel roster", bool(prof), str(prof))
        nick = c.get("/api/nick/check", nick="profile_guest")
        check("account setup also warns about a nick in a visible live roster",
              nick.get("taken") is True and nick.get("online") is True, str(nick))
        check("archive activity is included in a profile",
              c.get("/api/person", nick="someone").get("messages", 0) >= 2)

        saved = c.post("/api/person", {"nick": "someone", "network": nid,
                       "favourite": True, "notes": "GMT+2",
                       "links": {"github": "octocat", "x": "@aurora_test"}})
        check("a favourite and private note can be saved",
              saved.get("annotation", {}).get("favourite") is True
              and saved.get("annotation", {}).get("notes") == "GMT+2", str(saved))
        check("profile link shorthand is normalised",
              saved.get("annotation", {}).get("links", {}).get("github")
              == "https://github.com/octocat", str(saved))
        private = joiner.get("/api/person", nick="someone", network=nid)
        check("another account cannot see those annotations",
              private.get("annotation", {}).get("notes") == ""
              and not private.get("annotation", {}).get("favourite"), str(private))
        public = anon.get("/api/person", nick="someone", network=nid)
        check("anonymous profiles keep private annotations empty",
              public.get("annotation", {}).get("links") == {}, str(public))

        asked = c.post("/api/person/status", {"nick": "definitely_offline",
                                               "network": nid})
        checked = wait_for(lambda: p if (p := c.get(
            "/api/person", nick="definitely_offline", network=nid)).get(
                "presence", {}).get("state") == "offline" else None,
            timeout=10)
        check("ISON supplies an honest network-wide offline result", bool(checked), str(asked))

        who = c.post("/api/command", {"channel": "#mychannel",
                                       "command": "/whois ryan_"})
        who_done = wait_for(lambda: x if (x := c.get(
            "/api/command/status", id=who.get("queued", 0))).get(
                "state") == "done" else None, timeout=20)
        check("WHOIS is queued and its IRC numerics come back privately",
              bool(who_done) and any(x.get("code") == "311"
                                     for x in who_done.get("replies", [])), str(who_done))
        ison = c.post("/api/command", {"channel": "#mychannel",
                                        "command": "/ison ryan_ nobody_here"})
        ison_done = wait_for(lambda: x if (x := c.get(
            "/api/command/status", id=ison.get("queued", 0))).get(
                "state") == "done" else None, timeout=20)
        check("ISON replies include only online nicknames",
              bool(ison_done) and any(x.get("code") == "303" and "ryan_" in
                                      " ".join(x.get("params", []))
                                      for x in ison_done.get("replies", [])), str(ison_done))
        ns = c.post("/api/command", {"channel": "#mychannel",
                                      "command": "/ns info ryan_"})
        ns_done = wait_for(lambda: x if (x := c.get(
            "/api/command/status", id=ns.get("queued", 0))).get(
                "state") == "done" else None, timeout=20)
        check("NickServ INFO notices are returned",
              bool(ns_done) and any(x.get("code") == "NOTICE"
                                    for x in ns_done.get("replies", [])), str(ns_done))
        bad = c.post("/api/command", {"channel": "#mychannel",
                                      "command": "/monitor + ryan_"})
        check("MONITOR explains OFTC's limitation", "OFTC" in bad.get("error", ""), str(bad))
        bad = c.post("/api/command", {"channel": "#mychannel",
                                      "command": "/raw OPER root secret"})
        check("raw syntax cannot escape the read-only query set", "error" in bad, str(bad))

        ircd.inject_quit("profile_guest")
        gone = wait_for(lambda: c.get(
            "/api/person", nick="profile_guest", network=nid).get("presence", {}).get("state")
            != "online", timeout=10)
        check("QUIT removes the person from the live roster", bool(gone))

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

        # -------------------------------------------------------- importing
        head("Importing history")
        r = c.post("/api/import/preview",
                   {"source": "url", "url": web.base + "/logs/mychannel-chat.txt"})
        check("a log at a URL is read", r.get("seen") == 6, str(r)[:200])
        check("the format is recognised", r.get("format") == "export", str(r.get("format")))
        check("it says what would be new", r.get("added") == 6 and r.get("duplicates") == 0)
        check("and shows what it parsed", len(r.get("sample") or []) > 0)
        check("presence is left out of conversation",
              all("has joined" not in x["text"] for x in r["sample"]), str(r["sample"]))
        check("a preview stores nothing", r.get("committed") is False)
        before = c.get("/api/messages", channel="mychannel", limit=1)["total"]

        r = c.post("/api/import",
                   {"source": "url", "url": web.base + "/logs/mychannel-chat.txt"})
        check("committing stores it", r.get("added") == 6, str(r)[:200])
        after = c.get("/api/messages", channel="mychannel", limit=1)["total"]
        check("the archive grew by exactly that much", after - before == 6,
              f"{before} -> {after}")

        r = c.post("/api/import",
                   {"source": "url", "url": web.base + "/logs/mychannel-chat.txt"})
        check("importing the same log twice adds nothing",
              r.get("added") == 0 and r.get("duplicates") == 6, str(r)[:160])
        check("and the archive did not grow",
              c.get("/api/messages", channel="mychannel", limit=1)["total"] == after)

        r = c.post("/api/import", {"source": "url", "events": True,
                                   "url": web.base + "/logs/mychannel-chat.txt"})
        check("joins and quits can be imported separately", r.get("added") == 2, str(r)[:160])
        check("and still are not messages",
              c.get("/api/messages", channel="mychannel", limit=1)["total"] == after)

        r = c.post("/api/import/preview", {"source": "url", "url": web.base + "/logs/"})
        check("a directory listing is not mistaken for a log", "error" in r, str(r)[:160])
        check("and it says how to pull it in",
              "follow" in (r.get("error") or "").lower(), str(r.get("error")))
        r = c.post("/api/import/preview",
                   {"source": "url", "url": web.base + "/logs/", "follow": True})
        check("following the listing reads every log on it",
              len(r.get("files") or []) == 2, str([f["name"] for f in r.get("files", [])]))
        check("in two different formats",
              {f["format"] for f in r["files"]} == {"export", "znc"},
              str([f["format"] for f in r.get("files", [])]))
        check("nothing outside that directory is touched",
              all("secret" not in f["name"] for f in r["files"]),
              str([f["name"] for f in r["files"]]))
        check("and nothing off-site",
              all("elsewhere" not in f["name"] for f in r["files"]))

        r = c.post("/api/import", {"source": "url", "follow": True,
                                   "url": web.base + "/logs/"})
        check("the znc half lands too", r.get("added") == 3, str(r)[:200])
        znc = c.get("/api/messages", q="lunch")
        check("and is searchable", znc["total"] == 1, str(znc["total"]))

        r = c.post("/api/import/preview", {"source": "text", "documents": [
            {"name": "#chan.weechatlog",
             "text": "2026-08-19 11:00:00\talice\tuploaded weechat line\n"}]})
        check("an uploaded file is read the same way", r.get("added") == 1, str(r)[:200])
        check("and detected as weechat", r.get("format") == "weechat")
        r = c.post("/api/import/preview", {"source": "text", "documents": [
            {"name": "prose.txt", "text": "just some prose\nand more of it\n"}]})
        check("something that is not a log is refused, not guessed",
              r.get("seen") == 0 and len(r.get("unreadable") or []) == 1, str(r)[:160])

        r = c.post("/api/import/preview", {"source": "text", "format": "nonsense",
                                           "documents": [{"name": "a", "text": "b"}]})
        check("an unknown format is refused", "error" in r)
        r = c.post("/api/import/preview",
                   {"source": "url", "url": "file:///etc/passwd"})
        check("file: addresses are refused", "error" in r, str(r))
        r = c.post("/api/import/preview",
                   {"source": "url", "url": "http://nothing.invalid/x.txt"})
        check("a name that does not resolve fails cleanly", "error" in r, str(r))
        r = joiner.post("/api/import/preview",
                        {"source": "url", "url": web.base + "/logs/mychannel-chat.txt"})
        check("a user cannot import", "error" in r, str(r))

        # ------------------------------------------------- image quick-look
        head("Image quick-look")
        from urllib.parse import quote
        pic = "/api/fetch/image?url=" + quote(web.base + "/img/shot.png", safe="")

        status, _hdr, _body = anon.raw(pic)
        check("the image proxy is not open to anonymous callers", status == 401,
              str(status))

        status, hdr, body = c.raw(pic)
        check("a signed-in reader gets the bytes", status == 200, str(status))
        check("as the type the host actually sent",
              hdr.get("content-type") == "image/png", str(hdr.get("content-type")))
        check("and they are a real PNG", body[:8] == b"\x89PNG\r\n\x1a\n", str(body[:8]))
        check("always as an attachment, never as a page",
              hdr.get("content-disposition", "").startswith("attachment"),
              str(hdr.get("content-disposition")))
        check("with the filename from the address",
              "shot.png" in hdr.get("content-disposition", ""),
              str(hdr.get("content-disposition")))
        check("and nosniff, so the type cannot be talked around",
              hdr.get("x-content-type-options") == "nosniff")

        meta = c.get("/api/fetch/image",
                     url=web.base + "/img/shot.png", meta="1")
        check("its type and size can be read for the details card",
              meta.get("type") == "image/png" and meta.get("bytes") == len(body),
              str(meta))
        check("along with a filename", meta.get("filename") == "shot.png", str(meta))

        status, _h, _b = c.raw("/api/fetch/image?url="
                               + quote(web.base + "/img/notreally.txt", safe=""))
        check("something that is not a picture is refused", status == 415, str(status))
        status, _h, _b = c.raw("/api/fetch/image?url="
                               + quote(web.base + "/img/missing.png", safe=""))
        check("a missing picture fails cleanly", status == 400, str(status))
        status, _h, _b = c.raw("/api/fetch/image?url=" + quote("file:///etc/passwd", safe=""))
        check("and file: addresses are refused here too", status == 400, str(status))
        status, _h, _b = c.raw("/api/fetch/image?url=" + quote("http://nothing.invalid/a.png", safe=""))
        check("as is a name that does not resolve", status == 400, str(status))

        # ------------------------------------------------------ permissions
        head("Permissions")
        r = joiner.get("/api/users")
        check("a user cannot list users", "error" in r, str(r))
        r = joiner.post("/api/invites", {"role": "user"})
        check("a user cannot mint invites", "error" in r)
        r = joiner.get("/api/users/detail", username="ryan")
        check("a user cannot read provenance", "error" in r)
        r = joiner.post("/api/networks/test", {"host": "127.0.0.1", "port": ircd.port})
        check("a user cannot probe networks", "error" in r)
        r = joiner.post("/api/send", {"channel": "#mychannel", "text": "member speaking"})
        check("but a user can send", bool(r.get("queued")), str(r))
        noc = Client(base)
        noc.jar = joiner.jar                      # same cookie, no CSRF token
        r = noc.post("/api/send", {"channel": "#mychannel", "text": "csrf?"})
        check("a cookie without the CSRF token is refused", "error" in r, str(r))

        # ------------------------------------------------------ root safety
        head("The owner account")
        alice_owner = c.post("/api/users/update", {"username": "alice", "role": "admin"})
        check("alice can be promoted", "error" not in alice_owner)
        r = joiner.post("/api/users/update", {"username": "ryan", "role": "user"})
        check("another admin cannot demote the owner", "error" in r, str(r))
        r = joiner.post("/api/users/update", {"username": "ryan", "delete": True})
        check("nor delete the owner", "error" in r)

        # ------------------------------------------- two-factor for admins
        head("Two-factor is the admin's key")
        r = joiner.get("/api/users")
        check("an admin without two-factor is refused the management surface",
              "error" in r and r.get("totpSetup") is True, str(r))
        beg = joiner.post("/api/me/totp", {"action": "begin"})
        check("but may still enrol", bool(beg.get("secret")), str(beg))
        r = joiner.post("/api/me/totp",
                        {"action": "confirm", "code": A.totp_codes(beg["secret"])[1]})
        check("and turn it on", r.get("enabled") is True, str(r))
        r = joiner.get("/api/users")
        check("after which the surface opens", "users" in r, str(r))
        r = joiner.post("/api/users/update", {"username": "ryan", "role": "user"})
        check("with two-factor on the owner still cannot be demoted",
              "error" in r, str(r))
        r = joiner.post("/api/me/totp", {"action": "disable"})
        check("an admin cannot turn two-factor back off", "error" in r, str(r))
        r = joiner.post("/api/me/totp", {"action": "decline"})
        check("nor decline it", "error" in r, str(r))
        r = bob.post("/api/me/totp", {"action": "decline"})
        check("a user may decline once", r.get("declined") is True, str(r))
        s = bob.get("/api/session")
        check("and the choice rides the session",
              (s.get("user") or {}).get("totpDeclined") is True, str(s))
        r = c.post("/api/users/update", {"username": "bob", "role": "admin"})
        check("a user who declined can later be promoted", "error" not in r, str(r))
        s = bob.get("/api/session")
        check("promotion clears the old optional-security dismissal",
              (s.get("user") or {}).get("role") == "admin"
              and (s.get("user") or {}).get("totpDeclined") is False, str(s))
        locked = bob.get("/api/users")
        check("the promoted admin remains locked out until two-factor is set",
              locked.get("totpSetup") is True, str(locked))
        check("the founder stays exempt from the hard gate",
              "users" in c.get("/api/users"))

        # ------------------------------------------------------ reset links
        head("Password reset links")
        r = c.post("/api/users/reset", {"username": "nobody"})
        check("a link needs a real account", "error" in r, str(r))
        r = c.post("/api/users/reset", {"username": "dave"})
        rtok = r.get("token")
        check("the owner mints a reset link for dave",
              bool(rtok) and r.get("url", "").startswith("/#reset="), str(r))
        r = Client(base).post("/api/reset/complete",
                              {"token": rtok, "password": "short"})
        check("a short replacement password is refused", "error" in r, str(r))
        dave2 = Client(base)
        r = dave2.post("/api/reset/complete",
                       {"token": rtok, "password": "a brand new one 9"})
        check("a good one sets it and signs dave in",
              r.get("signedIn") is True, str(r))
        r = Client(base).post("/api/reset/complete",
                              {"token": rtok, "password": "again again 999"})
        check("a reset link is single use", "error" in r, str(r))
        r = Client(base).post("/api/login", {"username": "dave",
                                             "password": "another good one"})
        check("the old password is dead", "error" in r, str(r))
        r = Client(base).post("/api/login", {"username": "dave",
                                             "password": "a brand new one 9"})
        check("the new one signs in", r.get("signedIn") is True, str(r))
        r = joiner.post("/api/users/reset", {"username": "ryan"})
        check("only the owner may reset the owner", "error" in r, str(r))
        first = c.post("/api/users/reset", {"username": "dave"}).get("token")
        c.post("/api/users/reset", {"username": "dave"})
        r = Client(base).post("/api/reset/complete",
                              {"token": first, "password": "should not work 9"})
        check("minting a new link kills the old one", "error" in r, str(r))

        # ------------------------------------------------- profile pictures
        head("Profile pictures")
        png = base64.b64decode(
            "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8"
            "z8BQDwAEhQGAhKmMIQAAAABJRU5ErkJggg==")
        r = c.post("/api/me/avatar",
                   {"image": "data:image/png;base64,"
                             + base64.b64encode(png).decode()})
        check("a small PNG is accepted", bool(r.get("avatar")), str(r))
        status, hdr, body = c.raw("/api/avatar?u=ryan")
        check("members read it back", status == 200, str(status))
        check("as the type it really is",
              hdr.get("content-type") == "image/png", str(hdr.get("content-type")))
        check("byte for byte", body == png)
        status, _h, _b = anon.raw("/api/avatar?u=ryan")
        check("anonymous readers cannot address avatars by account username",
              status == 400, str(status))
        status, hdr, body = anon.raw("/api/avatar?n=ryan_")
        check("but the IRC-facing profile picture is public", status == 200, str(status))
        check("the public picture is byte for byte", body == png)
        m = c.get("/api/meta")
        check("meta maps the nick to the picture for members",
              (m.get("avatars") or {}).get("ryan_", {}).get("n") == "ryan_",
              str(m.get("avatars")))
        m = anon.get("/api/meta")
        check("and supplies the same public nick mapping anonymously",
              (m.get("avatars") or {}).get("ryan_", {}).get("n") == "ryan_", str(m))
        profile = anon.get("/api/person", nick="ryan_", network=nid)
        check("public person profiles recognise an Aurora member without leaking username",
              profile.get("identity", {}).get("kind") == "aurora"
              and profile.get("internal", {}).get("username") is None, str(profile))
        r = c.post("/api/me/avatar",
                   {"image": "data:image/jpeg;base64,"
                             + base64.b64encode(png).decode()})
        check("bytes must match the declared type", "error" in r, str(r))
        r = c.post("/api/me/avatar", {"image": "data:image/gif;base64,AAAA"})
        check("only JPEG, PNG and WebP are taken", "error" in r, str(r))
        big = png + b"\x00" * (301 * 1024)
        r = c.post("/api/me/avatar",
                   {"image": "data:image/png;base64,"
                             + base64.b64encode(big).decode()})
        check("an oversized picture is refused", "error" in r, str(r))
        r = c.post("/api/me/avatar", {"clear": True})
        check("the picture can be removed", r.get("avatar") == 0, str(r))
        status, _h, _b = c.raw("/api/avatar?u=ryan")
        check("after which there is nothing to fetch", status == 404, str(status))

        # ------------------------------------------------ appearance prefs
        head("Appearance follows the account")
        r = c.post("/api/prefs", {"prefs": {"theme": "borealis",
                                            "accent": "#8b9dff"}})
        check("preferences are stored", bool(r.get("at")), str(r))
        r = c.get("/api/prefs")
        check("and come back on any device",
              (r.get("prefs") or {}).get("theme") == "borealis", str(r))
        r = anon.get("/api/prefs")
        check("anonymous readers have none", "error" in r, str(r))
        r = c.post("/api/prefs", {"prefs": "nonsense"})
        check("prefs must be an object", "error" in r, str(r))
        r = c.post("/api/prefs", {"prefs": {"bg": "x" * 810_000}})
        check("and are capped in size", "error" in r, str(r))

        # ---------------------------------------------- tags stay members'
        head("Tags stay behind the sign-in")
        r = c.post("/api/tags", {"name": "secret", "color": "red"})
        check("a member makes a tag", "error" not in r, str(r))
        mid = c.get("/api/messages", limit=1)["messages"][0]["id"]
        r = c.post("/api/message/tag", {"message_id": mid, "tag": "secret",
                                        "on": True})
        check("and puts it on a message",
              any(t["name"] == "secret" for t in r.get("tags", [])), str(r))
        r = c.get("/api/messages", limit=5)
        check("members see it in the feed",
              any(any(t["name"] == "secret" for t in m.get("tags", []))
                  for m in r["messages"]), str(r)[:200])
        r = anon.get("/api/tags")
        check("anonymous readers get no tag list", r.get("tags") == [], str(r))
        check("no tags in meta", anon.get("/api/meta").get("tags") == [])
        r = anon.get("/api/messages", limit=200)
        check("and none on any message",
              all(m.get("tags") == [] for m in r["messages"]))
        with_f = anon.get("/api/messages", tag="secret")["total"]
        without = anon.get("/api/messages")["total"]
        check("a tag filter does not even leak by count", with_f == without,
              f"{with_f} != {without}")
        check("saved searches stay behind it too",
              anon.get("/api/searches").get("searches") == [])

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
