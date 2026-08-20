#!/usr/bin/env python3
"""Prove an upgrade keeps every account, message and credential.

Builds an archive with a *previous release's own code*, upgrades it by opening
it with the code in the working tree, and then checks two things:

  * a census taken in plain SQL - row counts and content digests, table by
    table - so nothing can be quietly dropped or rewritten;
  * that the credentials issued before the upgrade still work: the old
    password, the session cookie already in someone's browser, the same
    authenticator secret, the agent token, the passkey, the outstanding
    invitation.

    python3 tests/upgrade.py                 # against the previous tag
    python3 tests/upgrade.py --from v1.0.2   # or any older one
"""

import argparse
import hashlib
import http.cookiejar
import json
import os
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.request
from pathlib import Path
from urllib.parse import urlencode

ROOT = Path(__file__).resolve().parent.parent
PASS, FAIL = "\033[32m✓\033[0m", "\033[31m✗\033[0m"
results = {"ok": 0, "bad": []}


def check(label, cond, detail=""):
    if cond:
        results["ok"] += 1
        print(f"  {PASS} {label}")
    else:
        results["bad"].append(label)
        print(f"  {FAIL} {label}" + (f"  — {detail}" if detail else ""))


def head(t):
    print(f"\n\033[1m{t}\033[0m")


def this_version():
    for line in (ROOT / "addon" / "config.yaml").read_text().split("\n"):
        if line.startswith("version:"):
            return line.split(":", 1)[1].strip().strip('"')
    return ""


def previous_tag():
    """The newest release *before* the one being prepared.

    A tag for the version in config.yaml is this release, published or not -
    upgrading from it would prove nothing, so the newest one below it is used.
    """
    mine = "v" + this_version()
    for tag in subprocess.run(["git", "tag", "--sort=-v:refname"], cwd=ROOT,
                              capture_output=True, text=True).stdout.split():
        if tag != mine:
            return tag
    return None


# ----------------------------------------------------------------- the census

CENSUS = {
    "messages": "SELECT c.name, n.name, m.ts, m.kind, m.text, m.source FROM messages m "
                "JOIN channels c ON c.id=m.channel_id JOIN nicks n ON n.id=m.nick_id "
                "ORDER BY m.ts, m.id",
    "events": "SELECT c.name, n.name, e.ts, e.kind, e.detail FROM events e "
              "JOIN channels c ON c.id=e.channel_id JOIN nicks n ON n.id=e.nick_id "
              "ORDER BY e.ts, e.id",
    "users": "SELECT username, password, role, irc_nick, totp_secret, totp_enabled, "
             "disabled, created FROM users ORDER BY username",
    "sessions": "SELECT id, user_id, csrf, expires FROM sessions ORDER BY id",
    "credentials": "SELECT cred_id, public_key, sign_count, label FROM credentials "
                   "ORDER BY cred_id",
    "api_tokens": "SELECT name, hash, revoked FROM api_tokens ORDER BY hash",
    "tags": "SELECT name, label, color, builtin FROM tags ORDER BY name",
    "message_tags": "SELECT mt.message_id, t.name FROM message_tags mt "
                    "JOIN tags t ON t.id=mt.tag_id ORDER BY mt.message_id, t.name",
    "saved_searches": "SELECT name, query, extra, used FROM saved_searches ORDER BY name",
    "networks": "SELECT name, label, host, port, tls, archivist_nick, enabled "
                "FROM networks ORDER BY name",
    "channels": "SELECT name, network_id, archived FROM channels ORDER BY name",
    "settings": "SELECT key, value FROM settings WHERE key NOT LIKE 'live_%' "
                "AND key NOT LIKE 'prewarm:%' ORDER BY key",
    "outbox": "SELECT channel, text, nick, sent_at, error FROM outbox ORDER BY id",
    "invites": "SELECT token, role, created_by, expires FROM invites ORDER BY token",
    "ingests": "SELECT path, seen, inserted FROM ingests ORDER BY id",
}


def census(path):
    """Read with plain SQL, never through the application - a helper that hid
    a change would hide it from this too."""
    con = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
    out = {"counts": {}, "digests": {}}
    for (name,) in con.execute(
            "SELECT name FROM sqlite_master WHERE type='table' "
            "AND name NOT LIKE 'sqlite_%' AND name NOT LIKE 'messages_fts%'"):
        out["counts"][name] = con.execute(f"SELECT COUNT(*) FROM {name}").fetchone()[0]
    for key, sql in CENSUS.items():
        h = hashlib.sha256()
        for row in con.execute(sql):
            h.update(repr(tuple(row)).encode())
        out["digests"][key] = h.hexdigest()[:16]
    out["fts"] = con.execute(
        "SELECT COUNT(*) FROM messages_fts WHERE messages_fts MATCH 'history'").fetchone()[0]
    out["integrity"] = con.execute("PRAGMA integrity_check").fetchone()[0]
    con.close()
    return out


# ------------------------------------------------------- build the old archive

BUILD = r'''
import sys, time
sys.path.insert(0, OLD)
from ircarchive import db, auth as A
path = sys.argv[1]
con = db.connect(path)
owner = A.create_user(con, 'ryan', 'live server password', role='owner', irc_nick='ryan_')
db.setting(con, 'root_user_id', owner)
alice = A.create_user(con, 'alice', 'alice long password', role='member')
A.create_user(con, 'bob', 'bob long password', role='owner', irc_nick='bobby')
carol = A.create_user(con, 'carol', 'carol long password', role='member')
con.execute("UPDATE users SET disabled = 1 WHERE id = ?", (carol,))
sec = A.totp_secret()
con.execute("UPDATE users SET totp_secret = ?, totp_enabled = 1 WHERE id = ?", (sec, alice))
con.execute("INSERT INTO credentials(user_id, cred_id, public_key, sign_count, label, created) "
            "VALUES (?,?,?,?,?,?)", (owner, 'credid-abc', b'\x01\x02\x03', 7, 'Yubikey', 1700000000))
tok = A.mint_token(con, owner, 'agent-laptop')
sid, csrf = A.new_session(con, owner, ip='10.0.0.5', agent='Mozilla/5.0 test')
A.new_session(con, alice, ip='10.0.0.6', agent='phone')
inv_open = A.create_invite(con, owner, role='member')
inv_used = A.create_invite(con, owner, role='member')
A.redeem_invite(con, inv_used, 'dave', 'dave long password')
nid = con.execute("INSERT INTO networks(name,label,host,port,tls,archivist_nick,created) "
                  "VALUES ('libera','LIBERA','irc.libera.chat',6697,1,'aurora',?)",
                  (int(time.time()),)).lastrowid
ids = db.Ids(con)
for chan in ('mychannel', 'another'):
    con.execute("INSERT OR IGNORE INTO channels(name, network_id) VALUES (?,?)", (chan, nid))
    con.execute("UPDATE channels SET network_id=?, archived=1 WHERE name=?", (nid, chan))
base = 1755000000
rows  = [('mychannel','alice',base+i*60,0,f'line number {i} of history') for i in range(500)]
rows += [('mychannel','bob',base+60000+i,1,f'does thing {i}') for i in range(20)]
rows += [('another','carol',base+70000+i*30,0,f'other channel {i}') for i in range(120)]
db.insert_messages(con, ids, rows, 'export')
db.insert_events(con, ids,
    [('mychannel','dave',base+80000+i,i%6,'') for i in range(40)], 'live')
con.execute("INSERT INTO tags(name,label,color,builtin,created) VALUES ('gpu','GPU','pink',0,?)",
            (int(time.time()),))
for i, (mid,) in enumerate(con.execute("SELECT id FROM messages ORDER BY id LIMIT 25")):
    tid = con.execute("SELECT id FROM tags ORDER BY id LIMIT 1 OFFSET ?", (i % 7,)).fetchone()[0]
    con.execute("INSERT OR IGNORE INTO message_tags(message_id,tag_id,at) VALUES (?,?,?)",
                (mid, tid, int(time.time())))
con.execute("INSERT INTO saved_searches(name,query,extra,created,used) "
            "VALUES ('Release chatter','#mychannel release','{}',?,4)", (int(time.time()),))
con.execute("INSERT INTO saved_searches(name,query,extra,created,used) "
            "VALUES ('Alice','@alice','{}',?,1)", (int(time.time()),))
db.queue_outbound(con, '#mychannel', 'a queued line', user_id=owner, nick='ryan_')
db.record_ingest(con, '/logs/mychannel-chat.txt', 500, 500)
db.setting(con, 'app_name', 'Aurora Silicon Live')
A.log(con, 'login_ok', username='ryan', ip='10.0.0.5')
con.execute("PRAGMA wal_checkpoint(TRUNCATE)")
con.close()
print(json.dumps({'session': sid, 'csrf': csrf, 'token': tok,
                  'totp': sec, 'invite_open': inv_open, 'invite_used': inv_used}))
'''


class Client:
    def __init__(self, base):
        self.base = base
        self.jar = http.cookiejar.CookieJar()
        self.o = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(self.jar))
        self.csrf = ""

    def get(self, path, cookie=None, **q):
        url = self.base + path + ("?" + urlencode(q, doseq=True) if q else "")
        req = urllib.request.Request(url)
        if cookie:
            req.add_header("Cookie", cookie)
        try:
            with self.o.open(req, timeout=25) as r:
                return json.loads(r.read())
        except urllib.error.HTTPError as e:
            return json.loads(e.read() or b"{}")

    def post(self, path, body=None, headers=None):
        req = urllib.request.Request(self.base + path,
                                     data=json.dumps(body or {}).encode(), method="POST")
        req.add_header("Content-Type", "application/json")
        if self.csrf:
            req.add_header("X-CSRF", self.csrf)
        for k, v in (headers or {}).items():
            req.add_header(k, v)
        try:
            with self.o.open(req, timeout=30) as r:
                out = json.loads(r.read())
        except urllib.error.HTTPError as e:
            out = json.loads(e.read() or b"{}")
        if isinstance(out, dict) and out.get("csrf"):
            self.csrf = out["csrf"]
        return out


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--from", dest="ref", default=None,
                    help="release to upgrade from (default: the newest tag)")
    ap.add_argument("--port", type=int, default=8811)
    a = ap.parse_args()

    ref = a.ref or previous_tag()
    if not ref:
        print("No tags to upgrade from - nothing to check.")
        return 0
    tmp = Path(tempfile.mkdtemp(prefix="aurora-upgrade-"))
    old = tmp / "old"
    old.mkdir()
    tar = subprocess.run(["git", "archive", ref], cwd=ROOT, capture_output=True)
    if tar.returncode:
        print(f"Could not export {ref}: {tar.stderr.decode().strip()}")
        return 1
    subprocess.run(["tar", "x", "-C", str(old)], input=tar.stdout, check=True)
    print(f"Upgrading a {ref} archive to the working tree's code")

    dbfile = tmp / "archive.db"
    build = f"import json\nOLD={str(old)!r}\n" + BUILD
    made = subprocess.run([sys.executable, "-c", build, str(dbfile)],
                          capture_output=True, text=True)
    if made.returncode:
        print(made.stdout, made.stderr)
        return 1
    secrets = json.loads(made.stdout.strip().split("\n")[-1])

    before = census(dbfile)
    check(f"the {ref} archive is sound to begin with", before["integrity"] == "ok")

    # the upgrade itself: opening it is what runs every migration
    up = subprocess.run(
        [sys.executable, "-c",
         "import sys;sys.path.insert(0,%r)\n"
         "from ircarchive import db\n"
         "con=db.connect(sys.argv[1]);con.execute('PRAGMA wal_checkpoint(TRUNCATE)');con.close()"
         % str(ROOT), str(dbfile)],
        capture_output=True, text=True)
    if up.returncode:
        print("The upgrade itself failed:\n", up.stdout, up.stderr)
        return 1
    after = census(dbfile)

    head("Nothing is lost")
    check("the archive is still sound", after["integrity"] == "ok", after["integrity"])
    check("the full-text index still answers",
          after["fts"] == before["fts"] and after["fts"] > 0,
          f"{before['fts']} -> {after['fts']}")
    for table, was in sorted(before["counts"].items()):
        now = after["counts"].get(table)
        check(f"{table}: {was} row(s) kept", now is not None and now >= was,
              f"{was} -> {now}")
    for key, was in sorted(before["digests"].items()):
        check(f"{key} is byte-for-byte what it was", after["digests"][key] == was)

    base = f"http://127.0.0.1:{a.port}"
    env = {**os.environ, "PYTHONUNBUFFERED": "1"}
    srv = subprocess.Popen([sys.executable, str(ROOT / "archive.py"), "--db", str(dbfile),
                            "serve", "--host", "127.0.0.1", "--port", str(a.port)],
                           stdout=subprocess.PIPE, stderr=subprocess.STDOUT, env=env)
    log = []
    threading.Thread(target=lambda: [log.append(l.decode().rstrip())
                                     for l in iter(srv.stdout.readline, b"")],
                     daemon=True).start()
    try:
        for _ in range(80):
            try:
                urllib.request.urlopen(base + "/api/meta", timeout=2)
                break
            except Exception:
                time.sleep(0.25)

        sys.path.insert(0, str(ROOT))
        from ircarchive import auth as A

        head("The archive still reads")
        anon = Client(base)
        meta = anon.get("/api/meta")
        check("every message is still there", meta.get("total") == 640, str(meta.get("total")))
        check("the server keeps its name", meta.get("appName") == "Aurora Silicon Live")
        check("both channels survive",
              sorted(c["name"] for c in meta["channels"]) == ["another", "mychannel"])
        check("the custom tag survives", any(t["name"] == "gpu" for t in meta["tags"]))
        check("tagged messages are still tagged",
              anon.get("/api/messages", tag="important")["total"] > 0)
        check("search still works", anon.get("/api/messages", q="history")["total"] == 500)
        check("saved searches survive", len(anon.get("/api/searches")["searches"]) == 2)
        check("setup is not offered again", anon.get("/api/session")["setupNeeded"] is False)

        head("Credentials issued before the upgrade")
        sess = anon.get("/api/session", cookie=f"sid={secrets['session']}")
        check("a browser already signed in stays signed in", sess.get("signedIn") is True)
        check("as the same person, role and nick",
              sess.get("user", {}).get("name") == "ryan"
              and sess["user"]["role"] == "owner" and sess["user"]["nick"] == "ryan_",
              str(sess.get("user")))

        ryan = Client(base)
        check("the old password still signs in",
              ryan.post("/api/login", {"username": "ryan",
                                       "password": "live server password"}).get("signedIn"))
        check("a wrong one still does not",
              "error" in Client(base).post("/api/login",
                                           {"username": "ryan", "password": "nope"}))
        al = Client(base)
        check("an account with two-factor is still asked for a code",
              al.post("/api/login", {"username": "alice",
                                     "password": "alice long password"}).get("totpRequired"))
        check("and the same authenticator secret still works",
              al.post("/api/login", {"username": "alice", "password": "alice long password",
                                     "totp": A.totp_codes(secrets["totp"])[1]}).get("signedIn"))
        check("a disabled account is still refused",
              "error" in Client(base).post("/api/login",
                                           {"username": "carol",
                                            "password": "carol long password"}))
        r = Client(base).post("/mcp", {"jsonrpc": "2.0", "id": 1, "method": "tools/list"},
                              headers={"Authorization": "Bearer " + secrets["token"]})
        check("an agent token minted before the upgrade still works",
              "search_messages" in [t["name"] for t in
                                    r.get("result", {}).get("tools", [])], str(r)[:120])
        check("the registered passkey is still registered",
              len(ryan.post("/api/me/passkey", {"action": "list"}).get("passkeys") or []) == 1)

        head("Invitations keep their history")
        invites = ryan.get("/api/invites")["invites"]
        live = [i for i in invites if i["token"] == secrets["invite_open"]]
        spent = [i for i in invites if i["token"] == secrets["invite_used"]]
        check("an outstanding invitation is still usable",
              live and live[0]["live"] and live[0]["uses"] == 0, str(live))
        check("a redeemed one is marked used", spent and spent[0]["uses"] == 1, str(spent))
        check("and still remembers who joined on it",
              spent and [j["name"] for j in spent[0]["joiners"]] == ["dave"], str(spent))
        d = ryan.get("/api/users/detail", username="dave")
        check("an old redemption becomes proper provenance",
              d.get("joinMethod") == "invite" and d.get("invitedBy") == "ryan", str(d))
        check("and the founder is still root",
              ryan.get("/api/users/detail", username="ryan").get("root") is True)

        head("And it is still a working server")
        check("new writes work",
              len(ryan.post("/api/searches", {"name": "After upgrade", "query": "x",
                                              "extra": {}}).get("searches") or []) == 3)
        check("the features added this release work",
              len(ryan.post("/api/history", {"action": "record",
                                             "query": "#mychannel new"}).get("history") or []) == 1)
        check("nothing was logged as an error along the way",
              not any("Traceback" in l or "[error]" in l for l in log),
              " | ".join(l for l in log if "[error]" in l)[:200])
    finally:
        srv.terminate()
        try:
            srv.wait(timeout=8)
        except subprocess.TimeoutExpired:
            srv.kill()
        shutil.rmtree(tmp, ignore_errors=True)

    total = results["ok"] + len(results["bad"])
    print(f"\n{results['ok']}/{total} checks passed")
    if results["bad"]:
        print("\nFailed:")
        for b in results["bad"]:
            print("  -", b)
        return 1
    print(f"An upgrade from {ref} keeps every account, message and credential.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
