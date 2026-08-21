"""JSON API + static file server for the archive viewer.

Read querying lives in ircarchive.query, which the MCP server uses too, so the
two front ends can never drift apart.

Authorisation model (see ircarchive.auth for the mechanics):

  * anonymous - read only, and only the record itself: browse, search and
    filter the messages as IRC carried them. Public IRC-facing avatars are
    visible; tags, saved searches, private person notes and other member
    annotations stay behind a sign-in, and every mutating endpoint is behind
    _need_auth.
  * user - may send messages under their own IRC nick, and manage tags.
  * admin - the above, plus invites, user administration and the audit log.
    Admins must have two-factor on to reach the management surface. The
    founding account is the owner, no admin can demote or remove it, and it
    alone is exempt from the two-factor gate so it can never be locked out.

Accounts exist only by invitation; there is no public signup route. Sessions
live in the database, carry a CSRF token that state-changing requests must
echo in X-CSRF, and are rotated on every login.

Sending stays asymmetric: this server never touches an IRC socket. Posting
appends to ``outbox`` tagged with the sender's nick, and the live process
opens a send-only connection for that identity. The archivist connection is
the only receiver, so the message returns through it and is recorded once.

Endpoints:
  GET  /api/meta|nicks|messages|context|locate|activity|events|stream (public)
  GET  /api/person            archive + live profile for one IRC nick
  GET  /api/command/status    private reply to a queued IRC command
  GET  /api/tags|searches|avatar|prefs           (tags/searches empty for anon)
  GET  /api/session          sign-in state, role, CSRF token, live status
  GET  /api/users|invites|authlog                     (owner)
  GET  /api/sessions         this user's active sessions
  POST /api/setup            {username, password, nick}  first run only
  POST /api/login            {username, password, totp?}
  POST /api/redeem           {token, username, password, nick, claimNick?}
  POST /api/signout
  POST /api/me               {nick?, password?, current?}          (auth)
  POST /api/me/totp          {action: begin|confirm|disable|decline} (auth)
  POST /api/me/avatar        {image: data URL} or {clear}          (auth)
  POST /api/prefs            {prefs: {...}} synced appearance      (auth)
  POST /api/users/reset      {username} mint a password reset link (owner)
  POST /api/reset/complete   {token, password}                 (anonymous)
  POST /api/sessions/revoke  {id?|all}                             (auth)
  POST /api/send             {channel, text}                       (auth)
  POST /api/tags|tags/update|tags/delete|message/tag               (auth)
  POST /api/searches|searches/delete|searches/used                 (auth)
  POST /api/history          {action: record|clear, query}        (auth)
  POST /api/person           private favourite, notes and links   (auth)
  POST /api/person/status    refresh network-wide ISON status     (auth)
  POST /api/command          queue a read-only IRC slash command   (auth)
  POST /api/invites          {role, uses?, label?}                (owner)
  POST /api/invites/revoke   {token}                              (owner)
  POST /api/networks/test    {host, port, tls, nick}              (owner)
  POST /api/import           {source, url|documents, format, ...} (owner)
  POST /api/import/preview   the same, parsed and rolled back      (owner)
  GET  /api/fetch/image?url= a picture, through this server        (auth)
  POST /api/users/update     {username, role?, disabled?, delete?} (owner)
  GET  /api/users/detail?username=   join provenance for one account (owner)
  GET  /api/history          recent searches for this account       (auth)
"""

import base64
import binascii
import json
import re
import secrets
import sqlite3
import threading
import time
from http.cookies import SimpleCookie
from http.server import ThreadingHTTPServer, SimpleHTTPRequestHandler
from pathlib import Path
from urllib.parse import urlparse, parse_qs, quote

from . import (auth as A, backfill as BF, db, events as EV,
               fetching as F, query as Q, webauthn as W)
from .mcptools import Archive, TOOLS, PROTOCOL_VERSION, SERVER_INFO

WEB_ROOT = Path(__file__).resolve().parent / "web"
MAX_SEND = 450
LIVE_STALE = 45
MAX_BODY = 64 * 1024        # no API call needs more; refuse the rest unread
MAX_IMPORT_BODY = 16 * 1024 * 1024   # except an uploaded log, which is the payload
MAX_MEDIA_BODY = 1024 * 1024   # a profile picture or a background in the prefs
AVATAR_MAX_BYTES = 300 * 1024  # decoded; the client sends a 256px crop anyway
PREFS_MAX_LEN = 800_000        # serialized prefs, background image included
PERSON_NOTES_MAX = 2000
PERSON_LINK_MAX = 500
PERSON_LINK_KINDS = ("website", "github", "x", "matrix", "other")
IRC_COMMAND_ARGS = {
    "WHOIS": (1, 2), "ISON": (1, 10), "NAMES": (0, 1),
    "WHO": (0, 2), "USERHOST": (1, 5), "WHOWAS": (1, 2),
    "MOTD": (0, 1), "VERSION": (0, 1), "TIME": (0, 1),
}
IRC_NICK_RE = re.compile(r"^[A-Za-z\[\]\\`_^{|}][A-Za-z0-9\[\]\\`_^{|}-]{0,29}$")
MAX_IMAGE_BYTES = 25 * 1024 * 1024
# Served back from our own origin, so the list is what a browser will render
# as a picture and nothing else. SVG is a document with script in it and is
# refused outright rather than trusted to a Content-Disposition.
IMAGE_TYPES = {"image/png", "image/jpeg", "image/jpg", "image/gif", "image/webp",
               "image/avif", "image/bmp", "image/tiff", "image/x-icon",
               "image/vnd.microsoft.icon", "image/heic", "image/heif"}
MAX_STREAMS = 40            # SSE holds a thread each, so cap them
MAX_OFFSET = 2_000_000      # deep paging makes SQLite walk the table
STREAM_SECONDS = 900

_local = threading.local()
_mcp = {"archive": None}     # one read-only handle, shared by agent requests
_meta_cache = {"key": None, "value": None, "at": 0.0}
_meta_lock = threading.Lock()
META_TTL = 120          # seconds; the key below catches real changes sooner
_streams = 0
_streams_lock = threading.Lock()


def _con(dbpath):
    if getattr(_local, "con", None) is None:
        _local.con = sqlite3.connect(str(dbpath), timeout=30, isolation_level=None)
        _local.con.row_factory = sqlite3.Row
    return _local.con


def _filters(p):
    return {
        "q": p.get("q", [""])[0],
        "channels": p.get("channel", []),
        "nicks": p.get("nick", []),
        "since": p.get("from", [""])[0],
        "until": p.get("to", [""])[0],
        "kinds": p.get("kind", []),
        "tags": p.get("tag", []),
    }


def cached_meta(con):
    """/api/meta aggregates over every message and is hit on every page load.

    On a small machine that is close to a second of work each time, and it is
    reachable without authenticating - so it is cached against a key that is
    cheap to compute and changes whenever the answer would.
    """
    key = (
        con.execute("SELECT MAX(id) FROM messages").fetchone()[0],
        con.execute("SELECT COUNT(*), COALESCE(MAX(id),0) FROM tags").fetchone()[0:2],
        db.setting(con, "app_name"),
    )
    now = time.time()
    with _meta_lock:
        if _meta_cache["key"] == key and now - _meta_cache["at"] < META_TTL:
            return _meta_cache["value"]
    m = Q.meta(con)
    m["tags"] = Q.tags(con)
    m["appName"] = db.setting(con, "app_name") or "AuroraIRC"
    # Everyone who has spoken, so a "name:" mention can be linked even for
    # someone far outside the top talkers.
    m["speakers"] = Q.speakers(con)
    with _meta_lock:
        _meta_cache.update(key=key, value=m, at=now)
    return m


def network_status(con, nid):
    """Liveness of one network's archivist."""
    beat = db.setting(con, f"live_heartbeat:{nid}")
    age = (int(time.time()) - int(beat)) if beat else None
    chans = db.setting(con, f"live_channels:{nid}") or ""
    return {"id": nid, "connected": age is not None and age < LIVE_STALE,
            "nick": db.setting(con, f"live_nick:{nid}"),
            "channels": [c for c in chans.split(",") if c], "age": age}


def live_status(con):
    """Aggregate view for the UI: every network's archivist at once."""
    nets = db.networks(con, enabled_only=True)
    per = []
    for n in nets:
        st = network_status(con, n["id"])
        st["network"] = n["name"]
        st["label"] = n["label"] or n["name"]
        per.append(st)
    up = [p for p in per if p["connected"]]
    # Channels are namespaced by network, but the composer wants a flat list
    chans, seen = [], set()
    for p in up:
        for c in p["channels"]:
            if c not in seen:
                seen.add(c)
                chans.append(c)
    ages = [p["age"] for p in up if p["age"] is not None]
    return {"connected": bool(up), "nick": up[0]["nick"] if up else None,
            "channels": chans, "age": min(ages) if ages else None,
            "networks": per}


def channel_network(con, channel):
    """Which network a channel belongs to, or None if it isn't configured."""
    row = con.execute(
        "SELECT network_id FROM channels WHERE name = ? COLLATE NOCASE "
        "AND archived = 1", (channel.lstrip("#").lower(),)).fetchone()
    return row["network_id"] if row and row["network_id"] else None


def clean_person_nick(value):
    """A lookup key, not a complete network-specific nick validator."""
    nick = str(value or "").strip()
    if (not nick or len(nick) > 30 or any(c.isspace() or ord(c) < 32 for c in nick)
            or "," in nick):
        raise ValueError("invalid nick")
    return nick


def normalize_irc_nick(value, fallback=None):
    nick = str(value or fallback or "").strip()
    if not IRC_NICK_RE.fullmatch(nick):
        raise ValueError("IRC nicks are 1–30 characters and cannot start with a number")
    return nick


def irc_nick_state(con, value, exclude_user=None):
    """Known nick conflicts without pretending Aurora can prove ownership.

    Account mappings are durable; channel presence is current but limited to
    the networks and rooms Aurora tracks. The UI presents either as a warning
    and lets a person explicitly claim a nick they know is theirs.
    """
    nick = normalize_irc_nick(value)
    args = [nick]
    sql = "SELECT 1 FROM users WHERE irc_nick=? COLLATE NOCASE AND disabled=0"
    if exclude_user is not None:
        sql += " AND id != ?"
        args.append(exclude_user)
    account = bool(con.execute(sql + " LIMIT 1", args).fetchone())
    channels = [r["channel"] for r in con.execute(
        "SELECT DISTINCT channel FROM live_presence WHERE nick=? COLLATE NOCASE "
        "ORDER BY channel", (nick,))]
    reason = ("another Aurora account already uses this nick" if account else
              ("currently online in " + ", ".join(channels) if channels else ""))
    return {"nick": nick, "taken": bool(account or channels),
            "account": account, "online": bool(channels),
            "channels": channels, "reason": reason,
            "scope": "Aurora accounts and tracked channel rosters"}


def person_network(con, nick, channel=None, network_id=None):
    """Resolve profile context to the supplied channel or the nick's latest one."""
    if network_id is not None:
        try:
            row = con.execute("SELECT * FROM networks WHERE id = ?",
                              (int(network_id),)).fetchone()
        except (TypeError, ValueError):
            row = None
        return dict(row) if row else None
    if channel:
        row = con.execute(
            "SELECT n.* FROM channels c JOIN networks n ON n.id=c.network_id "
            "WHERE c.name=? COLLATE NOCASE", (str(channel).lstrip("#"),)).fetchone()
        if row:
            return dict(row)
    row = con.execute(
        "SELECT net.* FROM messages m JOIN nicks ni ON ni.id=m.nick_id "
        "JOIN channels c ON c.id=m.channel_id "
        "JOIN networks net ON net.id=c.network_id "
        "WHERE ni.name=? COLLATE NOCASE ORDER BY m.ts DESC LIMIT 1", (nick,)).fetchone()
    if not row:
        row = con.execute("SELECT * FROM networks WHERE enabled=1 ORDER BY id LIMIT 1").fetchone()
    return dict(row) if row else None


def person_kind(nick, internal=None):
    """Conservative bridge hints derived only from conventional nick affixes."""
    if internal:
        return {"kind": "aurora", "label": "Aurora member"}
    if re.search(r"\[m\]$", nick, re.I) or re.match(r"^M-", nick, re.I):
        return {"kind": "matrix", "label": "Likely Matrix bridge"}
    if re.search(r"\[d\]$", nick, re.I) or re.search(r"[|_-]discord$", nick, re.I):
        return {"kind": "discord", "label": "Likely Discord bridge"}
    if re.search(r"[|_-]slack$", nick, re.I):
        return {"kind": "slack", "label": "Likely Slack bridge"}
    return {"kind": "irc", "label": "IRC nickname"}


def normalize_person_links(raw):
    if raw is None:
        return {}
    if not isinstance(raw, dict):
        raise ValueError("links must be an object")
    out = {}
    for kind in PERSON_LINK_KINDS:
        value = str(raw.get(kind) or "").strip()
        if not value:
            continue
        if len(value) > PERSON_LINK_MAX:
            raise ValueError("a profile link is too long")
        if kind == "github" and re.fullmatch(r"[A-Za-z0-9-]{1,39}", value):
            value = "https://github.com/" + value
        elif kind == "x" and re.fullmatch(r"@?[A-Za-z0-9_]{1,15}", value):
            value = "https://x.com/" + value.lstrip("@")
        elif kind == "matrix" and value.startswith("@") and ":" in value:
            value = "https://matrix.to/#/" + quote(value, safe="@:")
        elif "://" not in value:
            value = "https://" + value
        parsed = urlparse(value)
        if parsed.scheme not in ("http", "https") or not parsed.netloc:
            raise ValueError("profile links must be http or https addresses")
        out[kind] = value
    return out


def prepare_irc_command(value, channel=None):
    """Validate the deliberately read-only slash/raw command surface.

    Aurora accounts are not IRC operators, and the persistent sender assumes
    it owns its nick and joined channels. Letting arbitrary JOIN, PART, NICK,
    OPER, KILL or PRIVMSG lines through would violate those invariants. `/raw`
    therefore means raw syntax and raw replies for the same safe query set,
    rather than an unbounded socket escape hatch.
    """
    value = str(value or "").strip()
    if not value or len(value) > MAX_SEND or any(c in value for c in "\r\n\0"):
        raise ValueError("invalid IRC command")
    value = value[1:].lstrip() if value.startswith("/") else value
    bits = value.split()
    if not bits:
        raise ValueError("command required")
    if bits[0].lower() in ("raw", "quote"):
        bits = bits[1:]
        if not bits:
            raise ValueError("/raw needs an IRC command")

    name = bits[0].upper()
    args = bits[1:]
    if name in ("NS", "NICKSERV"):
        if len(args) != 2 or args[0].upper() not in ("INFO", "STATUS"):
            raise ValueError("use /ns info <nick> or /ns status <nick>")
        sub, target = args[0].upper(), clean_person_nick(args[1])
        return {"command": f"/ns {sub.lower()} {target}",
                "wire": f"PRIVMSG NickServ :{sub} {target}",
                "name": "NICKSERV", "networkCommand": "PRIVMSG"}

    if name == "MONITOR":
        raise ValueError("OFTC does not advertise MONITOR; use /ison <nick>")
    spec = IRC_COMMAND_ARGS.get(name)
    if not spec:
        raise ValueError(
            "supported commands: WHOIS, ISON, NAMES, WHO, USERHOST, WHOWAS, "
            "NickServ INFO/STATUS, MOTD, VERSION and TIME")
    if name in ("NAMES", "WHO") and not args and channel:
        args = ["#" + str(channel).lstrip("#")]
    lo, hi = spec
    if len(args) < lo or len(args) > hi:
        hint = {
            "WHOIS": "<nick>", "ISON": "<nick> [nick…]",
            "NAMES": "[#channel]", "WHO": "[#channel|mask]",
            "USERHOST": "<nick> [nick…]", "WHOWAS": "<nick> [count]",
            "MOTD": "[server]", "VERSION": "[server]", "TIME": "[server]",
        }[name]
        raise ValueError(f"use /{name.lower()} {hint}".rstrip())
    if any(len(a) > 100 or any(ord(c) < 33 for c in a) for a in args):
        raise ValueError("invalid IRC command argument")
    wire = " ".join([name] + args)
    return {"command": "/" + " ".join([name.lower()] + args),
            "wire": wire, "name": name, "networkCommand": name}


def person_profile(con, nick, *, session=None, channel=None, network_id=None):
    """Archive facts, current presence, and this reader's private annotation."""
    nick = clean_person_nick(nick)
    net = person_network(con, nick, channel=channel, network_id=network_id)
    nid = net["id"] if net else None

    stat = con.execute(
        "SELECT COUNT(*) AS count, MIN(m.ts) AS first, MAX(m.ts) AS last "
        "FROM messages m JOIN nicks n ON n.id=m.nick_id "
        "WHERE n.name=? COLLATE NOCASE", (nick,)).fetchone()
    chans = [dict(r) for r in con.execute(
        "SELECT c.name, COUNT(*) AS count, MAX(m.ts) AS last FROM messages m "
        "JOIN nicks n ON n.id=m.nick_id JOIN channels c ON c.id=m.channel_id "
        "WHERE n.name=? COLLATE NOCASE GROUP BY c.id ORDER BY last DESC", (nick,))]
    recent_events = [dict(r) for r in con.execute(
        "SELECT e.ts, e.kind, e.detail, c.name AS channel FROM events e "
        "JOIN nicks n ON n.id=e.nick_id JOIN channels c ON c.id=e.channel_id "
        "WHERE n.name=? COLLATE NOCASE ORDER BY e.ts DESC, e.id DESC LIMIT 8", (nick,))]
    event_last = recent_events[0]["ts"] if recent_events else None
    last_seen = max([x for x in (stat["last"], event_last) if x is not None], default=None)

    roster = []
    synced = False
    connected = False
    checked = None
    if nid is not None:
        connected = network_status(con, nid)["connected"]
        roster = [r["channel"].lstrip("#") for r in con.execute(
            "SELECT channel FROM live_presence WHERE network_id=? "
            "AND nick=? COLLATE NOCASE ORDER BY channel", (nid, nick))]
        synced = bool(con.execute(
            "SELECT 1 FROM live_presence_state WHERE network_id=? LIMIT 1", (nid,)).fetchone())
        checked = con.execute(
            "SELECT checked_at, online, error, requested_at FROM live_presence_checks "
            "WHERE network_id=? AND nick=? COLLATE NOCASE", (nid, nick)).fetchone()

    now = int(time.time())
    if roster and connected:
        presence = {"state": "online", "label": "Online", "source": "channel",
                    "channels": roster, "checkedAt": now}
    elif checked and checked["checked_at"] and now - checked["checked_at"] < 180:
        if checked["online"] is None:
            presence = {"state": "unknown", "label": "Status unavailable",
                        "source": "ison", "error": checked["error"],
                        "channels": [], "checkedAt": checked["checked_at"]}
        else:
            online = bool(checked["online"])
            presence = {"state": "online" if online else "offline",
                        "label": "Online" if online else "Offline",
                        "source": "ison", "channels": [],
                        "checkedAt": checked["checked_at"]}
    elif connected and synced:
        presence = {"state": "not_here", "label": "Not in tracked channels",
                    "source": "channel", "channels": [], "checkedAt": None}
    else:
        presence = {"state": "unknown", "label": "Live status unavailable",
                    "source": "none", "channels": [], "checkedAt": None}
    presence["refreshing"] = bool(checked and (
        checked["checked_at"] is None or checked["requested_at"] > checked["checked_at"]))
    presence["canCheck"] = bool(session and connected and nid is not None)

    internal = None
    annotation = {"favourite": False, "notes": "", "links": {}, "updated": None}
    row = con.execute(
        "SELECT username, avatar_at FROM users WHERE irc_nick=? COLLATE NOCASE "
        "AND disabled=0 ORDER BY COALESCE(avatar_at,0) DESC, id DESC LIMIT 1",
        (nick,)).fetchone()
    if row:
        internal = {"avatar": row["avatar_at"] or 0,
                    "username": row["username"] if session else None}
    if session:
        if nid is not None:
            row = con.execute(
                "SELECT favourite, notes, links, updated FROM person_annotations "
                "WHERE user_id=? AND network_id=? AND nick=? COLLATE NOCASE",
                (session["user_id"], nid, nick)).fetchone()
            if row:
                try:
                    links = json.loads(row["links"] or "{}")
                except ValueError:
                    links = {}
                annotation = {"favourite": bool(row["favourite"]),
                              "notes": row["notes"] or "", "links": links,
                              "updated": row["updated"]}

    return {"nick": nick, "network": ({"id": nid,
             "name": net["name"], "label": net["label"] or net["name"]} if net else None),
            "identity": person_kind(nick, internal), "internal": internal,
            "presence": presence, "lastSeen": last_seen,
            "messages": stat["count"] or 0, "firstSeen": stat["first"],
            "lastMessage": stat["last"], "channels": chans,
            "recentEvents": recent_events, "annotation": annotation}


class Handler(SimpleHTTPRequestHandler):
    # A connection that stalls mid-request should die, not pin a thread
    timeout = 20
    dbpath = None
    behind_proxy = False
    proxy_hops = 1

    def __init__(self, *a, **kw):
        super().__init__(*a, directory=str(WEB_ROOT), **kw)

    def log_message(self, fmt, *args):
        pass

    # -- helpers ----------------------------------------------------------

    def _security_headers(self):
        """Sent on every response, including static files.

        The app is a single self-contained page, so the policy can be strict
        about where things may load from and who may frame it. 'unsafe-inline'
        is unavoidable while the script and styles live in the document.
        """
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Permissions-Policy",
                         "geolocation=(), microphone=(), camera=(), interest-cohort=()")
        # Pictures posted to IRC live wherever they live. Over TLS the policy
        # stays https-only, which is what stops a page served securely pulling
        # in something that is not. Served over plain http there is no such
        # thing to protect - and refusing http pictures there means a LAN
        # install shows none at all, which is not a security win, just a
        # broken feature.
        secure = self.behind_proxy and (
            self.headers.get("X-Forwarded-Proto") == "https")
        img = "img-src 'self' data: https:" + ("" if secure else " http:")
        self.send_header("Content-Security-Policy",
                         "default-src 'self'; "
                         "script-src 'self' 'unsafe-inline'; "
                         "style-src 'self' 'unsafe-inline'; "
                         f"{img}; "
                         "media-src 'self' https:; "
                         "connect-src 'self'; "
                         "frame-ancestors 'none'; "
                         "base-uri 'none'; "
                         "form-action 'self'")
        # Only meaningful over TLS, and only safe to assert when something
        # upstream is actually terminating it.
        if self.behind_proxy and (
                self.headers.get("X-Forwarded-Proto") == "https"):
            self.send_header("Strict-Transport-Security",
                             "max-age=31536000; includeSubDomains")

    def end_headers(self):
        self._security_headers()
        super().end_headers()

    def _json(self, payload, status=200, cookie=None):
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        if cookie:
            self.send_header("Set-Cookie", cookie)
        self.end_headers()
        self.wfile.write(body)

    def _body(self, limit=MAX_BODY):
        n = int(self.headers.get("Content-Length") or 0)
        if n > limit:
            # Do not read it: that is the whole point of the limit
            self._json({"error": f"that is larger than the "
                                 f"{limit // (1024 * 1024) or 1}MB limit"}, 413)
            raise ValueError("oversized body")
        if not n:
            return {}
        try:
            return json.loads(self.rfile.read(n).decode("utf-8"))
        except (ValueError, UnicodeDecodeError):
            return {}

    def _sid(self):
        raw = self.headers.get("Cookie")
        if not raw:
            return None
        c = SimpleCookie(raw).get("sid")
        return c.value if c else None

    def _session(self):
        con = _con(self.dbpath)
        s = A.session(con, self._sid())
        if s:
            A.touch(con, s["id"])
        return s

    def _need_auth(self, csrf=True):
        """Return the session or emit an error. Callers bail out on None.

        Anonymous visitors may read everything and write nothing, so this is
        the single gate in front of every mutating endpoint.
        """
        s = self._session()
        if not s:
            self._json({"error": "sign in first"}, 401)
            return None
        # CSRF: a cookie alone must not be enough to act, since a cookie is
        # what another site can make the browser send on its own.
        if csrf and not secrets.compare_digest(
                str(self.headers.get("X-CSRF") or ""), s["csrf"]):
            self._json({"error": "stale session, reload the page"}, 403)
            return None
        return s

    def _need_owner(self, csrf=True):
        # CSRF guards state changes, so reads pass csrf=False and are judged
        # on role alone - otherwise a GET returns a misleading "stale session".
        s = self._need_auth(csrf=csrf)
        if not s:
            return None
        if s["role"] != "admin":
            self._json({"error": "admins only"}, 403)
            return None
        # Admin power is what a stolen password must not be enough to reach:
        # an admin without two-factor is locked out of the management surface
        # until they enrol. The founding owner is exempt from the hard gate -
        # the same rule that stops anyone demoting root stops this check from
        # ever locking the founder out of their own server - but the sign-in
        # flow still walks every admin, root included, through enrolment.
        con = _con(self.dbpath)
        if not A.is_root(con, s["user_id"]):
            row = con.execute("SELECT totp_enabled FROM users WHERE id = ?",
                              (s["user_id"],)).fetchone()
            if not (row and row["totp_enabled"]):
                self._json({"error": "admins need two-factor on — "
                                     "set it up to continue",
                            "totpSetup": True}, 403)
                return None
        return s

    def _ip(self):
        """The client's address, or the real one if we sit behind a proxy.

        The leftmost X-Forwarded-For entry is whatever the *client* sent, so
        trusting it lets an attacker rotate a header to dodge the login
        throttle entirely. A proxy appends the address it actually saw to the
        right, so count in from that end instead - or better, use the header
        Cloudflare sets and overwrites, which a client cannot forge.
        """
        direct = (self.client_address[0] or "") if self.client_address else ""
        if not self.behind_proxy:
            return direct
        cf = (self.headers.get("CF-Connecting-IP") or "").strip()
        if cf:
            return cf
        parts = [x.strip() for x in
                 (self.headers.get("X-Forwarded-For") or "").split(",") if x.strip()]
        hops = max(1, int(self.proxy_hops or 1))
        return parts[-hops] if len(parts) >= hops else direct

    def _secure_flag(self):
        """Secure on the session cookie once TLS is genuinely in play, so the
        id cannot leak over an accidental plain-http request."""
        proto = (self.headers.get("X-Forwarded-Proto") or "").lower()
        return "Secure; " if (self.behind_proxy and proto == "https") else ""

    def _rp_id(self):
        """WebAuthn relying-party id: the hostname, no port, no scheme."""
        host = (self.headers.get("Host") or "localhost").split(":")[0]
        return host or "localhost"

    def _origins(self):
        """Origins we accept a ceremony from. Both schemes, since a LAN
        deployment may be plain http on localhost during setup."""
        host = self.headers.get("Host") or "localhost"
        return {f"https://{host}", f"http://{host}"}

    def _is_local(self):
        return self._ip() in ("127.0.0.1", "::1", "localhost")

    # -- GET --------------------------------------------------------------

    def do_GET(self):
        url = urlparse(self.path)
        if not url.path.startswith("/api/"):
            return super().do_GET()

        p = parse_qs(url.query)
        con = _con(self.dbpath)
        try:
            # Tags are members' annotations on the archive, not part of the
            # public record: an anonymous reader gets the messages exactly as
            # IRC carried them, and nothing a signed-in member layered on top.
            # One session lookup up front decides that for every read below.
            authed = self._session()

            def public_filters():
                f = _filters(p)
                if not authed:
                    f["tags"] = []      # a tag filter must not leak by count
                return f

            def public_msgs(res):
                if not authed:
                    for m in res.get("messages", []):
                        m["tags"] = []
                return res

            if url.path == "/api/meta":
                m = dict(cached_meta(con))
                # A profile picture is part of a person's public IRC-facing
                # identity. Address it by IRC nick so anonymous readers do not
                # learn the separate Aurora account username.
                avatars = {}
                for r in con.execute(
                        "SELECT id, irc_nick, avatar_at FROM users "
                        "WHERE avatar IS NOT NULL AND irc_nick IS NOT NULL "
                        "AND disabled=0 ORDER BY avatar_at DESC, id DESC"):
                    avatars.setdefault(r["irc_nick"].lower(),
                                       {"n": r["irc_nick"],
                                        "v": r["avatar_at"] or 0})
                m["avatars"] = avatars
                if authed:
                    m["personFavorites"] = [r["nick"] for r in con.execute(
                        "SELECT nick FROM person_annotations WHERE user_id=? "
                        "AND favourite=1 ORDER BY updated DESC", (authed["user_id"],))]
                else:
                    m["tags"] = []
                return self._json(m)
            if url.path == "/api/nicks":
                # The initial metadata deliberately carries only the busiest
                # nicks.  People/search discovery is paged separately so a
                # low-volume speaker remains findable without making every
                # page load ship the entire archive directory.
                try:
                    limit = max(1, min(int(p.get("limit", ["200"])[0]), 500))
                    offset = max(0, min(int(p.get("offset", ["0"])[0]),
                                        MAX_OFFSET))
                except ValueError:
                    return self._json({"error": "bad nick page"}, 400)
                contains = p.get("contains", [""])[0].strip()[:64]
                sort = p.get("sort", ["count"])[0]
                if sort not in ("count", "name", "recent"):
                    sort = "count"
                rows = Q.nicks(con, limit=limit, offset=offset, sort=sort,
                               contains=contains or None)
                total = Q.nick_count(con, contains=contains or None)
                return self._json({"nicks": rows, "total": total,
                                   "offset": offset,
                                   "more": offset + len(rows) < total})
            if url.path == "/api/messages":
                return self._json(public_msgs(Q.search(
                    con, **public_filters(),
                    limit=int(p.get("limit", ["200"])[0]),
                    offset=min(int(p.get("offset", ["0"])[0]), MAX_OFFSET),
                    order=p.get("order", ["asc"])[0])))
            if url.path == "/api/context":
                return self._json(public_msgs(Q.context(
                    con, int(p["id"][0]), int(p.get("span", ["25"])[0]))))
            if url.path == "/api/locate":
                return self._json(Q.locate(
                    con, int(p["id"][0]), **public_filters(),
                    order=p.get("order", ["asc"])[0],
                    in_channel=p.get("in_channel", ["0"])[0] == "1"))
            if url.path == "/api/activity":
                res = Q.activity(con, **public_filters(),
                                 bucket=p.get("bucket", ["month"])[0])
                return self._json({"months": [
                    {"month": b["bucket"], "count": b["count"]} for b in res["buckets"]]})
            if url.path == "/api/tags":
                return self._json({"tags": Q.tags(con) if authed else []})
            if url.path == "/api/nick/check":
                try:
                    return self._json(irc_nick_state(
                        con, p.get("nick", [""])[0],
                        exclude_user=(authed["user_id"] if authed and
                                      p.get("excludeSelf", ["0"])[0] == "1"
                                      else None)))
                except ValueError as exc:
                    return self._json({"error": str(exc), "taken": False}, 400)
            if url.path == "/api/searches":
                if not authed:
                    return self._json({"searches": []})
                return self._json({"searches": [dict(r) for r in con.execute(
                    "SELECT name, query, extra, created, used FROM saved_searches "
                    "ORDER BY used DESC, name")]})
            if url.path == "/api/avatar":
                # IRC-nick URLs are public profile pictures. Username URLs are
                # retained for account/settings surfaces and remain private.
                by_nick = p.get("n", [""])[0]
                if by_nick:
                    row = con.execute(
                        "SELECT avatar, avatar_type, avatar_at FROM users "
                        "WHERE irc_nick=? COLLATE NOCASE AND disabled=0 "
                        "ORDER BY COALESCE(avatar_at,0) DESC, id DESC LIMIT 1",
                        (by_nick,)).fetchone()
                elif authed:
                    row = con.execute(
                        "SELECT avatar, avatar_type, avatar_at FROM users "
                        "WHERE username = ? COLLATE NOCASE",
                        (p.get("u", [""])[0],)).fetchone()
                else:
                    return self._json({"error": "avatar nick required"}, 400)
                if not row or not row["avatar"]:
                    return self._json({"error": "no picture"}, 404)
                self.send_response(200)
                self.send_header("Content-Type", row["avatar_type"] or "image/jpeg")
                self.send_header("Content-Length", str(len(row["avatar"])))
                self.send_header("Cache-Control", ("public" if by_nick else "private")
                                 + ", max-age=86400")
                self.end_headers()
                self.wfile.write(row["avatar"])
                return
            if url.path == "/api/prefs":
                s = self._need_auth(csrf=False)
                if not s:
                    return
                row = con.execute("SELECT prefs, prefs_at FROM users WHERE id = ?",
                                  (s["user_id"],)).fetchone()
                prefs = None
                if row and row["prefs"]:
                    try:
                        prefs = json.loads(row["prefs"])
                    except ValueError:
                        prefs = None
                return self._json({"prefs": prefs,
                                   "at": (row["prefs_at"] or 0) if row else 0})
            if url.path == "/api/events":
                # Fetched for a visible window, not paged, so message offsets
                # (and jump-to-message) stay exact.
                return self._json({"events": EV.in_range(
                    con,
                    since=Q.as_ts(p.get("from", ["0"])[0]) or 0,
                    until=Q.as_ts(p.get("to", ["0"])[0], end_of_day=True) or 0,
                    channels=p.get("channel", []),
                    nicks=p.get("nick", []),
                    limit=int(p.get("limit", ["4000"])[0]))})
            if url.path == "/api/person":
                try:
                    profile = person_profile(
                        con, p.get("nick", [""])[0], session=authed,
                        channel=p.get("channel", [None])[0],
                        network_id=p.get("network", [None])[0])
                except ValueError as exc:
                    return self._json({"error": str(exc)}, 400)
                return self._json(profile)
            if url.path == "/api/command/status":
                s = self._need_auth(csrf=False)
                if not s:
                    return
                try:
                    cid = int(p.get("id", ["0"])[0])
                except ValueError:
                    return self._json({"error": "bad id"}, 400)
                row = con.execute(
                    "SELECT command, created, sent_at, finished_at, response, error "
                    "FROM irc_commands WHERE id=? AND user_id=?",
                    (cid, s["user_id"])).fetchone()
                if not row:
                    return self._json({"state": "unknown"})
                if row["finished_at"] is None:
                    return self._json({"state": "running" if row["sent_at"] else "queued",
                                       "command": row["command"],
                                       "waited": int(time.time()) - row["created"]})
                try:
                    replies = json.loads(row["response"] or "[]")
                except ValueError:
                    replies = []
                return self._json({"state": "failed" if row["error"] else "done",
                                   "command": row["command"], "replies": replies,
                                   "error": row["error"], "at": row["finished_at"]})
            if url.path == "/api/send/status":
                # What actually happened to a queued line. The client used to
                # guess with a timer, which called a slow-but-fine send a
                # failure; a cold connection legitimately takes ~12s.
                s = self._need_auth(csrf=False)
                if not s:
                    return
                try:
                    mid = int(p.get("id", ["0"])[0])
                except ValueError:
                    return self._json({"error": "bad id"}, 400)
                row = con.execute(
                    "SELECT sent_at, error, created FROM outbox "
                    "WHERE id = ? AND user_id = ?", (mid, s["user_id"])).fetchone()
                if not row:
                    return self._json({"state": "unknown"})
                if row["error"]:
                    return self._json({"state": "failed", "error": row["error"]})
                if row["sent_at"] is None:
                    return self._json({"state": "queued",
                                       "waited": int(time.time()) - row["created"]})
                return self._json({"state": "sent", "at": row["sent_at"]})

            if url.path == "/api/session":
                s = self._session()
                user = None
                if s:
                    u = con.execute(
                        "SELECT totp_enabled, totp_declined, avatar_at, prefs_at "
                        "FROM users WHERE id = ?", (s["user_id"],)).fetchone()
                    user = {"name": s["username"], "role": s["role"],
                            "nick": s["irc_nick"],
                            "totp": bool(u["totp_enabled"]),
                            "totpDeclined": bool(u["totp_declined"]),
                            "owner": A.is_root(con, s["user_id"]),
                            "avatar": u["avatar_at"] or 0,
                            "prefsAt": u["prefs_at"] or 0}
                return self._json({
                    "signedIn": bool(s),
                    "user": user,
                    "nick": s["irc_nick"] if s else None,
                    "csrf": s["csrf"] if s else None,
                    "setupNeeded": not A.any_users(con),
                    "live": live_status(con),
                })
            if url.path == "/api/users":
                if not self._need_owner(csrf=False):
                    return
                root = A.root_id(con)
                return self._json({"users": [
                    {"name": r["username"], "role": r["role"], "nick": r["irc_nick"],
                     "totp": bool(r["totp_enabled"]), "disabled": bool(r["disabled"]),
                     "owner": r["id"] == root, "avatar": r["avatar_at"] or 0,
                     "joinMethod": r["join_method"] or A.JOIN_MANUAL,
                     "created": r["created"], "lastSeen": r["last_seen"]}
                    for r in con.execute("SELECT * FROM users ORDER BY role, username")]})
            if url.path == "/api/users/detail":
                # Provenance for one account, behind a button rather than in
                # the list: useful when you need it, clutter when you do not.
                if not self._need_owner(csrf=False):
                    return
                detail = A.user_detail(con, p.get("username", [""])[0])
                if not detail:
                    return self._json({"error": "no such user"}, 404)
                return self._json(detail)
            if url.path == "/api/history":
                s = self._session()
                if not s:
                    # History is an account feature; anonymous readers get none
                    return self._json({"history": []})
                return self._json({"history": A.search_history(
                    con, s["user_id"],
                    limit=int(p.get("limit", ["12"])[0]))})
            if url.path == "/api/invites":
                if not self._need_owner(csrf=False):
                    return
                # Dead links are listed too: "who came in on that pass" is the
                # question an owner asks *after* the pass has been used up.
                return self._json({"invites": A.invites(con, include_dead=True),
                                   "expiresHours": A.INVITE_HOURS,
                                   "maxUses": A.MAX_PASS_USES})
            if url.path == "/api/sessions":
                s = self._need_auth(csrf=False)
                if not s:
                    return
                rows = con.execute(
                    "SELECT id, created, last_seen, expires, ip, agent FROM sessions "
                    "WHERE user_id = ? ORDER BY last_seen DESC", (s["user_id"],))
                return self._json({"sessions": [
                    {**dict(r), "current": r["id"] == s["id"],
                     "id": r["id"][:8]} for r in rows]})
            if url.path == "/api/authlog":
                if not self._need_owner(csrf=False):
                    return
                return self._json({"log": A.recent_log(con, 120)})
            if url.path == "/api/networks":
                if not self._need_owner(csrf=False):
                    return
                nets = db.networks(con)
                for n in nets:
                    # Only the channels actually joined. Listing de-archived
                    # ones here made it look like the archivist was in a
                    # channel it had left.
                    n["channels"] = db.network_channels(con, n["id"])
                    n["paused"] = [c for c in db.network_channels(
                        con, n["id"], archived_only=False) if c not in n["channels"]]
                    n.pop("sasl_pass", None)      # never hand secrets back out
                return self._json({"networks": nets})
            if url.path == "/api/import/formats":
                if not self._need_owner(csrf=False):
                    return
                return self._json({"formats": [{"key": k, "label": l}
                                               for k, l in BF.FORMATS]})
            if url.path == "/api/fetch/image":
                return self.proxy_image(p)
            if url.path == "/api/stream":
                return self.stream(con, p)
        except (KeyError, ValueError, TypeError):
            return self._json({"error": "bad request"}, 400)
        except Exception as exc:
            print(f"[error] GET {url.path}: {exc}")
            return self._json({"error": "server error"}, 500)
        self._json({"error": "not found"}, 404)

    def do_import(self, con, body, *, commit, ip, who):
        """Take history in from a URL or an uploaded log.

        Both doors lead to ircarchive.backfill, which is what the command line
        uses, so a log imported here is held to the same rules as one imported
        with `./archive.py import` - the same formats, the same idea of what
        counts as speech, the same dedupe key. Nothing is parsed twice, and
        nothing is parsed differently.
        """
        fmt = str(body.get("format") or "auto")
        if fmt not in BF.FORMAT_KEYS:
            return self._json({"error": "unknown log format"}, 400)
        channel = str(body.get("channel") or "").strip().lstrip("#").lower()
        if channel and (any(c.isspace() for c in channel) or len(channel) > 64):
            return self._json({"error": "that is not a channel name"}, 400)
        year = body.get("year")
        try:
            year = int(year) if year else None
        except (TypeError, ValueError):
            return self._json({"error": "year must be a number"}, 400)
        if year is not None and not (1988 <= year <= 2100):
            return self._json({"error": "that year is not plausible"}, 400)
        events = bool(body.get("events"))

        docs, skipped = [], []
        source = str(body.get("source") or "text")
        if source == "url":
            try:
                docs, skipped = BF.documents_from_url(
                    str(body.get("url") or "").strip(),
                    follow=bool(body.get("follow")))
            except F.FetchError as exc:
                return self._json({"error": str(exc)}, 400)
        else:
            for doc in (body.get("documents") or [])[:200]:
                name = str((doc or {}).get("name") or "log.txt")[:160]
                text = (doc or {}).get("text")
                if isinstance(text, str) and text.strip():
                    docs.append((name, text))
        if not docs:
            return self._json({"error": "nothing to read in that"}, 400)

        try:
            report = BF.import_documents(
                con, docs, fmt=fmt, channel=channel or None, year=year,
                events=events, commit=commit,
                source="url" if source == "url" else "import")
        except sqlite3.DatabaseError as exc:
            return self._json({"error": f"the archive refused it: {exc}"}, 500)
        report["skipped"] = skipped
        if commit:
            A.log(con, "import", username=who, ip=ip,
                  detail=f"{report['added']} of {report['seen']} from {source}")
            _meta_cache["key"] = None          # counts and channels have moved
        return self._json(report)

    def proxy_image(self, p):
        """Hand back a picture from elsewhere, through this server.

        The page is locked to ``connect-src 'self'``, so script cannot reach
        cross-origin bytes at all - which is why copying a picture to the
        clipboard, saving it, or reading its real size and type has to come
        back through here. Display still goes straight to the host, so this
        costs nothing on an ordinary read.

        A session is required: an open image proxy is bandwidth for anyone who
        finds it. Everything is served as an attachment with the type the
        remote actually sent, checked against a list of things browsers draw -
        so nothing served from this origin can be a document.
        """
        s = self._need_auth(csrf=False)      # a GET, so nothing to forge
        if not s:
            return
        target = p.get("url", [""])[0]
        try:
            res = F.fetch(target, timeout=15, max_bytes=MAX_IMAGE_BYTES,
                          accept="image/*")
        except F.FetchError as exc:
            return self._json({"error": str(exc)}, 400)
        ctype = (res["headers"].get("content-type") or "").split(";")[0].strip().lower()
        if ctype not in IMAGE_TYPES:
            return self._json(
                {"error": f"that is {ctype or 'of unknown type'}, not a picture "
                          f"this can hand back"}, 415)
        name = F.filename_of(res["url"], "image")
        if p.get("meta", [""])[0] == "1":
            return self._json({"ok": True, "type": ctype, "bytes": len(res["body"]),
                               "filename": name, "url": res["url"]})
        body = res["body"]
        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        # Always an attachment: a picture fetched through here is never a page
        self.send_header("Content-Disposition",
                         f'attachment; filename="{name}"')
        self.send_header("Cache-Control", "private, max-age=300")
        self.end_headers()
        try:
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError):
            pass

    def stream(self, con, p):
        """Server-sent events: push new messages as the live process records them."""
        global _streams
        with _streams_lock:
            if _streams >= MAX_STREAMS:
                return self._json({"error": "too many live connections"}, 503)
            _streams += 1
        try:
            self._stream_loop(con, p)
        finally:
            with _streams_lock:
                _streams -= 1

    def _stream_loop(self, con, p):
        try:
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream; charset=utf-8")
            self.send_header("Cache-Control", "no-cache, no-transform")
            self.send_header("Connection", "close")
            self.send_header("X-Accel-Buffering", "no")
            self.end_headers()
        except OSError:
            return

        since = p.get("since", [""])[0]
        last = int(since) if str(since).isdigit() else con.execute(
            "SELECT COALESCE(MAX(id), 0) FROM messages").fetchone()[0]
        # Decided once at connect time: tags ride along for members only,
        # matching every other read.
        authed = bool(A.session(con, self._sid()))

        deadline = time.time() + STREAM_SECONDS
        idle = 0
        try:
            self.wfile.write(f"event: hello\ndata: {json.dumps({'last': last})}\n\n"
                             .encode("utf-8"))
            self.wfile.flush()
            while time.time() < deadline:
                rows = con.execute(
                    f"{Q.SELECT_COLS} WHERE m.id > ? ORDER BY m.id LIMIT 200",
                    (last,)).fetchall()
                if rows:
                    last = rows[-1]["id"]
                    msgs = [dict(r) for r in rows]
                    if authed:
                        msgs = Q.attach_tags(con, msgs)
                    body = json.dumps(msgs, ensure_ascii=False)
                    self.wfile.write(f"event: messages\ndata: {body}\n\n".encode("utf-8"))
                    self.wfile.flush()
                    idle = 0
                else:
                    idle += 1
                    if idle >= 20:
                        self.wfile.write(b": keepalive\n\n")
                        self.wfile.flush()
                        idle = 0
                time.sleep(0.5)
        except (BrokenPipeError, ConnectionResetError, OSError):
            pass

    # -- POST -------------------------------------------------------------

    def mcp(self, con, body):
        """JSON-RPC for remote agents, authenticated by bearer token.

        Deliberately a separate door from the browser API: no cookies, no CSRF,
        no session - a token and nothing else. It shares the tool definitions
        with the stdio server and, like it, reads through a mode=ro connection,
        so an agent cannot write to the archive however it authenticates.
        """
        ip = self._ip()
        auth_hdr = self.headers.get("Authorization") or ""
        token = auth_hdr[7:].strip() if auth_hdr[:7].lower() == "bearer " else ""

        # Check the token before the backoff, not after. Looking one up is a
        # hash and an index hit, so it is safe to do first - and doing it last
        # meant a blocked address could never present a good token to clear
        # itself, which is precisely the NAT case the backoff is meant to
        # tolerate. Only failures are rate limited.
        who = A.token_owner(con, token) if token else None
        if not who:
            wait = A.throttle_check(con, ip)
            if wait:
                return self._json({"error": f"rate limited, wait {wait}s"}, 429)
            A.throttle_fail(con, ip)
            A.log(con, "mcp_denied", ip=ip)
            self.send_response(401)
            self.send_header("WWW-Authenticate", 'Bearer realm="irc-archive"')
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(b'{"error":"a valid bearer token is required"}')
            return

        # A good token clears the backoff, so a couple of bad requests cannot
        # lock out the legitimate agents sharing an address behind NAT.
        A.throttle_clear(con, ip)

        if _mcp["archive"] is None:
            _mcp["archive"] = Archive(self.dbpath)

        method, rid = body.get("method"), body.get("id")
        if method == "initialize":
            asked = (body.get("params") or {}).get("protocolVersion")
            res = {"protocolVersion": asked or PROTOCOL_VERSION,
                   "capabilities": {"tools": {}}, "serverInfo": SERVER_INFO}
        elif method in ("notifications/initialized", "initialized"):
            return self._json({})            # notification, nothing to answer
        elif method == "ping":
            res = {}
        elif method == "tools/list":
            res = {"tools": TOOLS}
        elif method == "tools/call":
            params = body.get("params") or {}
            try:
                payload = _mcp["archive"].call(params.get("name"),
                                               params.get("arguments") or {})
                res = {"content": [{"type": "text",
                                    "text": json.dumps(payload, ensure_ascii=False)}]}
            except Exception as exc:
                res = {"content": [{"type": "text", "text": f"error: {exc}"}],
                       "isError": True}
        else:
            return self._json({"jsonrpc": "2.0", "id": rid,
                               "error": {"code": -32601,
                                         "message": f"method not found: {method}"}})
        return self._json({"jsonrpc": "2.0", "id": rid, "result": res})

    def do_POST(self):
        url = urlparse(self.path)
        con = _con(self.dbpath)
        # An uploaded log is the payload rather than a few fields, so it gets a
        # bigger allowance - but only after we know who is sending it. Reading
        # sixteen megabytes from a stranger is not something to be talked into.
        importing = url.path.startswith("/api/import")
        if importing and not self._need_owner():
            return
        # A profile picture or a synced background is an image payload, so
        # these two get a bigger allowance - after proving who is sending it,
        # for the same reason imports do.
        bulky = url.path in ("/api/me/avatar", "/api/prefs")
        if bulky and not self._need_auth():
            return
        try:
            body = self._body(MAX_IMPORT_BODY if importing
                              else MAX_MEDIA_BODY if bulky else MAX_BODY)
        except ValueError:
            return          # _body already answered 413
        try:
            # ---- remote MCP for agents ----
            if url.path == "/mcp":
                return self.mcp(con, body)

            # ---- auth ----
            ip = self._ip()

            def start_session(uid, username):
                A.purge_expired(con)
                sid, csrf = A.new_session(
                    con, uid, ip=ip, agent=self.headers.get("User-Agent"))
                A.log(con, "login_ok", username=username, ip=ip)
                s = A.session(con, sid)
                u = con.execute(
                    "SELECT totp_enabled, totp_declined, avatar_at, prefs_at "
                    "FROM users WHERE id = ?", (uid,)).fetchone()
                return self._json(
                    {"signedIn": True, "csrf": csrf,
                     "user": {"name": s["username"], "role": s["role"],
                              "nick": s["irc_nick"],
                              "totp": bool(u["totp_enabled"]),
                              "totpDeclined": bool(u["totp_declined"]),
                              "owner": A.is_root(con, uid),
                              "avatar": u["avatar_at"] or 0,
                              "prefsAt": u["prefs_at"] or 0},
                     "nick": s["irc_nick"], "live": live_status(con)},
                    cookie=(f"sid={sid}; Path=/; SameSite=Strict; HttpOnly; "
                            f"{self._secure_flag()}"
                            f"Max-Age={A.SESSION_DAYS * 86400}"))

            if url.path == "/api/setup":
                # First run only: claims the archive as owner. Once a user
                # exists this is permanently closed.
                if A.any_users(con):
                    return self._json({"error": "already set up"}, 409)
                try:
                    nick = normalize_irc_nick(body.get("nick"), body.get("username"))
                    nick_state = irc_nick_state(con, nick)
                    if nick_state["taken"] and not body.get("claimNick"):
                        return self._json({"error": "that IRC nick appears to be in use",
                                           "nickConflict": nick_state}, 409)
                    uid = A.create_user(con, body.get("username"),
                                        str(body.get("password", "")), role="admin",
                                        irc_nick=nick,
                                        join_method=A.JOIN_SETUP)
                except ValueError as exc:
                    return self._json({"error": str(exc)}, 400)
                # The wizard names the server before the account exists, so it
                # arrives here rather than through /api/appname (owners only).
                app_name = str(body.get("appName") or "").strip()[:48]
                if app_name:
                    db.setting(con, "app_name", app_name)
                # Remember who founded this archive; they stay root forever
                db.setting(con, "root_user_id", uid)
                A.log(con, "setup", username=str(body.get("username")), ip=ip)
                print(f"[auth] owner account created from {ip}")
                return start_session(uid, str(body.get("username")))

            if url.path == "/api/login":
                wait = A.throttle_check(con, ip)
                if wait:
                    return self._json(
                        {"error": f"too many attempts, wait {wait}s"}, 429)
                u = A.user_by_name(con, body.get("username"))
                good = u and not u["disabled"] and A.verify_password(
                    u["password"], str(body.get("password", "")))
                if good and u["totp_enabled"]:
                    if not A.totp_check(u["totp_secret"], body.get("totp")):
                        if not str(body.get("totp") or ""):
                            return self._json({"error": "code required",
                                               "totpRequired": True}, 401)
                        good = False
                if not good:
                    delay = A.throttle_fail(con, ip)
                    A.log(con, "login_fail", username=str(body.get("username")), ip=ip)
                    time.sleep(0.4)          # blunt the edge off guessing
                    return self._json({"error": "wrong username or password"
                                       + (f"; locked for {delay}s" if delay else "")}, 403)
                A.throttle_clear(con, ip)
                # New sid on every login, so a leaked pre-login id is worthless
                return start_session(u["id"], u["username"])

            if url.path == "/api/reset/complete":
                # Anonymous by nature: the person clicking a reset link is the
                # person who lost their password. Throttled like login, since
                # the token is all that stands between a guess and an account.
                wait = A.throttle_check(con, ip)
                if wait:
                    return self._json(
                        {"error": f"too many attempts, wait {wait}s"}, 429)
                try:
                    uid, username = A.use_reset(con, str(body.get("token", "")),
                                                str(body.get("password", "")))
                except ValueError as exc:
                    A.throttle_fail(con, ip)
                    A.log(con, "reset_fail", ip=ip, detail=str(exc))
                    return self._json({"error": str(exc)}, 400)
                A.throttle_clear(con, ip)
                A.log(con, "reset_ok", username=username, ip=ip)
                return start_session(uid, username)

            if url.path == "/api/redeem":
                try:
                    nick = normalize_irc_nick(body.get("nick"), body.get("username"))
                    nick_state = irc_nick_state(con, nick)
                    if nick_state["taken"] and not body.get("claimNick"):
                        return self._json({"error": "that IRC nick appears to be in use",
                                           "nickConflict": nick_state}, 409)
                    uid = A.redeem_invite(con, body.get("token"),
                                          body.get("username"),
                                          str(body.get("password", "")), irc_nick=nick)
                except ValueError as exc:
                    A.log(con, "redeem_fail", ip=ip, detail=str(exc))
                    return self._json({"error": str(exc)}, 400)
                A.log(con, "redeem_ok", username=str(body.get("username")), ip=ip)
                return start_session(uid, str(body.get("username")))

            if url.path == "/api/signout":
                sid = self._sid()
                s = A.session(con, sid)
                if s:
                    A.log(con, "logout", username=s["username"], ip=ip)
                if sid:
                    A.drop_session(con, sid)
                return self._json({"signedIn": False}, cookie="sid=; Path=/; Max-Age=0")

            # ---- profile ----
            if url.path == "/api/me":
                s = self._need_auth()
                if not s:
                    return
                if body.get("password"):
                    if not A.verify_password(
                            con.execute("SELECT password FROM users WHERE id=?",
                                        (s["user_id"],)).fetchone()["password"],
                            str(body.get("current", ""))):
                        return self._json({"error": "current password required"}, 403)
                    try:
                        A.set_password(con, s["user_id"], str(body["password"]))
                    except ValueError as exc:
                        return self._json({"error": str(exc)}, 400)
                    A.drop_user_sessions(con, s["user_id"], keep=s["id"])
                    A.log(con, "password_change", username=s["username"], ip=ip)
                if body.get("nick") is not None:
                    try:
                        nick = normalize_irc_nick(body["nick"])
                        nick_state = irc_nick_state(con, nick, exclude_user=s["user_id"])
                    except ValueError as exc:
                        return self._json({"error": str(exc)}, 400)
                    if nick_state["taken"] and not body.get("claimNick"):
                        return self._json({"error": "that IRC nick appears to be in use",
                                           "nickConflict": nick_state}, 409)
                    con.execute("UPDATE users SET irc_nick = ? WHERE id = ?",
                                (nick, s["user_id"]))
                if body.get("username"):
                    new = str(body["username"]).strip()
                    if not A.USERNAME_RE.match(new):
                        return self._json(
                            {"error": "2-32 chars: letters, digits, . _ -"}, 400)
                    clash = A.user_by_name(con, new)
                    if clash and clash["id"] != s["user_id"]:
                        return self._json({"error": "that username is taken"}, 409)
                    con.execute("UPDATE users SET username = ? WHERE id = ?",
                                (new, s["user_id"]))
                    A.log(con, "username_change", username=new, ip=ip,
                          detail=f"was {s['username']}")
                cur = con.execute("SELECT username, irc_nick, role FROM users "
                                  "WHERE id = ?", (s["user_id"],)).fetchone()
                return self._json({"ok": True, "user": {
                    "name": cur["username"], "nick": cur["irc_nick"],
                    "role": cur["role"]}})

            if url.path == "/api/me/avatar":
                s = self._need_auth()
                if not s:
                    return
                if body.get("clear"):
                    con.execute("UPDATE users SET avatar = NULL, avatar_type = NULL, "
                                "avatar_at = NULL WHERE id = ?", (s["user_id"],))
                    return self._json({"ok": True, "avatar": 0})
                # The client sends a small square crop as a data URL. Trust
                # none of it: the declared type must match what the bytes
                # actually are, and the decoded size is capped.
                m = re.match(r"data:image/(jpeg|png|webp);base64,([A-Za-z0-9+/=\s]+)$",
                             str(body.get("image", "")))
                if not m:
                    return self._json({"error": "send a JPEG, PNG or WebP"}, 400)
                try:
                    raw = base64.b64decode(m.group(2), validate=False)
                except (ValueError, binascii.Error):
                    return self._json({"error": "that image did not decode"}, 400)
                if not raw or len(raw) > AVATAR_MAX_BYTES:
                    return self._json({"error": "pictures are capped at "
                                       f"{AVATAR_MAX_BYTES // 1024}KB"}, 400)
                kind = m.group(1)
                genuine = (
                    (kind == "jpeg" and raw[:3] == b"\xff\xd8\xff") or
                    (kind == "png" and raw[:8] == b"\x89PNG\r\n\x1a\n") or
                    (kind == "webp" and raw[:4] == b"RIFF" and raw[8:12] == b"WEBP"))
                if not genuine:
                    return self._json({"error": "that is not the image type "
                                                "it claims to be"}, 400)
                now = int(time.time())
                con.execute("UPDATE users SET avatar = ?, avatar_type = ?, "
                            "avatar_at = ? WHERE id = ?",
                            (raw, f"image/{kind}", now, s["user_id"]))
                A.log(con, "avatar_set", username=s["username"], ip=ip)
                return self._json({"ok": True, "avatar": now})

            if url.path == "/api/prefs":
                s = self._need_auth()
                if not s:
                    return
                prefs = body.get("prefs")
                if not isinstance(prefs, dict):
                    return self._json({"error": "prefs must be an object"}, 400)
                blob = json.dumps(prefs, ensure_ascii=False)
                if len(blob) > PREFS_MAX_LEN:
                    return self._json({"error": "those settings are too large "
                                                "to sync — a smaller background "
                                                "image should fix it"}, 400)
                now = int(time.time())
                con.execute("UPDATE users SET prefs = ?, prefs_at = ? WHERE id = ?",
                            (blob, now, s["user_id"]))
                return self._json({"ok": True, "at": now})

            if url.path == "/api/me/totp":
                s = self._need_auth()
                if not s:
                    return
                act = str(body.get("action", ""))
                if act == "begin":
                    sec = A.totp_secret()
                    con.execute("UPDATE users SET totp_secret = ?, totp_enabled = 0 "
                                "WHERE id = ?", (sec, s["user_id"]))
                    return self._json({"secret": sec,
                                       "uri": A.totp_uri(s["username"], sec)})
                if act == "confirm":
                    row = con.execute("SELECT totp_secret FROM users WHERE id = ?",
                                      (s["user_id"],)).fetchone()
                    if not A.totp_check(row["totp_secret"], body.get("code")):
                        return self._json({"error": "that code did not match"}, 400)
                    con.execute("UPDATE users SET totp_enabled = 1, "
                                "totp_declined = 0 WHERE id = ?", (s["user_id"],))
                    A.log(con, "totp_on", username=s["username"], ip=ip)
                    return self._json({"enabled": True})
                if act == "disable":
                    if s["role"] == "admin":
                        return self._json(
                            {"error": "admins must keep two-factor on"}, 403)
                    con.execute("UPDATE users SET totp_enabled = 0, totp_secret = NULL "
                                "WHERE id = ?", (s["user_id"],))
                    A.log(con, "totp_off", username=s["username"], ip=ip)
                    return self._json({"enabled": False})
                if act == "decline":
                    # "Not now" from the sign-in flow. Users may say it once
                    # and not be nagged again; admins do not get the choice.
                    if s["role"] == "admin":
                        return self._json(
                            {"error": "admins need two-factor on"}, 403)
                    con.execute("UPDATE users SET totp_declined = 1 WHERE id = ?",
                                (s["user_id"],))
                    return self._json({"declined": True})
                return self._json({"error": "unknown action"}, 400)

            if url.path == "/api/me/passkey":
                s = self._need_auth()
                if not s:
                    return
                act = str(body.get("action", ""))
                if act == "begin":
                    ch = A.issue_challenge(con, "register", s["user_id"])
                    return self._json({
                        "challenge": ch, "rpId": self._rp_id(),
                        "rpName": db.setting(con, "app_name") or "AuroraIRC",
                        "userId": W.b64u(str(s["user_id"]).encode()),
                        "userName": s["username"],
                        "exclude": [c["cred_id"] for c in A.passkeys(con, s["user_id"])],
                    })
                if act == "finish":
                    row = A.take_challenge(con, body.get("challenge"), "register")
                    if not row or row["user_id"] != s["user_id"]:
                        return self._json({"error": "that request expired, try again"}, 400)
                    try:
                        cid, key, count = W.register(
                            W.unb64u(body.get("clientDataJSON")),
                            W.unb64u(body.get("attestationObject")),
                            row["challenge"], self._origins(), self._rp_id())
                    except Exception as exc:
                        A.log(con, "passkey_fail", username=s["username"], ip=ip,
                              detail=str(exc))
                        return self._json({"error": str(exc)}, 400)
                    try:
                        con.execute(
                            "INSERT INTO credentials(user_id, cred_id, public_key, "
                            "sign_count, label, created) VALUES (?,?,?,?,?,?)",
                            (s["user_id"], W.b64u(cid), key, count,
                             str(body.get("label") or "Passkey")[:40], int(time.time())))
                    except sqlite3.IntegrityError:
                        return self._json({"error": "that passkey is already registered"}, 409)
                    A.log(con, "passkey_add", username=s["username"], ip=ip)
                    return self._json({"passkeys": A.passkeys(con, s["user_id"])})
                if act == "list":
                    return self._json({"passkeys": A.passkeys(con, s["user_id"])})
                if act == "delete":
                    con.execute("DELETE FROM credentials WHERE id = ? AND user_id = ?",
                                (int(body.get("id", 0)), s["user_id"]))
                    A.log(con, "passkey_remove", username=s["username"], ip=ip)
                    return self._json({"passkeys": A.passkeys(con, s["user_id"])})
                return self._json({"error": "unknown action"}, 400)

            if url.path == "/api/passkey/begin":
                # No username needed: a discoverable credential identifies itself
                ch = A.issue_challenge(con, "login")
                return self._json({"challenge": ch, "rpId": self._rp_id()})

            if url.path == "/api/passkey/finish":
                wait = A.throttle_check(con, ip)
                if wait:
                    return self._json({"error": f"too many attempts, wait {wait}s"}, 429)
                row = A.take_challenge(con, body.get("challenge"), "login")
                if not row:
                    return self._json({"error": "that request expired, try again"}, 400)
                cred = A.credential(con, body.get("credentialId"))
                if not cred or cred["disabled"]:
                    A.throttle_fail(con, ip)
                    return self._json({"error": "unknown passkey"}, 403)
                try:
                    count = W.authenticate(
                        W.unb64u(body.get("clientDataJSON")),
                        W.unb64u(body.get("authenticatorData")),
                        W.unb64u(body.get("signature")),
                        cred["public_key"], row["challenge"], self._origins(),
                        self._rp_id(), cred["sign_count"])
                except Exception as exc:
                    A.throttle_fail(con, ip)
                    A.log(con, "passkey_login_fail", username=cred["username"],
                          ip=ip, detail=str(exc))
                    return self._json({"error": str(exc)}, 403)
                con.execute("UPDATE credentials SET sign_count = ?, last_used = ? "
                            "WHERE id = ?", (count, int(time.time()), cred["id"]))
                A.throttle_clear(con, ip)
                return start_session(cred["user_id"], cred["username"])

            if url.path == "/api/tokens":
                s = self._need_auth()
                if not s:
                    return
                act = str(body.get("action", "list"))
                if act == "create":
                    tok = A.mint_token(con, s["user_id"], body.get("name"))
                    A.log(con, "token_create", username=s["username"], ip=ip,
                          detail=str(body.get("name")))
                    # Shown once; only its hash is kept
                    return self._json({"token": tok, "tokens": A.tokens(con, s["user_id"])})
                if act == "revoke":
                    A.revoke_token(con, s["user_id"], body.get("id", 0))
                    A.log(con, "token_revoke", username=s["username"], ip=ip)
                return self._json({"tokens": A.tokens(con, s["user_id"])})

            if url.path == "/api/sessions/revoke":
                s = self._need_auth()
                if not s:
                    return
                if body.get("all"):
                    A.drop_user_sessions(con, s["user_id"], keep=s["id"])
                    return self._json({"ok": True})
                prefix = str(body.get("id", "")).strip()
                if not prefix:
                    return self._json({"error": "session id required"}, 400)
                for r in con.execute("SELECT id FROM sessions WHERE user_id = ?",
                                     (s["user_id"],)):
                    if r["id"].startswith(prefix) and r["id"] != s["id"]:
                        A.drop_session(con, r["id"])
                return self._json({"ok": True})

            # ---- owner: users and invites ----
            if url.path == "/api/invites":
                s = self._need_owner()
                if not s:
                    return
                role = str(body.get("role", "user"))
                uses = body.get("uses", 1)
                try:
                    token = A.create_invite(con, s["user_id"], role=role,
                                            uses=uses,
                                            label=body.get("label"))
                except ValueError as exc:
                    return self._json({"error": str(exc)}, 400)
                A.log(con, "invite_created", username=s["username"], ip=ip,
                      detail=f"{role} x{int(uses or 1)}")
                return self._json({"token": token,
                                   "url": f"/#invite={token}",
                                   "role": role, "uses": int(uses or 1),
                                   "expiresHours": A.INVITE_HOURS,
                                   "invites": A.invites(con, include_dead=True)})

            if url.path == "/api/users/reset":
                s = self._need_owner()
                if not s:
                    return
                target = A.user_by_name(con, body.get("username"))
                if not target:
                    return self._json({"error": "no such user"}, 404)
                # A reset link is a takeover of the account it opens, so the
                # founder's account only ever resets by the founder's own hand.
                if A.is_root(con, target["id"]) and not A.is_root(con, s["user_id"]):
                    return self._json(
                        {"error": "only the owner can reset the owner"}, 403)
                token = A.create_reset(con, target["id"], by_uid=s["user_id"])
                A.log(con, "reset_created", username=s["username"], ip=ip,
                      detail=f"for {target['username']}")
                return self._json({"token": token,
                                   "url": f"/#reset={token}",
                                   "username": target["username"],
                                   "expiresHours": A.RESET_HOURS})

            if url.path == "/api/invites/revoke":
                s = self._need_owner()
                if not s:
                    return
                token = str(body.get("token", "")).strip()
                if not token:
                    return self._json({"error": "token required"}, 400)
                A.revoke_invite(con, token)
                A.log(con, "invite_revoked", username=s["username"], ip=ip)
                return self._json({"ok": True,
                                   "invites": A.invites(con, include_dead=True)})

            if url.path in ("/api/import", "/api/import/preview"):
                s = self._need_owner()
                if not s:
                    return
                return self.do_import(
                    con, body, commit=url.path == "/api/import", ip=ip,
                    who=s["username"])

            if url.path == "/api/networks/test":
                # Prove the connection works before the wizard lets anyone past
                # it. Nothing is written; this only opens a socket and closes it.
                s = self._need_owner()
                if not s:
                    return
                host = str(body.get("host", "")).strip()
                if not host:
                    return self._json({"ok": False, "error": "host required"}, 400)
                from .connections import probe
                res = probe(host, int(body.get("port", 6697) or 6697),
                            tls=body.get("tls") is not False,
                            nick=str(body.get("nick") or "aurora"),
                            timeout=int(body.get("timeout", 15) or 15))
                return self._json(res)

            if url.path == "/api/networks":
                s = self._need_owner()
                if not s:
                    return
                name = str(body.get("name", "")).strip().lower()
                host = str(body.get("host", "")).strip()
                if not name or not host:
                    return self._json({"error": "name and host required"}, 400)
                try:
                    nid = con.execute(
                        "INSERT INTO networks(name, label, host, port, tls, "
                        "archivist_nick, log_url, log_adapter, created) "
                        "VALUES (?,?,?,?,?,?,?,?,?)",
                        (name, str(body.get("label") or name.upper()), host,
                         int(body.get("port", 6697)),
                         0 if body.get("tls") is False else 1,
                         str(body.get("nick") or "aurora"),
                         body.get("log_url"), body.get("log_adapter"),
                         int(time.time()))).lastrowid
                except sqlite3.IntegrityError:
                    return self._json({"error": "a network with that name exists"}, 409)
                A.log(con, "network_add", username=s["username"], ip=ip, detail=name)
                return self._json({"id": nid})

            if url.path == "/api/appname":
                s = self._need_owner()
                if not s:
                    return
                name = str(body.get("name", "")).strip()[:48]
                if not name:
                    return self._json({"error": "name required"}, 400)
                db.setting(con, "app_name", name)
                A.log(con, "app_rename", username=s["username"], ip=ip, detail=name)
                return self._json({"appName": name})

            if url.path == "/api/networks/delete":
                s = self._need_owner()
                if not s:
                    return
                nid = int(body.get("id", 0))
                held = con.execute(
                    "SELECT COUNT(*) FROM messages m JOIN channels c "
                    "ON c.id = m.channel_id WHERE c.network_id = ?", (nid,)).fetchone()[0]
                if held and not body.get("force"):
                    return self._json(
                        {"error": f"{held:,} archived messages belong to this network",
                         "needsForce": True, "messages": held}, 409)
                con.execute("DELETE FROM networks WHERE id = ?", (nid,))
                if body.get("force"):
                    # Detach rather than cascade-delete: losing history to a
                    # mis-click would be unrecoverable.
                    con.execute("UPDATE channels SET network_id = NULL, archived = 0 "
                                "WHERE network_id = ?", (nid,))
                A.log(con, "network_delete", username=s["username"], ip=ip, detail=str(nid))
                return self._json({"ok": True})

            if url.path == "/api/networks/update":
                s = self._need_owner()
                if not s:
                    return
                nid = int(body.get("id", 0))
                sets, args = [], []
                for key, col in (("label", "label"), ("host", "host"),
                                 ("nick", "archivist_nick"), ("log_url", "log_url"),
                                 ("log_adapter", "log_adapter")):
                    if body.get(key) is not None:
                        sets.append(f"{col} = ?"); args.append(str(body[key]).strip())
                if body.get("port"):
                    sets.append("port = ?"); args.append(int(body["port"]))
                if "tls" in body:
                    sets.append("tls = ?"); args.append(1 if body["tls"] else 0)
                if "enabled" in body:
                    sets.append("enabled = ?"); args.append(1 if body["enabled"] else 0)
                if not sets:
                    return self._json({"error": "nothing to change"}, 400)
                con.execute(f"UPDATE networks SET {', '.join(sets)} WHERE id = ?",
                            args + [nid])
                A.log(con, "network_update", username=s["username"], ip=ip, detail=str(nid))
                return self._json({"ok": True})

            if url.path == "/api/users/create":
                s = self._need_owner()
                if not s:
                    return
                try:
                    nick = normalize_irc_nick(body.get("nick"), body.get("username"))
                    nick_state = irc_nick_state(con, nick)
                    if nick_state["taken"] and not body.get("claimNick"):
                        return self._json({"error": "that IRC nick appears to be in use",
                                           "nickConflict": nick_state}, 409)
                    uid = A.create_user(con, body.get("username"),
                                        str(body.get("password", "")),
                                        role=str(body.get("role", "user")),
                                        irc_nick=nick,
                                        join_method=A.JOIN_MANUAL,
                                        invited_by=s["user_id"])
                except ValueError as exc:
                    return self._json({"error": str(exc)}, 400)
                A.log(con, "user_create", username=s["username"], ip=ip,
                      detail=str(body.get("username")))
                return self._json({"id": uid})

            if url.path == "/api/networks/channels":
                s = self._need_owner()
                if not s:
                    return
                nid = int(body.get("network_id", 0))
                chan = str(body.get("channel", "")).strip().lstrip("#").lower()
                if not chan or any(c.isspace() for c in chan):
                    return self._json({"error": "invalid channel"}, 400)
                if not con.execute("SELECT 1 FROM networks WHERE id = ?",
                                   (nid,)).fetchone():
                    return self._json({"error": "no such network"}, 404)
                if body.get("delete"):
                    row = con.execute("SELECT id FROM channels WHERE name = ? "
                                      "AND network_id = ?", (chan, nid)).fetchone()
                    if row:
                        held = con.execute("SELECT COUNT(*) FROM messages WHERE "
                                           "channel_id = ?", (row["id"],)).fetchone()[0]
                        if held and not body.get("force"):
                            return self._json(
                                {"error": f"{held:,} archived messages in #{chan}",
                                 "needsForce": True, "messages": held}, 409)
                        con.execute("DELETE FROM channels WHERE id = ?", (row["id"],))
                elif "archived" in body:
                    con.execute("UPDATE channels SET archived = ? WHERE name = ? "
                                "AND network_id = ?",
                                (1 if body["archived"] else 0, chan, nid))
                elif body.get("remove"):
                    con.execute("UPDATE channels SET archived = 0 WHERE name = ? "
                                "AND network_id = ?", (chan, nid))
                else:
                    con.execute("INSERT OR IGNORE INTO channels(name, network_id) "
                                "VALUES (?,?)", (chan, nid))
                    con.execute("UPDATE channels SET network_id = ?, archived = 1 "
                                "WHERE name = ?", (nid, chan))
                A.log(con, "channel_update", username=s["username"], ip=ip, detail=chan)
                return self._json({"channels": db.network_channels(con, nid)})

            if url.path == "/api/users/update":
                s = self._need_owner()
                if not s:
                    return
                target = A.user_by_name(con, body.get("username"))
                if not target:
                    return self._json({"error": "no such user"}, 404)
                # The founding account is root: another owner must not be able
                # to demote, disable or delete the person whose server this is.
                if A.is_root(con, target["id"]) and (
                        body.get("delete") or body.get("disabled")
                        or body.get("role") == "user"):
                    return self._json(
                        {"error": "the owner account cannot be changed by anyone"}, 403)
                if target["id"] == s["user_id"] and (
                        body.get("role") == "user" or body.get("disabled")):
                    return self._json({"error": "you cannot demote or disable yourself"}, 400)
                if "role" in body and body["role"] in ("admin", "user"):
                    # A user's one-time dismissal is not consent to skip a
                    # future admin requirement. Clear it at promotion as well
                    # as enforcing the gate from the live role on every login.
                    con.execute(
                        "UPDATE users SET role = ?, totp_declined = CASE "
                        "WHEN ? = 'admin' THEN 0 ELSE totp_declined END WHERE id = ?",
                        (body["role"], body["role"], target["id"]))
                if "disabled" in body:
                    con.execute("UPDATE users SET disabled = ? WHERE id = ?",
                                (1 if body["disabled"] else 0, target["id"]))
                    if body["disabled"]:
                        A.drop_user_sessions(con, target["id"])
                if body.get("delete"):
                    if target["id"] == s["user_id"]:
                        return self._json({"error": "you cannot delete yourself"}, 400)
                    A.drop_user_sessions(con, target["id"])
                    con.execute("DELETE FROM users WHERE id = ?", (target["id"],))
                A.log(con, "user_update", username=s["username"], ip=ip,
                      detail=target["username"])
                return self._json({"ok": True})

            # ---- everything below needs a session ----
            if url.path == "/api/person/status":
                s = self._need_auth()
                if not s:
                    return
                nick = clean_person_nick(body.get("nick"))
                net = person_network(con, nick, channel=body.get("channel"),
                                     network_id=body.get("network"))
                if not net:
                    return self._json({"error": "no IRC network for that person"}, 400)
                if not network_status(con, net["id"])["connected"]:
                    return self._json({"error": "that IRC network is not connected"}, 409)
                now = int(time.time())
                old = con.execute(
                    "SELECT requested_at FROM live_presence_checks WHERE network_id=? "
                    "AND nick=? COLLATE NOCASE", (net["id"], nick)).fetchone()
                if not old or now - old["requested_at"] >= 3:
                    con.execute(
                        "INSERT INTO live_presence_checks(network_id, nick, requested_at, "
                        "checked_at, online, error) VALUES (?,?,?,NULL,NULL,NULL) "
                        "ON CONFLICT(network_id, nick) DO UPDATE SET "
                        "requested_at=excluded.requested_at, error=NULL",
                        (net["id"], nick, now))
                return self._json(person_profile(
                    con, nick, session=s, network_id=net["id"]))

            if url.path == "/api/person":
                s = self._need_auth()
                if not s:
                    return
                nick = clean_person_nick(body.get("nick"))
                net = person_network(con, nick, channel=body.get("channel"),
                                     network_id=body.get("network"))
                if not net:
                    return self._json({"error": "no IRC network for that person"}, 400)
                old = con.execute(
                    "SELECT favourite, notes, links FROM person_annotations "
                    "WHERE user_id=? AND network_id=? AND nick=? COLLATE NOCASE",
                    (s["user_id"], net["id"], nick)).fetchone()
                favourite = bool(old["favourite"]) if old else False
                notes = old["notes"] if old else ""
                try:
                    links = json.loads(old["links"] or "{}") if old else {}
                except ValueError:
                    links = {}
                if "favourite" in body:
                    favourite = bool(body["favourite"])
                if "notes" in body:
                    notes = str(body.get("notes") or "").rstrip()
                    if len(notes) > PERSON_NOTES_MAX:
                        return self._json(
                            {"error": f"notes are capped at {PERSON_NOTES_MAX} characters"}, 400)
                if "links" in body:
                    try:
                        links = normalize_person_links(body.get("links"))
                    except ValueError as exc:
                        return self._json({"error": str(exc)}, 400)
                now = int(time.time())
                if not favourite and not notes and not links:
                    con.execute(
                        "DELETE FROM person_annotations WHERE user_id=? AND network_id=? "
                        "AND nick=? COLLATE NOCASE", (s["user_id"], net["id"], nick))
                else:
                    con.execute(
                        "INSERT INTO person_annotations(user_id, network_id, nick, favourite, "
                        "notes, links, updated) VALUES (?,?,?,?,?,?,?) "
                        "ON CONFLICT(user_id, network_id, nick) DO UPDATE SET "
                        "favourite=excluded.favourite, notes=excluded.notes, "
                        "links=excluded.links, updated=excluded.updated",
                        (s["user_id"], net["id"], nick, 1 if favourite else 0,
                         notes, json.dumps(links, ensure_ascii=False), now))
                return self._json(person_profile(
                    con, nick, session=s, network_id=net["id"]))

            if url.path == "/api/live/nick":
                if not (s := self._need_auth()):
                    return
                nick = str(body.get("nick", "")).strip()
                if not nick or len(nick) > 30 or any(c.isspace() for c in nick):
                    return self._json({"error": "invalid nick"}, 400)
                db.setting(con, "desired_nick", nick)
                s["nick"] = nick
                return self._json({"nick": nick, "live": live_status(con)})

            if url.path == "/api/command":
                s = self._need_auth()
                if not s:
                    return
                channel = str(body.get("channel", "")).strip()
                nid = channel_network(con, channel) if channel else None
                if not nid:
                    try:
                        nid = int(body.get("network") or 0)
                    except (TypeError, ValueError):
                        nid = 0
                net = con.execute("SELECT id FROM networks WHERE id=? AND enabled=1",
                                  (nid,)).fetchone()
                if not net:
                    return self._json({"error": "choose a channel on a live network"}, 400)
                if not network_status(con, nid)["connected"]:
                    return self._json({"error": "that IRC network is not connected"}, 409)
                try:
                    command = prepare_irc_command(body.get("command"), channel=channel)
                except ValueError as exc:
                    return self._json({"error": str(exc)}, 400)
                recent = con.execute(
                    "SELECT COUNT(*) FROM irc_commands WHERE user_id=? AND created>?",
                    (s["user_id"], int(time.time()) - 10)).fetchone()[0]
                pending = con.execute(
                    "SELECT COUNT(*) FROM irc_commands WHERE user_id=? "
                    "AND finished_at IS NULL", (s["user_id"],)).fetchone()[0]
                if recent >= 6 or pending >= 3:
                    return self._json(
                        {"error": "too many IRC commands at once — wait for a reply"}, 429)
                cur = con.execute(
                    "INSERT INTO irc_commands(user_id, network_id, nick, command, wire, "
                    "created) VALUES (?,?,?,?,?,?)",
                    (s["user_id"], nid, s["irc_nick"], command["command"],
                     command["wire"], int(time.time())))
                return self._json({"queued": cur.lastrowid,
                                   "command": command["command"],
                                   "name": command["name"]})

            if url.path == "/api/send":
                s = self._need_auth()
                if not s:
                    return
                channel = str(body.get("channel", "")).strip()
                text = str(body.get("text", "")).strip()
                if not channel or not text:
                    return self._json({"error": "channel and text required"}, 400)
                # Resolve against configured channels, not a heartbeat summary:
                # with several networks the summary cannot say which is which.
                nid = channel_network(con, channel)
                if not nid:
                    return self._json({"error": f"{channel} is not configured"}, 400)
                if not network_status(con, nid)["connected"]:
                    return self._json(
                        {"error": f"no live connection for {channel}"}, 409)
                if len(text) > MAX_SEND:
                    return self._json({"error": f"message too long (max {MAX_SEND})"}, 400)
                # Goes out under this user's own nick, not the archivist's
                mid = db.queue_outbound(con, channel, text, user_id=s["user_id"],
                                        nick=s["irc_nick"])
                con.execute("UPDATE outbox SET network_id = ? WHERE id = ?", (nid, mid))
                return self._json({"queued": mid, "channel": channel, "text": text,
                                   "nick": s["irc_nick"]})

            if url.path == "/api/prewarm":
                # Opening a send-only connection costs ~12s (TCP, TLS, register,
                # JOIN, settle). Doing that when the user starts typing, rather
                # than when they hit send, is the difference between instant and
                # apparently broken. Best effort: a miss just means a slow send.
                s = self._need_auth()
                if not s:
                    return
                channel = str(body.get("channel", "")).strip()
                nid = channel_network(con, channel) if channel else None
                if not nid or not s["irc_nick"]:
                    return self._json({"ok": False})
                chan = channel if channel.startswith("#") else "#" + channel
                db.setting(con, f"prewarm:{nid}:{s['irc_nick']}",
                           f"{int(time.time())}|{chan}")
                return self._json({"ok": True})

            if url.path == "/api/tags":
                if not self._need_auth():
                    return
                name = str(body.get("name", "")).strip().lstrip("&").lower()
                color = str(body.get("color", "grey")).strip().lower()
                label = str(body.get("label", "")).strip() or name.title()
                if not name or not name.replace("-", "").replace("_", "").isalnum():
                    return self._json({"error": "tag names are letters, digits, - and _"}, 400)
                if len(name) > 24:
                    return self._json({"error": "tag name too long"}, 400)
                if color not in db.TAG_COLORS:
                    return self._json({"error": f"colour must be one of "
                                                f"{', '.join(db.TAG_COLORS)}"}, 400)
                if name in [c for c in db.TAG_COLORS]:
                    return self._json({"error": "that name is reserved for a colour"}, 400)
                con.execute(
                    "INSERT INTO tags(name, label, color, builtin, created) "
                    "VALUES (?,?,?,0,?) ON CONFLICT(name) DO UPDATE SET "
                    "label = excluded.label, color = excluded.color",
                    (name, label, color, int(time.time())))
                return self._json({"tags": Q.tags(con)})

            if url.path == "/api/history":
                # Remembering what you searched for is an account feature, so
                # it lives behind the same gate as everything else that writes.
                s = self._need_auth()
                if not s:
                    return
                act = str(body.get("action", "record"))
                if act == "clear":
                    A.clear_search_history(con, s["user_id"], body.get("query"))
                else:
                    A.record_search(con, s["user_id"], body.get("query"))
                return self._json({"history": A.search_history(con, s["user_id"])})

            if url.path == "/api/searches":
                if not self._need_auth():
                    return
                name = str(body.get("name", "")).strip()
                if not name or len(name) > 48:
                    return self._json({"error": "name required (max 48 chars)"}, 400)
                query = str(body.get("query", ""))
                extra = json.dumps(body.get("extra") or {}, ensure_ascii=False)
                con.execute(
                    "INSERT INTO saved_searches(name, query, extra, created) "
                    "VALUES (?,?,?,?) ON CONFLICT(name) DO UPDATE SET "
                    "query = excluded.query, extra = excluded.extra",
                    (name, query, extra, int(time.time())))
                return self._json({"searches": [dict(r) for r in con.execute(
                    "SELECT name, query, extra, created, used FROM saved_searches "
                    "ORDER BY used DESC, name")]})

            if url.path == "/api/searches/delete":
                if not self._need_auth():
                    return
                con.execute("DELETE FROM saved_searches WHERE name = ? COLLATE NOCASE",
                            (str(body.get("name", "")).strip(),))
                return self._json({"searches": [dict(r) for r in con.execute(
                    "SELECT name, query, extra, created, used FROM saved_searches "
                    "ORDER BY used DESC, name")]})

            if url.path == "/api/searches/used":
                # Still a write, so it still needs a session: an anonymous
                # caller must not be able to mutate anything at all.
                if not self._need_auth():
                    return
                con.execute("UPDATE saved_searches SET used = used + 1 "
                            "WHERE name = ? COLLATE NOCASE",
                            (str(body.get("name", "")).strip(),))
                return self._json({"ok": True})

            if url.path == "/api/tags/update":
                if not self._need_auth():
                    return
                name = str(body.get("name", "")).strip().lstrip("&").lower()
                row = con.execute("SELECT id FROM tags WHERE name = ? COLLATE NOCASE",
                                  (name,)).fetchone()
                if not row:
                    return self._json({"error": "no such tag"}, 404)
                if "color" in body:
                    color = str(body["color"]).strip().lower()
                    if color not in db.TAG_COLORS:
                        return self._json({"error": "unknown colour"}, 400)
                    con.execute("UPDATE tags SET color = ? WHERE id = ?", (color, row["id"]))
                if "label" in body:
                    label = str(body["label"]).strip()
                    if not label:
                        return self._json({"error": "label cannot be empty"}, 400)
                    con.execute("UPDATE tags SET label = ? WHERE id = ?", (label, row["id"]))
                if body.get("new_name"):
                    new = str(body["new_name"]).strip().lstrip("&").lower()
                    if not new.replace("-", "").replace("_", "").isalnum() or len(new) > 24:
                        return self._json({"error": "invalid tag name"}, 400)
                    if new in db.TAG_COLORS:
                        return self._json({"error": "that name is reserved for a colour"}, 400)
                    if con.execute("SELECT 1 FROM tags WHERE name = ? COLLATE NOCASE "
                                   "AND id != ?", (new, row["id"])).fetchone():
                        return self._json({"error": "a tag with that name exists"}, 409)
                    con.execute("UPDATE tags SET name = ? WHERE id = ?", (new, row["id"]))
                return self._json({"tags": Q.tags(con)})

            if url.path == "/api/tags/delete":
                if not self._need_auth():
                    return
                name = str(body.get("name", "")).strip().lstrip("&").lower()
                row = con.execute("SELECT id, builtin FROM tags WHERE name = ? "
                                  "COLLATE NOCASE", (name,)).fetchone()
                if not row:
                    return self._json({"error": "no such tag"}, 404)
                con.execute("DELETE FROM message_tags WHERE tag_id = ?", (row["id"],))
                con.execute("DELETE FROM tags WHERE id = ?", (row["id"],))
                return self._json({"tags": Q.tags(con)})

            if url.path == "/api/message/tag":
                if not self._need_auth():
                    return
                mid = int(body.get("message_id", 0))
                name = str(body.get("tag", "")).strip().lstrip("&").lower()
                on = bool(body.get("on", True))
                tag = con.execute("SELECT id FROM tags WHERE name = ? COLLATE NOCASE",
                                  (name,)).fetchone()
                if not tag:
                    return self._json({"error": "no such tag"}, 404)
                if not con.execute("SELECT 1 FROM messages WHERE id = ?",
                                   (mid,)).fetchone():
                    return self._json({"error": "no such message"}, 404)
                if on:
                    con.execute("INSERT OR IGNORE INTO message_tags(message_id, tag_id, at) "
                                "VALUES (?,?,?)", (mid, tag["id"], int(time.time())))
                else:
                    con.execute("DELETE FROM message_tags WHERE message_id = ? AND tag_id = ?",
                                (mid, tag["id"]))
                cur = Q.attach_tags(con, [{"id": mid}])[0]
                return self._json({"message_id": mid, "tags": cur["tags"]})
        except (KeyError, ValueError, TypeError):
            return self._json({"error": "bad request"}, 400)
        except Exception as exc:
            print(f"[error] POST {url.path}: {exc}")
            return self._json({"error": "server error"}, 500)
        self._json({"error": "not found"}, 404)


def serve(dbpath, host="127.0.0.1", port=8420, behind_proxy=False,
          proxy_hops=1, allow_local_fetch=False):
    F.ALLOW_PRIVATE = bool(allow_local_fetch)
    con = db.connect(dbpath)
    A.purge_expired(con)
    set_up = A.any_users(con)
    con.close()
    Handler.dbpath = str(dbpath)
    Handler.behind_proxy = behind_proxy
    Handler.proxy_hops = proxy_hops

    httpd = ThreadingHTTPServer((host, port), Handler)
    shown = "localhost" if host in ("127.0.0.1", "localhost") else host
    print(f"Archive viewer: http://{shown}:{port}/")
    if host == "0.0.0.0":
        print("Reachable from other devices on your network.")
    if behind_proxy:
        print("Trusting X-Forwarded-For - only correct behind a proxy you control.")
    if allow_local_fetch:
        print("Importing and image fetching may reach this network - owners only,")
        print("but they can point it at anything this machine can see.")
    print("\nReading is open to anyone who can reach this address.")
    if set_up:
        print("Sign in to send messages, tag, or manage users.")
    else:
        print("No accounts yet - the app will offer to create the owner,")
        print("or run:  ./archive.py adduser --admin")
    print("\nPress Ctrl+C to stop.")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nStopped.")
