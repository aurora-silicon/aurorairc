"""SQLite storage for IRC archive messages.

Design notes:

* Exported logs only carry minute resolution, while the live IRC client knows
  the second. Both are stored, but the dedupe key uses the minute-floored
  timestamp so that re-importing an export over live-captured data is a no-op
  rather than a source of duplicates.
* Message text is mirrored into an FTS5 index by triggers, so search stays
  correct no matter which code path inserted the row.
"""

import hashlib
import os
import secrets
import sqlite3
import time
from pathlib import Path

# Message kinds
MSG, ACTION, TOPIC = 0, 1, 2
KIND_NAMES = {MSG: "message", ACTION: "action", TOPIC: "topic"}

# Event kinds (stored in `events`, never in `messages`)
EV_JOIN, EV_PART, EV_QUIT, EV_NICK, EV_KICK, EV_MODE = 0, 1, 2, 3, 4, 5
EVENT_NAMES = {EV_JOIN: "join", EV_PART: "part", EV_QUIT: "quit",
               EV_NICK: "nick", EV_KICK: "kick", EV_MODE: "mode"}

SCHEMA = """
PRAGMA journal_mode=WAL;
PRAGMA foreign_keys=ON;

-- An IRC network. Several are archived side by side; each gets exactly one
-- always-on archivist connection, which is the only thing that receives.
CREATE TABLE IF NOT EXISTS networks (
    id             INTEGER PRIMARY KEY,
    name           TEXT NOT NULL UNIQUE COLLATE NOCASE,   -- slug, e.g. 'libera'
    label          TEXT,                                  -- display name
    host           TEXT NOT NULL,
    port           INTEGER NOT NULL DEFAULT 6697,
    tls            INTEGER NOT NULL DEFAULT 1,
    archivist_nick TEXT NOT NULL DEFAULT 'aurora',
    sasl_user      TEXT,
    sasl_pass      TEXT,
    log_url        TEXT,      -- optional web archive to backfill from
    log_adapter    TEXT,      -- which adapter reads it, e.g. 'catirclogs'
    enabled        INTEGER NOT NULL DEFAULT 1,
    created        INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS channels (
    id   INTEGER PRIMARY KEY,
    name TEXT NOT NULL UNIQUE          -- without leading '#'
);

CREATE TABLE IF NOT EXISTS nicks (
    id   INTEGER PRIMARY KEY,
    name TEXT NOT NULL UNIQUE
);

CREATE TABLE IF NOT EXISTS messages (
    id         INTEGER PRIMARY KEY,
    channel_id INTEGER NOT NULL REFERENCES channels(id),
    nick_id    INTEGER NOT NULL REFERENCES nicks(id),
    ts         INTEGER NOT NULL,       -- unix seconds, UTC, best known precision
    ts_min     INTEGER NOT NULL,       -- ts floored to the minute; part of dedupe key
    seq        INTEGER NOT NULL,       -- nth identical line within that minute
    kind       INTEGER NOT NULL,       -- 0 message, 1 action, 2 topic
    text       TEXT    NOT NULL,
    source     TEXT    NOT NULL,       -- 'export' or 'live'
    UNIQUE (channel_id, ts_min, nick_id, kind, text, seq)
);

CREATE INDEX IF NOT EXISTS idx_msg_ts       ON messages(ts);
CREATE INDEX IF NOT EXISTS idx_msg_chan_ts  ON messages(channel_id, ts);
CREATE INDEX IF NOT EXISTS idx_msg_nick_ts  ON messages(nick_id, ts);

CREATE VIRTUAL TABLE IF NOT EXISTS messages_fts USING fts5(
    text,
    content='messages',
    content_rowid='id',
    tokenize="unicode61 remove_diacritics 2"
);

CREATE TRIGGER IF NOT EXISTS messages_ai AFTER INSERT ON messages BEGIN
    INSERT INTO messages_fts(rowid, text) VALUES (new.id, new.text);
END;
CREATE TRIGGER IF NOT EXISTS messages_ad AFTER DELETE ON messages BEGIN
    INSERT INTO messages_fts(messages_fts, rowid, text) VALUES('delete', old.id, old.text);
END;
CREATE TRIGGER IF NOT EXISTS messages_au AFTER UPDATE ON messages BEGIN
    INSERT INTO messages_fts(messages_fts, rowid, text) VALUES('delete', old.id, old.text);
    INSERT INTO messages_fts(rowid, text) VALUES (new.id, new.text);
END;

-- Join/part/quit/nick/kick traffic. Deliberately a separate table from
-- messages, not a message kind:
--   * the MCP server reads only `messages`, so agents never wade through it;
--   * it is 4-5x the volume of conversation and would bloat the FTS index
--     for no benefit - nobody full-text searches "has joined".
CREATE TABLE IF NOT EXISTS events (
    id         INTEGER PRIMARY KEY,
    channel_id INTEGER NOT NULL REFERENCES channels(id),
    nick_id    INTEGER NOT NULL REFERENCES nicks(id),
    ts         INTEGER NOT NULL,
    ts_min     INTEGER NOT NULL,
    seq        INTEGER NOT NULL,
    kind       INTEGER NOT NULL,       -- see EVENT_* below
    detail     TEXT    NOT NULL DEFAULT '',
    source     TEXT    NOT NULL,
    UNIQUE (channel_id, ts_min, nick_id, kind, detail, seq)
);
CREATE INDEX IF NOT EXISTS idx_events_chan_ts ON events(channel_id, ts);
CREATE INDEX IF NOT EXISTS idx_events_ts      ON events(ts);

-- Outbound messages queued by the web UI. The web server never touches the
-- network: it appends here, and the live IRC process drains the queue. A
-- read-only connection (the MCP server) physically cannot insert into this,
-- which is what keeps "agents can never message" true by construction.
CREATE TABLE IF NOT EXISTS outbox (
    id       INTEGER PRIMARY KEY,
    channel  TEXT    NOT NULL,
    text     TEXT    NOT NULL,
    created  INTEGER NOT NULL,
    sent_at  INTEGER,
    error    TEXT
);
CREATE INDEX IF NOT EXISTS idx_outbox_pending ON outbox(sent_at) WHERE sent_at IS NULL;

-- Small key/value store: live heartbeat, desired nick, password hash, etc.
CREATE TABLE IF NOT EXISTS settings (
    key   TEXT PRIMARY KEY,
    value TEXT
);

-- Finder-style flags. A tag has a colour and a short slug used as &slug in
-- the search bar. Colours are named, not hex, so the UI can theme them.
CREATE TABLE IF NOT EXISTS tags (
    id      INTEGER PRIMARY KEY,
    name    TEXT NOT NULL UNIQUE COLLATE NOCASE,   -- slug: 'important', 'gpu'
    label   TEXT,                                  -- display name if different
    color   TEXT NOT NULL,                         -- red|orange|yellow|green|blue|purple|pink|grey
    builtin INTEGER NOT NULL DEFAULT 0,
    created INTEGER NOT NULL
);

-- Saved searches live on the server, not in localStorage, so the same set is
-- there on the phone and the desktop. Readable by anyone; writing needs auth.
CREATE TABLE IF NOT EXISTS saved_searches (
    id      INTEGER PRIMARY KEY,
    name    TEXT NOT NULL UNIQUE COLLATE NOCASE,
    query   TEXT NOT NULL DEFAULT '',   -- raw search-bar contents (#chan @nick &tag text)
    extra   TEXT,                       -- JSON: dates, kinds, order, events
    created INTEGER NOT NULL,
    used    INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS message_tags (
    message_id INTEGER NOT NULL REFERENCES messages(id) ON DELETE CASCADE,
    tag_id     INTEGER NOT NULL REFERENCES tags(id) ON DELETE CASCADE,
    at         INTEGER NOT NULL,
    PRIMARY KEY (message_id, tag_id)
);
CREATE INDEX IF NOT EXISTS idx_mtags_tag ON message_tags(tag_id);

CREATE TABLE IF NOT EXISTS ingests (
    id        INTEGER PRIMARY KEY,
    path      TEXT NOT NULL,
    at        INTEGER NOT NULL,
    seen      INTEGER NOT NULL,        -- lines that parsed as chat
    inserted  INTEGER NOT NULL         -- rows actually new
);
"""

DEFAULT_DB = Path(__file__).resolve().parent.parent / "archive.db"


def connect(path=None):
    path = Path(path or DEFAULT_DB)
    path.parent.mkdir(parents=True, exist_ok=True)
    con = sqlite3.connect(str(path), timeout=30, isolation_level=None)
    con.row_factory = sqlite3.Row
    con.executescript(SCHEMA)
    from . import auth
    auth.init(con)
    seed_tags(con)
    migrate(con)
    return con


# Used only when an archive predates multi-network support and has channels
# with no network. A fresh install never hits this; the owner configures real
# networks in Settings.
DEFAULT_NETWORK = {
    "name": "default", "label": "Unconfigured", "host": "irc.example.org",
    "port": 6697, "tls": 1, "archivist_nick": "aurora",
    "log_url": None, "log_adapter": None,
}


def migrate(con):
    """Additive migrations, safe to run on every open. Never drops data.

    Three processes share this file and any of them may be the first to open it
    after an upgrade, so every ALTER here has to survive another one having got
    there a millisecond earlier - see auth.add_column.
    """
    from .auth import add_column
    # Whose IRC identity should carry this line out
    add_column(con, "outbox", "user_id", "INTEGER")
    add_column(con, "outbox", "nick", "TEXT")
    add_column(con, "outbox", "network_id", "INTEGER")
    add_column(con, "channels", "network_id", "INTEGER")
    add_column(con, "channels", "archived", "INTEGER NOT NULL DEFAULT 1")

    # Adopt any pre-network channels into a first network, so an archive that
    # predates multi-network support keeps every message reachable.
    orphans = con.execute(
        "SELECT COUNT(*) FROM channels WHERE network_id IS NULL").fetchone()[0]
    if orphans:
        row = con.execute("SELECT id FROM networks ORDER BY id LIMIT 1").fetchone()
        if row:
            nid = row["id"]
        else:
            d = DEFAULT_NETWORK
            nid = con.execute(
                "INSERT INTO networks(name, label, host, port, tls, archivist_nick, "
                "log_url, log_adapter, created) VALUES (?,?,?,?,?,?,?,?,?)",
                (d["name"], d["label"], d["host"], d["port"], d["tls"],
                 d["archivist_nick"], d["log_url"], d["log_adapter"],
                 int(time.time()))).lastrowid
        con.execute("UPDATE channels SET network_id = ? WHERE network_id IS NULL", (nid,))
        con.execute("UPDATE outbox SET network_id = ? WHERE network_id IS NULL", (nid,))


def networks(con, enabled_only=False):
    sql = "SELECT * FROM networks"
    if enabled_only:
        sql += " WHERE enabled = 1"
    return [dict(r) for r in con.execute(sql + " ORDER BY id")]


def network_channels(con, network_id, archived_only=True):
    sql = "SELECT name FROM channels WHERE network_id = ?"
    if archived_only:
        sql += " AND archived = 1"
    return [r["name"] for r in con.execute(sql + " ORDER BY name", (network_id,))]


class Ids:
    """Write-through cache for channel/nick lookups, plus repeat tracking.

    ``seq`` distinguishes genuinely repeated lines (someone sending the same
    text several times inside one minute) from the same line being imported
    twice. It is derived deterministically, so re-importing an overlapping
    export still collapses to a no-op.
    """

    def __init__(self, con):
        self.con = con
        self._chan = {}
        self._nick = {}
        self._seq = {}

    def _lookup(self, table, cache, name):
        i = cache.get(name)
        if i is not None:
            return i
        cur = self.con.execute(f"SELECT id FROM {table} WHERE name = ?", (name,))
        row = cur.fetchone()
        if row is None:
            cur = self.con.execute(f"INSERT INTO {table}(name) VALUES (?)", (name,))
            i = cur.lastrowid
        else:
            i = row["id"]
        cache[name] = i
        return i

    def channel(self, name):
        return self._lookup("channels", self._chan, name.lstrip("#"))

    def nick(self, name):
        return self._lookup("nicks", self._nick, name)

    def reset_seq(self):
        """Call between input files so occurrence counts restart per file.

        Without this, ingesting two exports that cover the same day would give
        the second file's copies fresh seq values and duplicate the day.
        """
        self._seq.clear()

    def seq(self, key, from_db=False):
        """Next occurrence index for an otherwise identical message."""
        n = self._seq.get(key)
        if n is None:
            if from_db:
                # Live capture: continue from whatever is already stored, so a
                # later export import lines up with what we recorded.
                n = self.con.execute(
                    "SELECT COUNT(*) FROM messages WHERE channel_id=? AND ts_min=? "
                    "AND nick_id=? AND kind=? AND text=?", key
                ).fetchone()[0]
            else:
                n = 0
        self._seq[key] = n + 1
        return n


def insert_messages(con, ids, rows, source):
    """rows: iterable of (channel, nick, ts, kind, text). Returns count inserted."""
    live = source == "live"
    payload = []
    for channel, nick, ts, kind, text in rows:
        # Trailing whitespace survives in a web export but not in what a live
        # client sees, and `text` is part of the dedupe key - so the same line
        # arriving both ways was stored twice. Normalise here, where every
        # caller passes through, rather than in each parser.
        text = text.strip()
        if not text:
            continue
        cid, nid = ids.channel(channel), ids.nick(nick)
        ts = int(ts)
        ts_min = (ts // 60) * 60
        key = (cid, ts_min, nid, int(kind), text)
        payload.append((cid, nid, ts, ts_min, ids.seq(key, from_db=live),
                        int(kind), text, source))
    if not payload:
        return 0
    # total_changes() is unusable here: the FTS5 sync triggers make it count
    # shadow-table writes too. Compare real row counts instead.
    before = con.execute("SELECT COUNT(*) FROM messages").fetchone()[0]
    con.executemany(
        "INSERT OR IGNORE INTO messages"
        "(channel_id, nick_id, ts, ts_min, seq, kind, text, source) "
        "VALUES (?,?,?,?,?,?,?,?)",
        payload,
    )
    after = con.execute("SELECT COUNT(*) FROM messages").fetchone()[0]
    return after - before


def setting(con, key, value=None):
    """Read a setting, or write it when a value is given."""
    if value is None:
        row = con.execute("SELECT value FROM settings WHERE key = ?", (key,)).fetchone()
        return row["value"] if row else None
    con.execute("INSERT INTO settings(key, value) VALUES (?,?) "
                "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                (key, str(value)))
    return value


# ---------------------------------------------------------------- password

PBKDF_ROUNDS = 240_000


def set_password(con, password):
    """Store a salted PBKDF2 hash. The plaintext is never written anywhere."""
    if not password or len(password) < 6:
        raise ValueError("password must be at least 6 characters")
    salt = secrets.token_bytes(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, PBKDF_ROUNDS)
    setting(con, "password",
            f"pbkdf2_sha256${PBKDF_ROUNDS}${salt.hex()}${dk.hex()}")


def has_password(con):
    return bool(setting(con, "password"))


def check_password(con, password):
    stored = setting(con, "password")
    if not stored or not password:
        return False
    try:
        algo, rounds, salt_hex, want = stored.split("$")
        if algo != "pbkdf2_sha256":
            return False
        dk = hashlib.pbkdf2_hmac("sha256", password.encode(),
                                 bytes.fromhex(salt_hex), int(rounds))
    except (ValueError, TypeError):
        return False
    return secrets.compare_digest(dk.hex(), want)


# -------------------------------------------------------------------- tags

TAG_COLORS = ("red", "orange", "yellow", "green", "blue", "purple", "pink", "grey")

BUILTIN_TAGS = [
    ("important", "Important", "red"),
    ("question",  "Question",  "orange"),
    ("todo",      "To do",     "yellow"),
    ("resolved",  "Resolved",  "green"),
    ("reference", "Reference", "blue"),
    ("idea",      "Idea",      "purple"),
]


def seed_tags(con):
    """Create the built-in tag set once, mirroring Finder's default flags."""
    if con.execute("SELECT COUNT(*) FROM tags").fetchone()[0]:
        return
    now = int(time.time())
    con.executemany(
        "INSERT OR IGNORE INTO tags(name, label, color, builtin, created) "
        "VALUES (?,?,?,1,?)",
        [(n, l, c, now) for n, l, c in BUILTIN_TAGS])


def queue_outbound(con, channel, text, user_id=None, nick=None):
    """Queue a line to send. `nick` is the IRC identity it must go out under.

    The archivist connection never sends. A separate send-only connection is
    opened for that nick, and the message comes back through the archivist like
    any other, so it is recorded once with correct attribution.
    """
    cur = con.execute(
        "INSERT INTO outbox(channel, text, created, user_id, nick) VALUES (?,?,?,?,?)",
        (channel if channel.startswith("#") else "#" + channel, text,
         int(time.time()), user_id, nick))
    return cur.lastrowid


def insert_events(con, ids, rows, source):
    """rows: (channel, nick, ts, kind, detail). Returns count inserted."""
    live = source == "live"
    payload = []
    for channel, nick, ts, kind, detail in rows:
        cid, nid = ids.channel(channel), ids.nick(nick)
        ts = int(ts)
        ts_min = (ts // 60) * 60
        key = ("ev", cid, ts_min, nid, int(kind), detail)
        payload.append((cid, nid, ts, ts_min, ids.seq(key, from_db=False),
                        int(kind), detail, source))
    if not payload:
        return 0
    before = con.execute("SELECT COUNT(*) FROM events").fetchone()[0]
    con.executemany(
        "INSERT OR IGNORE INTO events"
        "(channel_id, nick_id, ts, ts_min, seq, kind, detail, source) "
        "VALUES (?,?,?,?,?,?,?,?)",
        payload,
    )
    return con.execute("SELECT COUNT(*) FROM events").fetchone()[0] - before


def record_ingest(con, path, seen, inserted):
    con.execute(
        "INSERT INTO ingests(path, at, seen, inserted) VALUES (?,?,?,?)",
        (str(path), int(time.time()), seen, inserted),
    )
