"""Users, sessions, invites, and the hardening around them.

Shape of the system, as chosen:

  * Accounts exist only by invitation from an owner. There is no public signup
    endpoint to attack.
  * Unauthenticated visitors get anonymous read-only access. Nothing here gates
    reading; it gates every write.
  * Sessions live in the database, not in process memory, so a restart does not
    sign everyone out and a session can be revoked from another device.
  * TOTP is optional per account, and enrolling requires proving the code works
    before it is switched on.

Passwords use PBKDF2-SHA256. TOTP is RFC 6238 over HMAC-SHA1, implemented here
rather than pulled in, since the whole project is standard library only.
"""

import base64
import hashlib
import hmac
import json
import re
import secrets
import sqlite3
import struct
import time

SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id           INTEGER PRIMARY KEY,
    username     TEXT NOT NULL UNIQUE COLLATE NOCASE,
    password     TEXT,                      -- NULL until an invite is redeemed
    role         TEXT NOT NULL DEFAULT 'user',     -- 'admin' | 'user'
    irc_nick     TEXT,                      -- identity for their send connection
    totp_secret  TEXT,
    totp_enabled INTEGER NOT NULL DEFAULT 0,
    disabled     INTEGER NOT NULL DEFAULT 0,
    created      INTEGER NOT NULL,
    last_seen    INTEGER
);

CREATE TABLE IF NOT EXISTS invites (
    token      TEXT PRIMARY KEY,
    username   TEXT,
    role       TEXT NOT NULL DEFAULT 'member',
    created_by INTEGER REFERENCES users(id),
    created    INTEGER NOT NULL,
    expires    INTEGER NOT NULL,
    used_by    INTEGER REFERENCES users(id),
    used_at    INTEGER
);

-- Who actually joined on which link. An invite may be a *pass* good for
-- several people, so "used_by" on the invite itself is not enough to answer
-- "where did this account come from" - which is exactly what an owner needs
-- when an account turns up they do not recognise.
CREATE TABLE IF NOT EXISTS invite_uses (
    id      INTEGER PRIMARY KEY,
    token   TEXT NOT NULL,
    user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
    at      INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_invite_uses_token ON invite_uses(token);
CREATE INDEX IF NOT EXISTS idx_invite_uses_user  ON invite_uses(user_id);

-- Recent searches, per account, so the bar can offer them back. Server-side
-- rather than localStorage for the same reason saved searches are: the phone
-- and the desktop should agree.
CREATE TABLE IF NOT EXISTS search_history (
    id      INTEGER PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    query   TEXT NOT NULL,
    at      INTEGER NOT NULL
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_hist_user_query
    ON search_history(user_id, query);

CREATE TABLE IF NOT EXISTS sessions (
    id        TEXT PRIMARY KEY,
    user_id   INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    csrf      TEXT NOT NULL,
    created   INTEGER NOT NULL,
    last_seen INTEGER NOT NULL,
    expires   INTEGER NOT NULL,
    ip        TEXT,
    agent     TEXT
);
CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id);

CREATE TABLE IF NOT EXISTS auth_log (
    id       INTEGER PRIMARY KEY,
    at       INTEGER NOT NULL,
    event    TEXT NOT NULL,
    username TEXT,
    ip       TEXT,
    detail   TEXT
);
CREATE INDEX IF NOT EXISTS idx_authlog_at ON auth_log(at);

-- Passkeys. The stored public key is a COSE_Key blob exactly as the
-- authenticator produced it; nothing secret is ever held here.
CREATE TABLE IF NOT EXISTS credentials (
    id         INTEGER PRIMARY KEY,
    user_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    cred_id    TEXT NOT NULL UNIQUE,      -- base64url credential id
    public_key BLOB NOT NULL,
    sign_count INTEGER NOT NULL DEFAULT 0,
    label      TEXT,
    created    INTEGER NOT NULL,
    last_used  INTEGER
);
CREATE INDEX IF NOT EXISTS idx_creds_user ON credentials(user_id);

-- Short-lived WebAuthn challenges, kept server-side so a replayed one fails.
CREATE TABLE IF NOT EXISTS webauthn_challenges (
    challenge TEXT PRIMARY KEY,
    user_id   INTEGER,
    purpose   TEXT NOT NULL,
    expires   INTEGER NOT NULL
);

-- API tokens for remote agents. Only a hash is stored, so a database leak
-- does not hand anyone a working credential.
CREATE TABLE IF NOT EXISTS api_tokens (
    id        INTEGER PRIMARY KEY,
    user_id   INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name      TEXT NOT NULL,
    hash      TEXT NOT NULL UNIQUE,
    created   INTEGER NOT NULL,
    last_used INTEGER,
    uses      INTEGER NOT NULL DEFAULT 0,
    revoked   INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_tokens_user ON api_tokens(user_id);

CREATE TABLE IF NOT EXISTS login_throttle (
    ip            TEXT PRIMARY KEY,
    fails         INTEGER NOT NULL DEFAULT 0,
    last          INTEGER NOT NULL,
    blocked_until INTEGER NOT NULL DEFAULT 0
);

-- Password reset links an admin hands to someone locked out. Only a hash of
-- the token is stored, single use, short lived - the same posture as the API
-- tokens above.
CREATE TABLE IF NOT EXISTS password_resets (
    id         INTEGER PRIMARY KEY,
    user_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    hash       TEXT NOT NULL UNIQUE,
    created_by INTEGER REFERENCES users(id),
    created    INTEGER NOT NULL,
    expires    INTEGER NOT NULL,
    used_at    INTEGER
);
CREATE INDEX IF NOT EXISTS idx_resets_user ON password_resets(user_id);
"""

PBKDF_ROUNDS = 240_000
SESSION_DAYS = 14
INVITE_HOURS = 48
MAX_FAILS = 5            # per IP before backoff starts
USERNAME_RE = re.compile(r"^[A-Za-z0-9._-]{2,32}$")


def init(con):
    con.executescript(SCHEMA)
    _migrate(con)


# How an account came to exist, recorded on the account itself so it survives
# the invite being revoked or cleaned up.
JOIN_SETUP, JOIN_INVITE, JOIN_MANUAL = "setup", "invite", "manual"


def add_column(con, table, column, decl):
    """Add a column if it is not there yet, tolerating a concurrent add.

    Three processes share this database and any of them may be the first to
    open it after an upgrade, so checking-then-altering is a race the loser
    would otherwise crash on. The check is still worth doing - it keeps the
    common path free of exceptions - but the ALTER has to survive losing.
    """
    have = {r[1] for r in con.execute(f"PRAGMA table_info({table})")}
    if column in have:
        return False
    try:
        con.execute(f"ALTER TABLE {table} ADD COLUMN {column} {decl}")
        return True
    except sqlite3.OperationalError as exc:
        if "duplicate column" not in str(exc).lower():
            raise
        return False


def _migrate(con):
    """Additive only, safe on every open. Never drops or rewrites data."""
    # A pass: one link several people may join on, rather than one seat.
    add_column(con, "invites", "max_uses", "INTEGER NOT NULL DEFAULT 1")
    add_column(con, "invites", "uses", "INTEGER NOT NULL DEFAULT 0")
    add_column(con, "invites", "revoked", "INTEGER NOT NULL DEFAULT 0")
    add_column(con, "invites", "label", "TEXT")
    # Bring pre-pass invites in line: one already-redeemed seat counts as one use
    con.execute("UPDATE invites SET uses = 1 WHERE used_by IS NOT NULL AND uses = 0")
    con.execute(
        "INSERT INTO invite_uses(token, user_id, at) "
        "SELECT token, used_by, COALESCE(used_at, created) FROM invites "
        "WHERE used_by IS NOT NULL AND token NOT IN "
        "(SELECT token FROM invite_uses)")

    add_column(con, "users", "invited_by", "INTEGER")
    add_column(con, "users", "invite_token", "TEXT")
    add_column(con, "users", "join_method", "TEXT")
    # Existing accounts: the founder is 'setup', anything with a recorded
    # invite is 'invite', and the rest were created by hand.
    con.execute(
        "UPDATE users SET join_method = 'invite', invite_token = ("
        "  SELECT iu.token FROM invite_uses iu WHERE iu.user_id = users.id LIMIT 1), "
        "invited_by = (SELECT i.created_by FROM invite_uses iu "
        "  JOIN invites i ON i.token = iu.token WHERE iu.user_id = users.id LIMIT 1) "
        "WHERE join_method IS NULL AND id IN (SELECT user_id FROM invite_uses)")
    first = con.execute("SELECT MIN(id) AS id FROM users").fetchone()
    if first and first["id"]:
        con.execute("UPDATE users SET join_method = 'setup' "
                    "WHERE id = ? AND join_method IS NULL", (first["id"],))
    con.execute("UPDATE users SET join_method = 'manual' WHERE join_method IS NULL")

    # The words changed in 1.1.2: the role once called "owner" is "admin", a
    # "member" is a "user", and "owner" now names the founding account alone.
    # Stored values follow, so the API and the UI never speak two dialects.
    con.execute("UPDATE users SET role = 'admin' WHERE role = 'owner'")
    con.execute("UPDATE users SET role = 'user' WHERE role = 'member'")
    con.execute("UPDATE invites SET role = 'admin' WHERE role = 'owner'")
    con.execute("UPDATE invites SET role = 'user' WHERE role = 'member'")

    # A user may decline two-factor once and not be asked again on every
    # sign-in. Admins cannot decline; the column simply never applies to them.
    add_column(con, "users", "totp_declined", "INTEGER NOT NULL DEFAULT 0")
    # Profile pictures, held on the server so every device shows the same face.
    add_column(con, "users", "avatar", "BLOB")
    add_column(con, "users", "avatar_type", "TEXT")
    add_column(con, "users", "avatar_at", "INTEGER")
    # Appearance preferences follow the account between devices, unless a
    # device opts out and keeps its own.
    add_column(con, "users", "prefs", "TEXT")
    add_column(con, "users", "prefs_at", "INTEGER")


# ------------------------------------------------------------------ passwords

def hash_password(password):
    if not password or len(password) < 8:
        raise ValueError("password must be at least 8 characters")
    salt = secrets.token_bytes(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, PBKDF_ROUNDS)
    return f"pbkdf2_sha256${PBKDF_ROUNDS}${salt.hex()}${dk.hex()}"


def verify_password(stored, password):
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


# ----------------------------------------------------------------------- TOTP

def totp_secret():
    return base64.b32encode(secrets.token_bytes(20)).decode().rstrip("=")


def totp_codes(secret, at=None, window=1):
    """Valid codes around `at`, allowing for clock drift either side."""
    if not secret:
        return []
    pad = "=" * (-len(secret) % 8)
    try:
        key = base64.b32decode(secret + pad, casefold=True)
    except Exception:
        return []
    step = int((at if at is not None else time.time()) // 30)
    out = []
    for drift in range(-window, window + 1):
        msg = struct.pack(">Q", step + drift)
        h = hmac.new(key, msg, hashlib.sha1).digest()
        off = h[-1] & 0x0F
        code = (struct.unpack(">I", h[off:off + 4])[0] & 0x7FFFFFFF) % 1_000_000
        out.append(f"{code:06d}")
    return out


def totp_check(secret, code):
    code = re.sub(r"\s+", "", str(code or ""))
    if not code.isdigit():
        return False
    return any(secrets.compare_digest(code, c) for c in totp_codes(secret))


def totp_uri(username, secret, issuer="AuroraIRC"):
    from urllib.parse import quote
    return (f"otpauth://totp/{quote(issuer)}:{quote(username)}"
            f"?secret={secret}&issuer={quote(issuer)}&period=30&digits=6")


# ---------------------------------------------------------------------- users

def user_by_name(con, username):
    return con.execute("SELECT * FROM users WHERE username = ? COLLATE NOCASE",
                       (str(username or "").strip(),)).fetchone()


def user_by_id(con, uid):
    return con.execute("SELECT * FROM users WHERE id = ?", (uid,)).fetchone()


def any_users(con):
    return con.execute("SELECT COUNT(*) FROM users").fetchone()[0] > 0


def root_id(con):
    """The founding account - root/wheel for this archive.

    Recorded at setup; falls back to the lowest id for archives created before
    the setting existed. It can never be demoted, disabled or removed, so that
    a second owner cannot lock the founder out of their own server.
    """
    row = con.execute("SELECT value FROM settings WHERE key = 'root_user_id'").fetchone()
    if row and str(row["value"]).isdigit():
        return int(row["value"])
    first = con.execute("SELECT MIN(id) AS id FROM users").fetchone()
    return first["id"] if first else None


def is_root(con, uid):
    return uid is not None and uid == root_id(con)


def create_user(con, username, password, role="user", irc_nick=None,
                join_method=None, invited_by=None):
    username = str(username or "").strip()
    if not USERNAME_RE.match(username):
        raise ValueError("usernames are 2-32 chars: letters, digits, . _ -")
    if user_by_name(con, username):
        raise ValueError("that username is taken")
    if role not in ("admin", "user"):
        raise ValueError("unknown role")
    cur = con.execute(
        "INSERT INTO users(username, password, role, irc_nick, created, "
        "join_method, invited_by) VALUES (?,?,?,?,?,?,?)",
        (username, hash_password(password), role,
         (irc_nick or username).strip(), int(time.time()),
         join_method or JOIN_MANUAL, invited_by))
    return cur.lastrowid


def set_password(con, uid, password):
    con.execute("UPDATE users SET password = ? WHERE id = ?",
                (hash_password(password), uid))


# -------------------------------------------------------------------- invites

MAX_PASS_USES = 100


def create_invite(con, by_uid, role="user", hours=INVITE_HOURS, uses=1,
                  label=None):
    """Mint an invite link.

    ``uses`` above one makes it a *pass*: one link several people may join on,
    which is how you hand a room a way in without minting a token each. Every
    redemption is recorded against the token, so an owner can still see exactly
    who came in on which link.
    """
    if role not in ("admin", "user"):
        raise ValueError("unknown role")
    try:
        uses = int(uses or 1)
    except (TypeError, ValueError):
        raise ValueError("uses must be a number")
    if uses < 1 or uses > MAX_PASS_USES:
        raise ValueError(f"a pass is good for 1 to {MAX_PASS_USES} people")
    token = secrets.token_urlsafe(24)
    now = int(time.time())
    con.execute(
        "INSERT INTO invites(token, username, role, created_by, created, expires, "
        "max_uses, uses, revoked, label) VALUES (?,NULL,?,?,?,?,?,0,0,?)",
        (token, role, by_uid, now, now + int(hours) * 3600, uses,
         (str(label).strip()[:48] or None) if label else None))
    return token


def invite_ok(con, token):
    row = con.execute("SELECT * FROM invites WHERE token = ?",
                      (str(token or ""),)).fetchone()
    if not row or row["revoked"]:
        return None
    # <=, not <: an invite whose lifetime has just run out is dead, not valid
    if row["expires"] <= int(time.time()):
        return None
    if (row["uses"] or 0) >= (row["max_uses"] or 1):
        return None
    return row


def revoke_invite(con, token):
    """Kill a link immediately. Accounts already created on it are untouched -
    revoking a pass must not orphan the people who joined honestly."""
    con.execute("UPDATE invites SET revoked = 1 WHERE token = ?", (str(token or ""),))


def redeem_invite(con, token, username, password):
    inv = invite_ok(con, token)
    if not inv:
        raise ValueError("that invite is invalid, used up or has expired")
    if inv["username"] and inv["username"].lower() != str(username).strip().lower():
        raise ValueError(f"this invite is for {inv['username']}")
    uid = create_user(con, username, password, role=inv["role"])
    now = int(time.time())
    con.execute("UPDATE invites SET uses = uses + 1, used_by = COALESCE(used_by, ?), "
                "used_at = COALESCE(used_at, ?) WHERE token = ?", (uid, now, token))
    con.execute("INSERT INTO invite_uses(token, user_id, at) VALUES (?,?,?)",
                (token, uid, now))
    con.execute("UPDATE users SET invited_by = ?, invite_token = ?, "
                "join_method = ? WHERE id = ?",
                (inv["created_by"], token, JOIN_INVITE, uid))
    return uid


def invites(con, include_dead=False):
    """Every invite with its state, creator and who joined on it."""
    now = int(time.time())
    rows = con.execute(
        "SELECT i.*, u.username AS creator FROM invites i "
        "LEFT JOIN users u ON u.id = i.created_by ORDER BY i.created DESC")
    out = []
    for r in rows:
        d = dict(r)
        d.pop("username", None)             # legacy per-seat pin, no longer used
        d["maxUses"] = d.pop("max_uses", 1) or 1
        d["uses"] = d.get("uses") or 0
        d["revoked"] = bool(d.get("revoked"))
        d["expired"] = d["expires"] <= now
        d["spent"] = d["uses"] >= d["maxUses"]
        d["live"] = not (d["revoked"] or d["expired"] or d["spent"])
        d["joiners"] = [
            {"name": x["username"], "at": x["at"]}
            for x in con.execute(
                "SELECT iu.at, us.username FROM invite_uses iu "
                "LEFT JOIN users us ON us.id = iu.user_id "
                "WHERE iu.token = ? ORDER BY iu.at", (d["token"],))
            if x["username"]]
        d.pop("used_by", None)
        d.pop("used_at", None)
        if d["live"] or include_dead:
            out.append(d)
    return out


def user_detail(con, username):
    """Provenance for one account: when it appeared, and by whose hand.

    Owners asked for this so an unfamiliar name in the list can be traced back
    to the link it came in on, rather than being a mystery.
    """
    u = user_by_name(con, username)
    if not u:
        return None
    inviter = None
    if u["invited_by"]:
        row = con.execute("SELECT username FROM users WHERE id = ?",
                          (u["invited_by"],)).fetchone()
        inviter = row["username"] if row else None
    inv = None
    if u["invite_token"]:
        row = con.execute(
            "SELECT i.token, i.role, i.created, i.expires, i.max_uses, i.uses, "
            "i.revoked, i.label, c.username AS creator FROM invites i "
            "LEFT JOIN users c ON c.id = i.created_by WHERE i.token = ?",
            (u["invite_token"],)).fetchone()
        if row:
            inv = dict(row)
            inv["maxUses"] = inv.pop("max_uses", 1) or 1
            inv["isPass"] = inv["maxUses"] > 1
            inv["revoked"] = bool(inv["revoked"])
    joined_at = con.execute(
        "SELECT at FROM invite_uses WHERE user_id = ? ORDER BY at LIMIT 1",
        (u["id"],)).fetchone()
    return {
        "name": u["username"],
        "role": u["role"],
        "owner": is_root(con, u["id"]),
        "nick": u["irc_nick"],
        "disabled": bool(u["disabled"]),
        "created": u["created"],
        "lastSeen": u["last_seen"],
        "totp": bool(u["totp_enabled"]),
        "passkeys": con.execute(
            "SELECT COUNT(*) FROM credentials WHERE user_id = ?",
            (u["id"],)).fetchone()[0],
        "sessions": con.execute(
            "SELECT COUNT(*) FROM sessions WHERE user_id = ? AND expires > ?",
            (u["id"], int(time.time()))).fetchone()[0],
        "joinMethod": u["join_method"] or JOIN_MANUAL,
        "joinedAt": joined_at["at"] if joined_at else u["created"],
        "invitedBy": inviter,
        "invite": inv,
    }


# -------------------------------------------------------- password resets

RESET_HOURS = 24


def create_reset(con, uid, by_uid=None, hours=RESET_HOURS):
    """Mint a single-use password reset link for an account.

    Any older unused links for the same account die with it, so there is only
    ever one live way in and revoking it is as simple as minting a fresh one.
    """
    con.execute("DELETE FROM password_resets WHERE user_id = ? AND used_at IS NULL",
                (uid,))
    token = secrets.token_urlsafe(24)
    now = int(time.time())
    con.execute(
        "INSERT INTO password_resets(user_id, hash, created_by, created, expires) "
        "VALUES (?,?,?,?,?)",
        (uid, _token_hash(token), by_uid, now, now + int(hours) * 3600))
    return token


def reset_ok(con, token):
    row = con.execute(
        "SELECT r.*, u.username, u.disabled FROM password_resets r "
        "JOIN users u ON u.id = r.user_id WHERE r.hash = ?",
        (_token_hash(token),)).fetchone()
    if not row or row["used_at"] or row["disabled"]:
        return None
    if row["expires"] <= int(time.time()):
        return None
    return row


def use_reset(con, token, password):
    """Set a new password on the account a live reset link belongs to."""
    row = reset_ok(con, token)
    if not row:
        raise ValueError("that reset link is invalid, used or has expired")
    set_password(con, row["user_id"], password)
    con.execute("UPDATE password_resets SET used_at = ? WHERE id = ?",
                (int(time.time()), row["id"]))
    # Whoever held the old password holds nothing now
    drop_user_sessions(con, row["user_id"])
    return row["user_id"], row["username"]


# --------------------------------------------------------------- history

HISTORY_KEEP = 40


def record_search(con, uid, query):
    """Remember a search this account ran. Newest wins; the list is capped."""
    q = str(query or "").strip()
    if not q or len(q) > 200:
        return
    now = int(time.time())
    con.execute(
        "INSERT INTO search_history(user_id, query, at) VALUES (?,?,?) "
        "ON CONFLICT(user_id, query) DO UPDATE SET at = excluded.at",
        (uid, q, now))
    con.execute(
        "DELETE FROM search_history WHERE user_id = ? AND id NOT IN "
        "(SELECT id FROM search_history WHERE user_id = ? ORDER BY at DESC LIMIT ?)",
        (uid, uid, HISTORY_KEEP))


def search_history(con, uid, limit=12):
    return [{"query": r["query"], "at": r["at"]} for r in con.execute(
        "SELECT query, at FROM search_history WHERE user_id = ? "
        "ORDER BY at DESC LIMIT ?", (uid, max(1, min(int(limit), 50))))]


def clear_search_history(con, uid, query=None):
    if query:
        con.execute("DELETE FROM search_history WHERE user_id = ? AND query = ?",
                    (uid, str(query)))
    else:
        con.execute("DELETE FROM search_history WHERE user_id = ?", (uid,))


# ------------------------------------------------------------------- sessions

def new_session(con, uid, ip=None, agent=None, days=SESSION_DAYS):
    sid = secrets.token_urlsafe(32)
    csrf = secrets.token_urlsafe(24)
    now = int(time.time())
    con.execute(
        "INSERT INTO sessions(id, user_id, csrf, created, last_seen, expires, ip, agent) "
        "VALUES (?,?,?,?,?,?,?,?)",
        (sid, uid, csrf, now, now, now + days * 86400, ip, (agent or "")[:200]))
    con.execute("UPDATE users SET last_seen = ? WHERE id = ?", (now, uid))
    return sid, csrf


def session(con, sid):
    if not sid:
        return None
    row = con.execute(
        "SELECT s.*, u.username, u.role, u.irc_nick, u.disabled "
        "FROM sessions s JOIN users u ON u.id = s.user_id WHERE s.id = ?",
        (sid,)).fetchone()
    if not row or row["expires"] <= int(time.time()) or row["disabled"]:
        return None
    return row


def touch(con, sid):
    con.execute("UPDATE sessions SET last_seen = ? WHERE id = ?",
                (int(time.time()), sid))


def drop_session(con, sid):
    con.execute("DELETE FROM sessions WHERE id = ?", (sid,))


def drop_user_sessions(con, uid, keep=None):
    if keep:
        con.execute("DELETE FROM sessions WHERE user_id = ? AND id != ?", (uid, keep))
    else:
        con.execute("DELETE FROM sessions WHERE user_id = ?", (uid,))


def purge_expired(con):
    con.execute("DELETE FROM sessions WHERE expires < ?", (int(time.time()),))


# ----------------------------------------------------------- throttle and log

def throttle_check(con, ip):
    """Seconds the caller must wait, or 0 if they may try now."""
    row = con.execute("SELECT * FROM login_throttle WHERE ip = ?", (ip,)).fetchone()
    if not row:
        return 0
    left = row["blocked_until"] - int(time.time())
    return max(0, left)


def throttle_fail(con, ip):
    now = int(time.time())
    row = con.execute("SELECT * FROM login_throttle WHERE ip = ?", (ip,)).fetchone()
    fails = (row["fails"] if row else 0) + 1
    # Nothing for the first few, then doubling backoff capped at 15 minutes
    delay = 0 if fails <= MAX_FAILS else min(900, 2 ** (fails - MAX_FAILS) * 5)
    con.execute(
        "INSERT INTO login_throttle(ip, fails, last, blocked_until) VALUES (?,?,?,?) "
        "ON CONFLICT(ip) DO UPDATE SET fails = excluded.fails, last = excluded.last, "
        "blocked_until = excluded.blocked_until",
        (ip, fails, now, now + delay))
    return delay


def throttle_clear(con, ip):
    con.execute("DELETE FROM login_throttle WHERE ip = ?", (ip,))


def log(con, event, username=None, ip=None, detail=None):
    con.execute(
        "INSERT INTO auth_log(at, event, username, ip, detail) VALUES (?,?,?,?,?)",
        (int(time.time()), event, username, ip,
         json.dumps(detail) if isinstance(detail, (dict, list)) else detail))


# ------------------------------------------------------------------ passkeys

def issue_challenge(con, purpose, user_id=None, seconds=300):
    from . import webauthn as W
    con.execute("DELETE FROM webauthn_challenges WHERE expires < ?",
                (int(time.time()),))
    # /api/passkey/begin is anonymous by necessity, so bound how many live
    # challenges can pile up inside the expiry window.
    if con.execute("SELECT COUNT(*) FROM webauthn_challenges").fetchone()[0] > 500:
        con.execute("DELETE FROM webauthn_challenges WHERE challenge IN "
                    "(SELECT challenge FROM webauthn_challenges "
                    " ORDER BY expires LIMIT 200)")
    ch = W.new_challenge()
    con.execute("INSERT INTO webauthn_challenges(challenge, user_id, purpose, expires) "
                "VALUES (?,?,?,?)",
                (ch, user_id, purpose, int(time.time()) + seconds))
    return ch


def take_challenge(con, challenge, purpose):
    """Consume a challenge. Single use, so a captured one cannot be replayed."""
    row = con.execute(
        "SELECT * FROM webauthn_challenges WHERE challenge = ? AND purpose = ?",
        (str(challenge or ""), purpose)).fetchone()
    if not row:
        return None
    con.execute("DELETE FROM webauthn_challenges WHERE challenge = ?", (row["challenge"],))
    if row["expires"] < int(time.time()):
        return None
    return row


def passkeys(con, uid):
    return [dict(r) for r in con.execute(
        "SELECT id, cred_id, label, created, last_used FROM credentials "
        "WHERE user_id = ? ORDER BY created", (uid,))]


def credential(con, cred_id):
    return con.execute(
        "SELECT c.*, u.username, u.role, u.disabled FROM credentials c "
        "JOIN users u ON u.id = c.user_id WHERE c.cred_id = ?",
        (str(cred_id or ""),)).fetchone()


# ------------------------------------------------------------- api tokens

TOKEN_PREFIX = "irc_"


def _token_hash(token):
    return hashlib.sha256(str(token or "").encode()).hexdigest()


def mint_token(con, uid, name):
    """Create an agent token. The plaintext is returned once and never stored."""
    token = TOKEN_PREFIX + secrets.token_urlsafe(32)
    con.execute("INSERT INTO api_tokens(user_id, name, hash, created) "
                "VALUES (?,?,?,?)",
                (uid, str(name or "agent")[:40], _token_hash(token), int(time.time())))
    return token


def token_owner(con, token):
    """Resolve a bearer token to its user, or None."""
    if not str(token or "").startswith(TOKEN_PREFIX):
        return None
    row = con.execute(
        "SELECT t.*, u.username, u.role, u.disabled FROM api_tokens t "
        "JOIN users u ON u.id = t.user_id "
        "WHERE t.hash = ? AND t.revoked = 0", (_token_hash(token),)).fetchone()
    if not row or row["disabled"]:
        return None
    con.execute("UPDATE api_tokens SET last_used = ?, uses = uses + 1 WHERE id = ?",
                (int(time.time()), row["id"]))
    return row


def tokens(con, uid):
    return [dict(r) for r in con.execute(
        "SELECT id, name, created, last_used, uses FROM api_tokens "
        "WHERE user_id = ? AND revoked = 0 ORDER BY created", (uid,))]


def revoke_token(con, uid, tid):
    con.execute("UPDATE api_tokens SET revoked = 1 WHERE id = ? AND user_id = ?",
                (int(tid), uid))


def recent_log(con, limit=100):
    return [dict(r) for r in con.execute(
        "SELECT at, event, username, ip, detail FROM auth_log "
        "ORDER BY at DESC LIMIT ?", (max(1, min(int(limit), 500)),))]
