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
import struct
import time

SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id           INTEGER PRIMARY KEY,
    username     TEXT NOT NULL UNIQUE COLLATE NOCASE,
    password     TEXT,                      -- NULL until an invite is redeemed
    role         TEXT NOT NULL DEFAULT 'member',   -- 'owner' | 'member'
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
"""

PBKDF_ROUNDS = 240_000
SESSION_DAYS = 14
INVITE_HOURS = 48
MAX_FAILS = 5            # per IP before backoff starts
USERNAME_RE = re.compile(r"^[A-Za-z0-9._-]{2,32}$")


def init(con):
    con.executescript(SCHEMA)


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


def create_user(con, username, password, role="member", irc_nick=None):
    username = str(username or "").strip()
    if not USERNAME_RE.match(username):
        raise ValueError("usernames are 2-32 chars: letters, digits, . _ -")
    if user_by_name(con, username):
        raise ValueError("that username is taken")
    if role not in ("owner", "member"):
        raise ValueError("unknown role")
    cur = con.execute(
        "INSERT INTO users(username, password, role, irc_nick, created) "
        "VALUES (?,?,?,?,?)",
        (username, hash_password(password), role,
         (irc_nick or username).strip(), int(time.time())))
    return cur.lastrowid


def set_password(con, uid, password):
    con.execute("UPDATE users SET password = ? WHERE id = ?",
                (hash_password(password), uid))


# -------------------------------------------------------------------- invites

def create_invite(con, by_uid, username=None, role="member", hours=INVITE_HOURS):
    if role not in ("owner", "member"):
        raise ValueError("unknown role")
    if username and not USERNAME_RE.match(username.strip()):
        raise ValueError("invalid username")
    token = secrets.token_urlsafe(24)
    now = int(time.time())
    con.execute(
        "INSERT INTO invites(token, username, role, created_by, created, expires) "
        "VALUES (?,?,?,?,?,?)",
        (token, (username or "").strip() or None, role, by_uid, now,
         now + int(hours) * 3600))
    return token


def invite_ok(con, token):
    row = con.execute("SELECT * FROM invites WHERE token = ?",
                      (str(token or ""),)).fetchone()
    # <=, not <: an invite whose lifetime has just run out is dead, not valid
    if not row or row["used_by"] or row["expires"] <= int(time.time()):
        return None
    return row


def redeem_invite(con, token, username, password):
    inv = invite_ok(con, token)
    if not inv:
        raise ValueError("that invite is invalid or has expired")
    if inv["username"] and inv["username"].lower() != str(username).strip().lower():
        raise ValueError(f"this invite is for {inv['username']}")
    uid = create_user(con, username, password, role=inv["role"])
    con.execute("UPDATE invites SET used_by = ?, used_at = ? WHERE token = ?",
                (uid, int(time.time()), token))
    return uid


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
