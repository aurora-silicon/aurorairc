"""Importers for history that predates the archivist.

Two kinds of source:

  * **Web archives** — a network can carry a ``log_url`` plus an adapter name.
    ``catirclogs`` reads the whitequark/catirclogs layout used by OFTC.
  * **Client log files** — ZNC, irssi, WeeChat and HexChat, so an existing
    personal log can be folded in.

Everything funnels into the same (channel, nick, ts, kind, text) rows as the
live capture, so imports dedupe against what is already there.
"""

import re
from datetime import datetime, timezone
from pathlib import Path

from . import db

# ---------------------------------------------------------------- file logs

MONTHS = {m: i + 1 for i, m in enumerate(
    ["Jan", "Feb", "Mar", "Apr", "May", "Jun",
     "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"])}

# ZNC:     [12:34:56] <nick> text
RE_ZNC = re.compile(r"^\[(\d{2}):(\d{2}):(\d{2})\]\s+(.*)$")
# irssi:   12:34 <nick> text      plus "--- Day changed Mon Aug 17 2026"
RE_IRSSI = re.compile(r"^(\d{2}):(\d{2})\s+(.*)$")
RE_IRSSI_DAY = re.compile(
    r"^--- (?:Day changed|Log opened) \w+ (\w{3}) (\d{1,2}) (?:(\d{4})|.*? (\d{4}))")
# WeeChat: 2026-08-17 12:34:56\tnick\ttext
RE_WEECHAT = re.compile(
    r"^(\d{4})-(\d{2})-(\d{2}) (\d{2}):(\d{2}):(\d{2})\t([^\t]*)\t(.*)$")
# HexChat: Aug 17 12:34:56 <nick> text
RE_HEXCHAT = re.compile(r"^(\w{3}) (\d{1,2}) (\d{2}):(\d{2}):(\d{2})\s+(.*)$")
RE_HEXCHAT_DAY = re.compile(r"^\*\*\*\* (?:BEGIN|ENDING) LOGGING AT \w+ (\w{3}) *(\d{1,2}) "
                            r"\d{2}:\d{2}:\d{2} (\d{4})")

# Body forms shared across clients
RE_SAY = re.compile(r"^<\s*[@+%~&]?([^>\s]+)\s*>\s?(.*)$")
RE_ACT = re.compile(r"^\*\s+(\S+)\s+(.*)$")


def _ts(y, mo, d, h, mi, s=0):
    return int(datetime(y, mo, d, h, mi, s, tzinfo=timezone.utc).timestamp())


def _body(text):
    """Turn a line body into (kind, nick, text), or None if it isn't speech."""
    m = RE_SAY.match(text)
    if m:
        return db.MSG, m.group(1), m.group(2)
    m = RE_ACT.match(text)
    if m and not text.startswith("*** "):
        return db.ACTION, m.group(1), m.group(2)
    return None


def sniff(path):
    """Guess a client format from the first lines that look like content."""
    try:
        head = Path(path).read_text(encoding="utf-8", errors="replace").split("\n")[:80]
    except OSError:
        return None
    for line in head:
        if RE_WEECHAT.match(line):
            return "weechat"
        if RE_ZNC.match(line):
            return "znc"
        if RE_HEXCHAT.match(line) or RE_HEXCHAT_DAY.match(line):
            return "hexchat"
        if RE_IRSSI_DAY.match(line) or RE_IRSSI.match(line):
            return "irssi"
    return None


def date_from_name(path):
    """ZNC and friends put the date in the filename; irssi often does not."""
    m = re.search(r"(\d{4})[-_]?(\d{2})[-_]?(\d{2})", Path(path).stem)
    return tuple(int(g) for g in m.groups()) if m else None


def channel_from_path(path, fallback=None):
    stem = Path(path).stem
    stem = re.sub(r"[-_]?\d{4}[-_]?\d{2}[-_]?\d{2}$", "", stem)
    name = stem.lstrip("#").strip() or Path(path).parent.name
    return (name or fallback or "unknown").lstrip("#").lower()


def parse_client_log(path, fmt=None, channel=None, year=None):
    """Yield (channel, nick, ts, kind, text) from one client log file."""
    fmt = fmt or sniff(path)
    if not fmt:
        return
    chan = (channel or channel_from_path(path)).lstrip("#")
    text = Path(path).read_text(encoding="utf-8", errors="replace")

    named = date_from_name(path)
    cur = list(named) if named else None          # [y, m, d]
    if cur is None and year:
        cur = [year, 1, 1]

    for line in text.split("\n"):
        line = line.rstrip("\r")
        if not line:
            continue

        if fmt == "weechat":
            m = RE_WEECHAT.match(line)
            if not m:
                continue
            y, mo, d, h, mi, s, nick, body = m.groups()
            nick = nick.strip()
            when = _ts(int(y), int(mo), int(d), int(h), int(mi), int(s))
            if nick == "*":
                # WeeChat puts actions in a '*' column with the nick leading
                # the body: "* \t ivan dances"
                parts = body.strip().split(None, 1)
                if len(parts) == 2:
                    yield chan, parts[0], when, db.ACTION, parts[1]
                continue
            if not nick or nick in ("--", "-->", "<--", "=!=", "‼", "»", "«"):
                # join/part/quit rows use marker nicks; presence is not imported
                continue
            yield chan, nick.lstrip("@+%~&"), when, db.MSG, body
            continue

        if fmt == "irssi":
            dm = RE_IRSSI_DAY.match(line)
            if dm:
                mon, day, y1, y2 = dm.groups()
                y = int(y1 or y2 or (cur[0] if cur else 1970))
                cur = [y, MONTHS.get(mon, 1), int(day)]
                continue
            m = RE_IRSSI.match(line)
            if not m or not cur:
                continue
            h, mi, body = m.groups()
            parsed = _body(body)
            if not parsed:
                continue
            kind, nick, msg = parsed
            yield chan, nick, _ts(cur[0], cur[1], cur[2], int(h), int(mi)), kind, msg
            continue

        if fmt == "hexchat":
            dm = RE_HEXCHAT_DAY.match(line)
            if dm:
                mon, day, y = dm.groups()
                cur = [int(y), MONTHS.get(mon, 1), int(day)]
                continue
            m = RE_HEXCHAT.match(line)
            if not m or not cur:
                continue
            mon, day, h, mi, s, body = m.groups()
            cur = [cur[0], MONTHS.get(mon, cur[1]), int(day)]
            parsed = _body(body)
            if not parsed:
                continue
            kind, nick, msg = parsed
            yield chan, nick, _ts(cur[0], cur[1], cur[2],
                                  int(h), int(mi), int(s)), kind, msg
            continue

        if fmt == "znc":
            m = RE_ZNC.match(line)
            if not m or not cur:
                continue
            h, mi, s, body = m.groups()
            parsed = _body(body)
            if not parsed:
                continue
            kind, nick, msg = parsed
            yield chan, nick, _ts(cur[0], cur[1], cur[2],
                                  int(h), int(mi), int(s)), kind, msg


def import_files(con, paths, fmt=None, channel=None, year=None, batch=20000):
    """Import client logs. Idempotent, like every other ingest path."""
    ids = db.Ids(con)
    files = []
    for p in paths:
        p = Path(p).expanduser()
        if p.is_dir():
            # WeeChat writes .weechatlog, ZNC writes .log, irssi often writes
            # no suffix at all - so allow anything sniff() can recognise.
            files += sorted(x for x in p.rglob("*")
                            if x.is_file() and x.suffix.lower() in
                            (".log", ".txt", ".weechatlog", ".irclog", ""))
        elif p.exists():
            files.append(p)
    total = 0
    for path in files:
        guess = fmt or sniff(path)
        if not guess:
            print(f"  {path.name:<34} unrecognised format, skipped")
            continue
        ids.reset_seq()
        buf, seen, added = [], 0, 0
        con.execute("BEGIN")
        try:
            for row in parse_client_log(path, guess, channel, year):
                buf.append(row); seen += 1
                if len(buf) >= batch:
                    added += db.insert_messages(con, ids, buf, "import"); buf.clear()
            added += db.insert_messages(con, ids, buf, "import")
            con.execute("COMMIT")
        except Exception:
            con.execute("ROLLBACK")
            raise
        total += added
        print(f"  {path.name:<34} {guess:<8} {seen:>7,} parsed  {added:>7,} new")
    return total
