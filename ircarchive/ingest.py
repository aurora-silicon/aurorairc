"""Parse exported IRC logs into the archive database.

Handles both shapes produced by the downloader:

  * ``<channel>-chat.txt``  - merged, conversation only, with day headers
  * ``irc_logs_cache/<channel>/<date>.txt`` - raw daily export including
    join/quit traffic, which is filtered out here

Ingest is idempotent: re-running over an overlapping export inserts only the
rows that are genuinely new, so pulling a fresh export later is cheap.
"""

import re
from datetime import datetime, timezone
from pathlib import Path

from . import db

# MULTILINE matters: this is used both with .match() on a single line and with
# .search() over a whole file, where '$' would otherwise only match at the end
# of the entire string and channel detection would fall through to the filename.
RE_HEADER = re.compile(r"^--- Logs for (\d{4}-\d{2}-\d{2}) \(#([^)]+)\) ---\s*$", re.MULTILINE)
RE_MSG = re.compile(r"^(\d{4}-\d{2}-\d{2}) (\d{2}):(\d{2}) <([^>]+)> ?(.*)$")
RE_TOPIC = re.compile(
    r"^(\d{4}-\d{2}-\d{2}) (\d{2}):(\d{2}) (\S+) changed the topic of (\S+) to: ?(.*)$"
)
RE_ACTION = re.compile(r"^(\d{4}-\d{2}-\d{2}) (\d{2}):(\d{2}) \* (\S+) ?(.*)$")
# join/quit/part/nick/kick/mode - stored separately from conversation
RE_EVENT = re.compile(
    r"^(\d{4}-\d{2}-\d{2}) (\d{2}):(\d{2}) (\S+) "
    r"(has joined|has quit|has left|has parted|is now known as|was kicked|sets mode)"
    r"\s*(.*)$"
)
EVENT_KIND = {
    "has joined": db.EV_JOIN,
    "has left": db.EV_PART,
    "has parted": db.EV_PART,
    "has quit": db.EV_QUIT,
    "is now known as": db.EV_NICK,
    "was kicked": db.EV_KICK,
    "sets mode": db.EV_MODE,
}
RE_CHAN_HINT = re.compile(r"has joined (#\S+)")


def _ts(date, hh, mm):
    dt = datetime(int(date[0:4]), int(date[5:7]), int(date[8:10]),
                  int(hh), int(mm), tzinfo=timezone.utc)
    return int(dt.timestamp())


def channel_for(path, text):
    """Best-effort channel name for a log file."""
    m = RE_HEADER.search(text)
    if m:
        return m.group(2)
    m = RE_CHAN_HINT.search(text)
    if m:
        return m.group(1).lstrip("#")
    name = Path(path).stem
    for suffix in ("-chat", "-events", "-logs-accumulated"):
        if name.endswith(suffix):
            return name[: -len(suffix)]
    # raw cache layout: <cache>/<channel>/<date>.txt
    parent = Path(path).parent.name
    if parent and re.fullmatch(r"\d{4}-\d{2}-\d{2}", name):
        return parent
    return parent or name


def parse_file(path, events=False):
    """Yield rows from a log file.

    With ``events`` false: (channel, nick, ts, kind, text) for conversation.
    With ``events`` true:  (channel, nick, ts, kind, detail) for join/quit
    traffic. The two are stored in different tables and never mixed.
    """
    raw = Path(path).read_text(encoding="utf-8", errors="replace")
    channel = channel_for(path, raw)
    skipped = 0
    seen = 0

    # split("\n") rather than splitlines(): the latter also breaks on U+0085 and
    # form feed, which occur inside pasted message bodies and would fragment them
    for line in raw.split("\n"):
        line = line.rstrip("\r")
        if not line or RE_HEADER.match(line):
            continue

        if events:
            m = RE_EVENT.match(line)
            if m:
                date, hh, mm, nick, verb, detail = m.groups()
                kind = EVENT_KIND[verb]
                detail = detail.strip()
                # Exports write the channel into the detail ("has joined
                # #channel"); live capture does not. Left as-is the two sources
                # disagree on the dedupe key and every event is stored twice.
                if kind == db.EV_JOIN:
                    detail = ""
                elif kind == db.EV_PART:
                    detail = re.sub(r"^#\S+\s*", "", detail)
                seen += 1
                yield channel, nick, _ts(date, hh, mm), kind, detail
            continue

        m = RE_MSG.match(line)
        if m:
            date, hh, mm, nick, text = m.groups()
            seen += 1
            yield channel, nick, _ts(date, hh, mm), db.MSG, text
            continue

        m = RE_TOPIC.match(line)
        if m:
            date, hh, mm, nick, chan, text = m.groups()
            seen += 1
            yield chan.lstrip("#") or channel, nick, _ts(date, hh, mm), db.TOPIC, text
            continue

        m = RE_ACTION.match(line)
        if m:
            date, hh, mm, nick, text = m.groups()
            seen += 1
            yield channel, nick, _ts(date, hh, mm), db.ACTION, text
            continue

        if RE_EVENT.match(line):
            continue  # join/quit noise

        skipped += 1

    if skipped:
        print(f"    note: {skipped} line(s) in {Path(path).name} matched no known format")


def discover(paths, events=False):
    """Expand directories into the log files they contain."""
    pattern = "*-events.txt" if events else "*-chat.txt"
    out = []
    for p in paths:
        p = Path(p).expanduser()
        if p.is_dir():
            found = sorted(p.glob(pattern))
            if not found:
                # raw cache directory: every day file holds both kinds
                found = sorted(p.glob("*/*.txt"))
            out.extend(found)
        elif p.exists():
            # An explicit file is used as given, whichever mode we're in
            out.append(p)
        else:
            print(f"    skip: {p} does not exist")
    return out


def ingest(con, paths, batch=20000, events=False):
    ids = db.Ids(con)
    files = discover(paths, events=events)
    if not files:
        print("Nothing to ingest.")
        return 0

    insert = db.insert_events if events else db.insert_messages
    grand_total = 0
    for path in files:
        buf, seen, inserted = [], 0, 0
        ids.reset_seq()
        con.execute("BEGIN")
        try:
            for row in parse_file(path, events=events):
                buf.append(row)
                seen += 1
                if len(buf) >= batch:
                    inserted += insert(con, ids, buf, "export")
                    buf.clear()
            inserted += insert(con, ids, buf, "export")
            db.record_ingest(con, path, seen, inserted)
            con.execute("COMMIT")
        except Exception:
            con.execute("ROLLBACK")
            raise

        grand_total += inserted
        dupes = seen - inserted
        print(f"  {Path(path).name:<28} {seen:>7,} parsed  "
              f"{inserted:>7,} new  {dupes:>7,} already present")

    return grand_total
