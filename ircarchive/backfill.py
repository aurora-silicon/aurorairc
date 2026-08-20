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
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import urljoin, urlsplit, urlunsplit

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


def sniff_text(text):
    """Guess a client format from the first lines that look like content."""
    for line in str(text or "").split("\n")[:80]:
        if RE_WEECHAT.match(line):
            return "weechat"
        if RE_ZNC.match(line):
            return "znc"
        if RE_HEXCHAT.match(line) or RE_HEXCHAT_DAY.match(line):
            return "hexchat"
        if RE_IRSSI_DAY.match(line) or RE_IRSSI.match(line):
            return "irssi"
    return None


def sniff(path):
    """The same guess, for a file on disk."""
    try:
        return sniff_text(Path(path).read_text(encoding="utf-8", errors="replace"))
    except OSError:
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
    try:
        text = Path(path).read_text(encoding="utf-8", errors="replace")
    except OSError:
        return
    yield from parse_client_text(text, fmt or sniff_text(text), channel=channel,
                                 year=year, name=str(path))


def parse_client_text(text, fmt=None, channel=None, year=None, name="log.txt"):
    """The same parse, for text that never touched the disk.

    Import from a URL and import from a file go through this one function, so
    a log read over HTTP is held to exactly the rules the command line applies
    - the same formats, the same idea of what is speech, the same refusal to
    treat join and quit traffic as conversation.
    """
    path = name
    fmt = fmt or sniff_text(text)
    if not fmt:
        return
    chan = (channel or channel_from_path(path)).lstrip("#")

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


# ------------------------------------------------------------------ importing
#
# The web importer exists so that a Home Assistant install - which has no
# shell - can still take in history. It deliberately owns no parsing of its
# own: every byte goes through the parsers above, or through ingest.py, which
# is what `./archive.py import` and `./archive.py ingest` use. One grammar,
# one dedupe key, whichever door the log came in by.

FORMATS = [
    ("auto",    "Detect automatically"),
    ("export",  "AuroraIRC / web export"),
    ("znc",     "ZNC"),
    ("irssi",   "irssi"),
    ("weechat", "WeeChat"),
    ("hexchat", "HexChat"),
]
FORMAT_KEYS = {k for k, _ in FORMATS}
FORMAT_NAMES = dict(FORMATS)

MAX_DOCS = 60                       # files pulled from one index page
MAX_TOTAL_BYTES = 48 * 1024 * 1024
LOG_SUFFIXES = (".txt", ".log", ".weechatlog", ".irclog")


def detect(text, name=""):
    """Which of the supported formats this text is, or None.

    The export shape is checked first: it carries a full date on every line,
    so a client-log regex would never match it anyway, but being explicit
    keeps the order of preference obvious.
    """
    from . import ingest
    if ingest.looks_like_export(text):
        return "export"
    return sniff_text(text)


def parse_any(text, fmt, channel=None, year=None, name="log.txt", events=False):
    """Rows from one document, in whichever supported format it is."""
    from . import ingest
    if fmt == "export":
        rows = ingest.parse_text(text, name, events=events, quiet=True)
    elif events:
        return                       # presence only exists in the export shape
    else:
        rows = parse_client_text(text, fmt, channel=channel, year=year, name=name)
    override = (channel or "").lstrip("#").lower()
    for chan, nick, ts, kind, body in rows:
        yield (override or chan), nick, ts, kind, body


def import_documents(con, docs, *, fmt="auto", channel=None, year=None,
                     events=False, commit=True, batch=20000, samples=8,
                     source="import"):
    """Import one or more (name, text) documents. Returns a report.

    ``commit=False`` is a dry run: the work is done for real, inside a
    transaction that is then rolled back. That is the only honest way to say
    how many lines are new - the answer depends on what is already stored, and
    the dedupe key is the database's, not something worth reimplementing here.

    Idempotent either way: repeated lines within one document keep their own
    occurrence numbers, and re-importing the same document produces the same
    keys, which INSERT OR IGNORE then drops.
    """
    ids = db.Ids(con)
    report = {"files": [], "seen": 0, "added": 0, "duplicates": 0,
              "channels": [], "nicks": 0, "first": None, "last": None,
              "sample": [], "committed": bool(commit), "events": bool(events),
              "unreadable": []}
    chans, nicks = {}, set()
    insert = db.insert_events if events else db.insert_messages

    con.execute("BEGIN")
    try:
        for name, text in docs:
            use = fmt if fmt and fmt != "auto" else detect(text, name)
            if not use or use not in FORMAT_KEYS or use == "auto":
                report["unreadable"].append(
                    {"name": name, "why": "no supported format recognised"})
                continue
            # Occurrence numbers restart per document, exactly as the command
            # line does between files - otherwise two exports covering the same
            # day would each get fresh numbers and duplicate it.
            ids.reset_seq()
            buf, seen, added = [], 0, 0
            for row in parse_any(text, use, channel=channel, year=year,
                                 name=name, events=events):
                buf.append(row)
                seen += 1
                chan, nick, ts, kind, body = row
                chans[chan] = chans.get(chan, 0) + 1
                nicks.add(nick)
                if report["first"] is None or ts < report["first"]:
                    report["first"] = ts
                if report["last"] is None or ts > report["last"]:
                    report["last"] = ts
                if len(report["sample"]) < samples:
                    report["sample"].append(
                        {"channel": chan, "nick": nick, "ts": ts,
                         "kind": kind, "text": body[:200]})
                if len(buf) >= batch:
                    added += insert(con, ids, buf, source)
                    buf.clear()
            added += insert(con, ids, buf, source)
            if commit and not events:
                db.record_ingest(con, name, seen, added)
            report["files"].append(
                {"name": name, "format": use, "seen": seen, "added": added,
                 "duplicates": seen - added})
            report["seen"] += seen
            report["added"] += added
            report["duplicates"] += seen - added
        con.execute("COMMIT" if commit else "ROLLBACK")
    except Exception:
        con.execute("ROLLBACK")
        raise

    report["channels"] = sorted(
        ({"name": c, "count": n} for c, n in chans.items()),
        key=lambda x: -x["count"])
    report["nicks"] = len(nicks)
    report["format"] = (report["files"][0]["format"] if report["files"]
                        else (fmt if fmt != "auto" else None))
    return report


# ---------------------------------------------------------------- from a URL

class _Links(HTMLParser):
    """Every href on a page, in the order they appear."""

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.hrefs = []

    def handle_starttag(self, tag, attrs):
        if tag != "a":
            return
        for name, value in attrs:
            if name == "href" and value:
                self.hrefs.append(value)


def log_links(html, base):
    """Log files linked from an index page, restricted to the same place.

    A directory listing is the usual shape of a web archive, so following it
    is the point - but only downwards, and only on the same host. A link that
    wanders off elsewhere is not part of this archive and is not fetched.
    """
    parser = _Links()
    parser.feed(html)
    here = urlsplit(base)
    root = here.path.rsplit("/", 1)[0] + "/"
    out, seen = [], set()
    for href in parser.hrefs:
        if href.startswith(("#", "javascript:", "mailto:", "data:")):
            continue
        target = urljoin(base, href)
        parts = urlsplit(target)
        if parts.scheme not in ("http", "https"):
            continue
        if parts.netloc != here.netloc:
            continue
        if not parts.path.startswith(root):
            continue                        # no climbing out of the directory
        if not parts.path.lower().endswith(LOG_SUFFIXES):
            continue
        clean = urlunsplit((parts.scheme, parts.netloc, parts.path, "", ""))
        if clean in seen or clean.rstrip("/") == base.rstrip("/"):
            continue
        seen.add(clean)
        out.append(clean)
    return out


def documents_from_url(url, *, follow=False, max_docs=MAX_DOCS,
                       max_total=MAX_TOTAL_BYTES, timeout=20):
    """Fetch (name, text) documents from a URL. Raises fetching.FetchError."""
    from . import fetching as F
    text, res = F.fetch_text(url, timeout=timeout,
                             max_bytes=min(max_total, F.DEFAULT_MAX_BYTES),
                             accept="text/plain, text/html;q=0.8, */*;q=0.5")
    ctype = (res["headers"].get("content-type") or "").split(";")[0].strip().lower()
    looks_html = ctype in ("text/html", "application/xhtml+xml") or \
        text.lstrip()[:200].lower().startswith(("<!doctype html", "<html"))

    if not looks_html:
        return [(F.filename_of(res["url"], "log.txt"), text)], []

    links = log_links(text, res["url"])
    if not follow:
        raise F.FetchError(
            f"that address is a web page, not a log file"
            + (f" — it links to {len(links)} log file(s); tick "
               f"“follow the links on this page” to pull them in"
               if links else ", and nothing on it looks like a log file"))
    if not links:
        raise F.FetchError("no log files are linked from that page")

    docs, skipped, budget = [], [], max_total - len(text.encode("utf-8", "replace"))
    for link in links[:max_docs]:
        if budget <= 0:
            skipped.append({"name": link, "why": "size limit reached"})
            continue
        try:
            body, sub = F.fetch_text(link, timeout=timeout,
                                     max_bytes=min(budget, F.DEFAULT_MAX_BYTES),
                                     accept="text/plain, */*;q=0.5")
        except F.FetchError as exc:
            skipped.append({"name": link, "why": str(exc)})
            continue
        budget -= len(body.encode("utf-8", "replace"))
        docs.append((F.filename_of(link, "log.txt"), body))
    if len(links) > max_docs:
        skipped.append({"name": f"{len(links) - max_docs} more file(s)",
                        "why": f"only {max_docs} are taken from one page"})
    if not docs:
        raise F.FetchError("none of the linked files could be read")
    return docs, skipped
