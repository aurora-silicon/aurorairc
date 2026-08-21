"""Shared read-only query layer used by both the HTTP API and the MCP server.

Every function here only ever reads. Nothing in this module writes to the
database, which is what lets the MCP server open its connection in read-only
mode and still serve every tool it exposes.
"""

import re
from datetime import datetime, timezone

MAX_LIMIT = 500

SELECT_COLS = (
    "SELECT m.id, m.ts, m.kind, m.text, m.source, "
    "c.name AS channel, n.name AS nick "
    "FROM messages m "
    "JOIN channels c ON c.id = m.channel_id "
    "JOIN nicks n ON n.id = m.nick_id"
)
FROM_ONLY = (
    "FROM messages m "
    "JOIN channels c ON c.id = m.channel_id "
    "JOIN nicks n ON n.id = m.nick_id"
)


def fts_query(raw):
    """Turn user input into a safe FTS5 MATCH expression.

    Each whitespace-separated term becomes a quoted string (implicit AND).
    A trailing '*' is kept as a prefix search and "quoted phrases" stay intact.
    Everything else is escaped, so punctuation can neither raise a syntax error
    nor inject FTS operators.
    """
    out = []
    for t in re.findall(r'"[^"]*"|\S+', (raw or "").strip()):
        inner = t[1:-1] if (t.startswith('"') and t.endswith('"') and len(t) > 1) else t
        prefix = inner.endswith("*")
        if prefix:
            inner = inner[:-1]
        inner = inner.replace('"', '""').strip()
        if inner:
            out.append(f'"{inner}"' + ("*" if prefix else ""))
    return " ".join(out)


def as_ts(value, end_of_day=False):
    """Accept a unix timestamp or an ISO date; return unix seconds or None."""
    if value in (None, ""):
        return None
    s = str(value)
    if re.fullmatch(r"-?\d+", s):
        return int(s)
    m = re.fullmatch(r"(\d{4})-(\d{2})-(\d{2})", s)
    if m:
        y, mo, d = map(int, m.groups())
        t = datetime(y, mo, d, 23, 59, 59 if end_of_day else 0,
                     tzinfo=timezone.utc) if end_of_day else \
            datetime(y, mo, d, tzinfo=timezone.utc)
        return int(t.timestamp())
    raise ValueError(f"cannot parse date/time: {value!r}")


def _listify(v):
    if v is None:
        return []
    if isinstance(v, str):
        return [x for x in v.split(",") if x]
    return [x for x in v if x not in (None, "")]


def build_where(q=None, channels=None, nicks=None, since=None, until=None,
                kinds=None, tags=None):
    where, args, joins = [], [], ""

    expr = fts_query(q) if q else ""
    if expr:
        joins = " JOIN messages_fts f ON f.rowid = m.id "
        where.append("messages_fts MATCH ?")
        args.append(expr)

    chans = [c.lstrip("#") for c in _listify(channels)]
    if chans:
        where.append("c.name IN (%s)" % ",".join("?" * len(chans)))
        args += chans

    nk = _listify(nicks)
    if nk:
        where.append("n.name IN (%s)" % ",".join("?" * len(nk)))
        args += nk

    a = as_ts(since)
    if a is not None:
        where.append("m.ts >= ?")
        args.append(a)
    b = as_ts(until, end_of_day=True)
    if b is not None:
        where.append("m.ts <= ?")
        args.append(b)

    kd = [int(k) for k in _listify(kinds)]
    if kd:
        where.append("m.kind IN (%s)" % ",".join("?" * len(kd)))
        args += kd

    # A &token matches either a tag's own name or any tag of that colour, so
    # "&red" finds everything flagged with a red tag.
    tg = _listify(tags)
    if tg:
        ph = ",".join("?" * len(tg))
        where.append(
            "EXISTS (SELECT 1 FROM message_tags mt JOIN tags t ON t.id = mt.tag_id "
            f"WHERE mt.message_id = m.id AND (t.name IN ({ph}) COLLATE NOCASE "
            f"OR t.color IN ({ph})))")
        args += tg + [t.lower() for t in tg]

    clause = (" WHERE " + " AND ".join(where)) if where else ""
    return joins, clause, args


def attach_tags(con, messages):
    """Fill in each message's tags in one query rather than N."""
    if not messages:
        return messages
    ids = [m["id"] for m in messages if isinstance(m.get("id"), int)]
    if not ids:
        return messages
    rows = con.execute(
        "SELECT mt.message_id, t.name, t.label, t.color FROM message_tags mt "
        "JOIN tags t ON t.id = mt.tag_id "
        f"WHERE mt.message_id IN ({','.join('?' * len(ids))}) ORDER BY t.name",
        ids)
    by_id = {}
    for r in rows:
        by_id.setdefault(r["message_id"], []).append(
            {"name": r["name"], "label": r["label"], "color": r["color"]})
    for m in messages:
        m["tags"] = by_id.get(m["id"], [])
    return messages


def search(con, q=None, channels=None, nicks=None, since=None, until=None,
           kinds=None, tags=None, limit=200, offset=0, order="asc"):
    joins, clause, args = build_where(q, channels, nicks, since, until, kinds, tags)
    limit = max(0, min(int(limit), MAX_LIMIT))
    offset = max(0, int(offset))
    direction = "DESC" if str(order).lower() == "desc" else "ASC"

    total = con.execute(f"SELECT COUNT(*) {FROM_ONLY}{joins}{clause}", args).fetchone()[0]
    rows = con.execute(
        f"{SELECT_COLS}{joins}{clause} ORDER BY m.ts {direction}, m.id {direction} "
        f"LIMIT ? OFFSET ?",
        args + [limit, offset],
    )
    return {"total": total, "offset": offset, "limit": limit,
            "messages": attach_tags(con, [dict(r) for r in rows])}


def context(con, message_id, span=25):
    span = max(1, min(int(span), 200))
    row = con.execute("SELECT ts, channel_id FROM messages WHERE id = ?",
                      (int(message_id),)).fetchone()
    if not row:
        return {"messages": [], "focus": None}
    before = list(con.execute(
        f"{SELECT_COLS} WHERE m.channel_id = ? AND (m.ts < ? OR (m.ts = ? AND m.id < ?)) "
        f"ORDER BY m.ts DESC, m.id DESC LIMIT ?",
        (row["channel_id"], row["ts"], row["ts"], int(message_id), span)))
    after = list(con.execute(
        f"{SELECT_COLS} WHERE m.channel_id = ? AND (m.ts > ? OR (m.ts = ? AND m.id >= ?)) "
        f"ORDER BY m.ts ASC, m.id ASC LIMIT ?",
        (row["channel_id"], row["ts"], row["ts"], int(message_id), span + 1)))
    msgs = [dict(r) for r in reversed(before)] + [dict(r) for r in after]
    return {"messages": attach_tags(con, msgs), "focus": int(message_id)}


def locate(con, message_id, q=None, channels=None, nicks=None, since=None,
           until=None, kinds=None, tags=None, order="asc", in_channel=False):
    """Position of a message within a filtered result set.

    Lets the viewer jump straight to a message and keep paging in both
    directions, rather than only being able to show it in isolation.
    Returns index -1 when the message falls outside the current filters.

    With ``in_channel`` the message's own channel is applied as the filter, so
    the surrounding context reads as one conversation instead of every channel
    interleaved. The channel is returned either way, so the caller can reflect
    it in the UI without a second round trip.
    """
    row = con.execute(
        "SELECT m.ts, c.name AS channel, n.name AS nick FROM messages m "
        "JOIN channels c ON c.id = m.channel_id "
        "JOIN nicks n ON n.id = m.nick_id WHERE m.id = ?",
        (int(message_id),)).fetchone()
    if not row:
        return {"index": -1, "total": 0, "channel": None, "nick": None}

    if in_channel:
        channels = [row["channel"]]

    joins, clause, args = build_where(q, channels, nicks, since, until, kinds, tags)
    total = con.execute(f"SELECT COUNT(*) {FROM_ONLY}{joins}{clause}", args).fetchone()[0]

    # Count rows that sort before the target under the same ORDER BY that
    # search() uses, so the index lines up with an offset exactly.
    ahead = ("(m.ts > ? OR (m.ts = ? AND m.id > ?))" if str(order).lower() == "desc"
             else "(m.ts < ? OR (m.ts = ? AND m.id < ?))")
    joiner = " AND " if clause else " WHERE "
    idx = con.execute(
        f"SELECT COUNT(*) {FROM_ONLY}{joins}{clause}{joiner}{ahead}",
        args + [row["ts"], row["ts"], int(message_id)]).fetchone()[0]

    # Confirm the message itself survives the filters
    present = con.execute(
        f"SELECT 1 {FROM_ONLY}{joins}{clause}{joiner}m.id = ? LIMIT 1",
        args + [int(message_id)]).fetchone()
    return {"index": idx if present else -1, "total": total,
            "channel": row["channel"], "nick": row["nick"]}


def tags(con):
    """Every tag with how many messages carry it."""
    return [dict(r) for r in con.execute(
        "SELECT t.id, t.name, t.label, t.color, t.builtin, "
        "COUNT(mt.message_id) AS count "
        "FROM tags t LEFT JOIN message_tags mt ON mt.tag_id = t.id "
        "GROUP BY t.id ORDER BY count DESC, t.name")]


def activity(con, q=None, channels=None, nicks=None, since=None, until=None,
             kinds=None, tags=None, bucket="month"):
    fmt = {"day": "%Y-%m-%d", "month": "%Y-%m", "year": "%Y"}.get(bucket, "%Y-%m")
    joins, clause, args = build_where(q, channels, nicks, since, until, kinds, tags)
    rows = con.execute(
        f"SELECT strftime('{fmt}', m.ts, 'unixepoch') AS bucket, COUNT(*) AS count "
        f"{FROM_ONLY}{joins}{clause} GROUP BY bucket ORDER BY bucket", args)
    return {"bucket": bucket, "buckets": [dict(r) for r in rows]}


def channels(con):
    return [dict(r) for r in con.execute(
        "SELECT c.name, COUNT(*) AS count, MIN(m.ts) AS first, MAX(m.ts) AS last "
        "FROM messages m JOIN channels c ON c.id = m.channel_id "
        "GROUP BY c.name ORDER BY count DESC")]


def nicks(con, channel=None, limit=200, sort="count", contains=None, offset=0):
    where, args = [], []
    if channel:
        where.append("c.name = ?")
        args.append(str(channel).lstrip("#"))
    if contains:
        where.append("n.name LIKE ?")
        args.append(f"%{contains}%")
    clause = (" WHERE " + " AND ".join(where)) if where else ""
    order = {"name": "n.name ASC", "recent": "last DESC"}.get(sort, "count DESC")
    rows = con.execute(
        f"SELECT n.name, COUNT(*) AS count, MIN(m.ts) AS first, MAX(m.ts) AS last "
        f"FROM messages m JOIN nicks n ON n.id = m.nick_id "
        f"JOIN channels c ON c.id = m.channel_id{clause} "
        f"GROUP BY n.name ORDER BY {order} LIMIT ? OFFSET ?",
        args + [max(1, min(int(limit), 2000)), max(0, int(offset))])
    return [dict(r) for r in rows]


def nick_count(con, channel=None, contains=None):
    """How many speaking nicks match the people-directory query."""
    where, args = [], []
    if channel:
        where.append("c.name = ?")
        args.append(str(channel).lstrip("#"))
    if contains:
        where.append("n.name LIKE ?")
        args.append(f"%{contains}%")
    clause = (" WHERE " + " AND ".join(where)) if where else ""
    row = con.execute(
        "SELECT COUNT(DISTINCT n.id) AS count FROM messages m "
        "JOIN nicks n ON n.id = m.nick_id "
        f"JOIN channels c ON c.id = m.channel_id{clause}", args).fetchone()
    return row["count"] or 0


def speakers(con):
    """Names of everyone who has actually said something.

    Used to decide whether "someone:" in a message is a real person worth
    linking. Deliberately not every known nick - two thirds of those only ever
    joined and quit, and shipping them would quadruple the payload.
    """
    return [r["name"] for r in con.execute(
        "SELECT n.name FROM nicks n WHERE EXISTS "
        "(SELECT 1 FROM messages m WHERE m.nick_id = n.id)")]


def meta(con):
    row = con.execute(
        "SELECT COUNT(*) AS total, MIN(ts) AS first, MAX(ts) AS last FROM messages"
    ).fetchone()
    return {"channels": channels(con), "nicks": nicks(con, limit=2000),
            "total": row["total"] or 0, "first": row["first"], "last": row["last"]}
