"""Join/part/quit traffic, kept apart from conversation.

This module is imported by the web server only. The MCP server imports
ircarchive.query and nothing here, so an agent has no path to this data at
all - it is presentation detail for a human reading a channel, not signal.

Events are fetched for a visible time window rather than paged like messages.
That keeps message offsets (and therefore jump-to-message) exact: conversation
remains the spine of the feed and events are decoration spliced alongside.
"""

from . import db

SELECT = (
    "SELECT e.id, e.ts, e.kind, e.detail, c.name AS channel, n.name AS nick "
    "FROM events e "
    "JOIN channels c ON c.id = e.channel_id "
    "JOIN nicks n ON n.id = e.nick_id"
)


def in_range(con, since, until, channels=None, nicks=None, limit=4000):
    """Events between two timestamps, oldest first."""
    where = ["e.ts >= ?", "e.ts <= ?"]
    args = [int(since), int(until)]

    chans = [c.lstrip("#") for c in (channels or []) if c]
    if chans:
        where.append("c.name IN (%s)" % ",".join("?" * len(chans)))
        args += chans

    nk = [n for n in (nicks or []) if n]
    if nk:
        where.append("n.name IN (%s)" % ",".join("?" * len(nk)))
        args += nk

    rows = con.execute(
        f"{SELECT} WHERE {' AND '.join(where)} ORDER BY e.ts, e.id LIMIT ?",
        args + [max(1, min(int(limit), 8000))])
    return [dict(r) for r in rows]


def stats(con):
    row = con.execute(
        "SELECT COUNT(*) AS total, MIN(ts) AS first, MAX(ts) AS last FROM events"
    ).fetchone()
    per_kind = {db.EVENT_NAMES.get(r["kind"], r["kind"]): r["n"] for r in con.execute(
        "SELECT kind, COUNT(*) AS n FROM events GROUP BY kind")}
    return {"total": row["total"] or 0, "first": row["first"],
            "last": row["last"], "kinds": per_kind}
