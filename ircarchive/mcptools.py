"""The MCP tool surface, shared by both transports.

One definition, used by the stdio server (mcp_server.py) and the HTTP endpoint
in server.py, so an agent gets the same tools and the same read-only guarantee
whichever way it connects.

Every connection here is opened with ``mode=ro``: the driver itself refuses
writes, so no amount of wrong code in this path can alter the archive.
"""

import json
import sqlite3
from pathlib import Path

from . import query as Q

PROTOCOL_VERSION = "2025-06-18"
SERVER_INFO = {"name": "irc-archive", "version": "1.1.0"}


_FILTERS = {
    "q": {"type": "string",
          "description": "Full-text search. Terms are ANDed; \"quoted phrases\" "
                         "and trailing * prefixes are supported."},
    "channels": {"type": "array", "items": {"type": "string"},
                 "description": "Restrict to these channels, e.g. [\"mychannel\"]."},
    "nicks": {"type": "array", "items": {"type": "string"},
              "description": "Restrict to these nicks."},
    "since": {"type": "string", "description": "ISO date (YYYY-MM-DD) or unix seconds."},
    "until": {"type": "string", "description": "ISO date (YYYY-MM-DD) or unix seconds."},
    "kinds": {"type": "array", "items": {"type": "integer"},
              "description": "0 = message, 1 = /me action, 2 = topic change."},
    "tags": {"type": "array", "items": {"type": "string"},
             "description": "Only messages flagged with these tags. Accepts a tag "
                            "name (\"important\", \"gpu\") or a colour (\"red\"), "
                            "which matches every tag of that colour."},
}

TOOLS = [
    {
        "name": "search_messages",
        "description": "Search the IRC archive. Returns matching messages with "
                       "ids, timestamps, channel and nick. Use offset to page.",
        "inputSchema": {
            "type": "object",
            "properties": {
                **_FILTERS,
                "limit": {"type": "integer", "description": "Max rows (default 50, cap 500)."},
                "offset": {"type": "integer", "description": "Rows to skip (default 0)."},
                "order": {"type": "string", "enum": ["asc", "desc"],
                          "description": "Chronological direction (default asc)."},
            },
        },
    },
    {
        "name": "get_context",
        "description": "Fetch the messages surrounding a given message id, so a "
                       "search hit can be read in the flow of its conversation.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "message_id": {"type": "integer"},
                "span": {"type": "integer",
                         "description": "Messages either side (default 25, cap 200)."},
            },
            "required": ["message_id"],
        },
    },
    {
        "name": "list_channels",
        "description": "List archived channels with message counts and date ranges.",
        "inputSchema": {"type": "object", "properties": {}},
    },
    {
        "name": "list_nicks",
        "description": "List people in the archive with message counts and "
                       "first/last activity. Sort by count, name or recency.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "channel": {"type": "string"},
                "contains": {"type": "string", "description": "Substring filter on the nick."},
                "sort": {"type": "string", "enum": ["count", "name", "recent"]},
                "limit": {"type": "integer", "description": "Default 200, cap 2000."},
            },
        },
    },
    {
        "name": "activity",
        "description": "Message counts bucketed by day, month or year. Useful for "
                       "spotting when a topic was being discussed.",
        "inputSchema": {
            "type": "object",
            "properties": {
                **_FILTERS,
                "bucket": {"type": "string", "enum": ["day", "month", "year"]},
            },
        },
    },
    {
        "name": "archive_stats",
        "description": "Overall archive summary: totals, channels, date bounds.",
        "inputSchema": {"type": "object", "properties": {}},
    },
    {
        "name": "list_tags",
        "description": "List the flags used to mark messages, with colours and "
                       "how many messages carry each. Use these names with the "
                       "'tags' filter on search_messages.",
        "inputSchema": {"type": "object", "properties": {}},
    },
    {
        "name": "locate_message",
        "description": "Where a message sits within a filtered result set, as a "
                       "0-based index, plus its channel and nick. Use the index "
                       "as an offset on search_messages to read around it.",
        "inputSchema": {
            "type": "object",
            "properties": {
                **_FILTERS,
                "message_id": {"type": "integer"},
                "in_channel": {"type": "boolean",
                               "description": "Scope the index to the message's own channel."},
                "order": {"type": "string", "enum": ["asc", "desc"]},
            },
            "required": ["message_id"],
        },
    },
]


class Archive:
    def __init__(self, path):
        path = Path(path).resolve()
        if not path.exists():
            raise SystemExit(f"database not found: {path}\nRun ./archive.py ingest first.")
        # mode=ro: the driver refuses writes, so a bug here cannot mutate the archive
        self.con = sqlite3.connect(f"file:{path}?mode=ro", uri=True,
                                   check_same_thread=False)
        self.con.row_factory = sqlite3.Row

    def _filters(self, a):
        return {"q": a.get("q"), "channels": a.get("channels"),
                "nicks": a.get("nicks"), "since": a.get("since"),
                "until": a.get("until"), "kinds": a.get("kinds"),
                "tags": a.get("tags")}

    def call(self, name, a):
        if name == "search_messages":
            return Q.search(self.con, **self._filters(a),
                            limit=a.get("limit", 50), offset=a.get("offset", 0),
                            order=a.get("order", "asc"))
        if name == "get_context":
            return Q.context(self.con, a["message_id"], a.get("span", 25))
        if name == "list_channels":
            return {"channels": Q.channels(self.con)}
        if name == "list_nicks":
            return {"nicks": Q.nicks(self.con, channel=a.get("channel"),
                                     limit=a.get("limit", 200),
                                     sort=a.get("sort", "count"),
                                     contains=a.get("contains"))}
        if name == "activity":
            return Q.activity(self.con, **self._filters(a),
                              bucket=a.get("bucket", "month"))
        if name == "archive_stats":
            m = Q.meta(self.con)
            return {"total": m["total"], "first": m["first"], "last": m["last"],
                    "channels": m["channels"], "distinct_nicks": len(m["nicks"]),
                    "tags": Q.tags(self.con)}
        if name == "list_tags":
            return {"tags": Q.tags(self.con)}
        if name == "locate_message":
            return Q.locate(self.con, a["message_id"], **self._filters(a),
                            order=a.get("order", "asc"),
                            in_channel=bool(a.get("in_channel", False)))
        raise ValueError(f"unknown tool: {name}")


