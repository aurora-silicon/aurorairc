#!/usr/bin/env python3
"""Read-only MCP server over an AuroraIRC archive.

Speaks MCP over stdio (line-delimited JSON-RPC 2.0) and exposes search and
retrieval tools so an agent can query the archive directly.

Read-only by construction, not merely by convention:

  * the SQLite connection is opened with ``mode=ro``, so the driver itself
    rejects any write, and
  * there is no tool that sends anything to IRC. This server cannot speak on a
    channel; it only reads what has already been recorded.

Usage:
    ./mcp_server.py [--db path/to/archive.db]
"""

import argparse
import json
import sqlite3
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from ircarchive.mcptools import Archive, TOOLS, PROTOCOL_VERSION, SERVER_INFO


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--db", default=str(Path(__file__).resolve().parent / "archive.db"))
    args = ap.parse_args()
    archive = Archive(args.db)

    def send(msg):
        sys.stdout.write(json.dumps(msg) + "\n")
        sys.stdout.flush()

    def result(rid, payload):
        send({"jsonrpc": "2.0", "id": rid, "result": payload})

    def error(rid, code, message):
        send({"jsonrpc": "2.0", "id": rid, "error": {"code": code, "message": message}})

    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            req = json.loads(line)
        except json.JSONDecodeError:
            continue

        method, rid = req.get("method"), req.get("id")

        if method == "initialize":
            asked = (req.get("params") or {}).get("protocolVersion")
            result(rid, {
                "protocolVersion": asked or PROTOCOL_VERSION,
                "capabilities": {"tools": {}},
                "serverInfo": SERVER_INFO,
            })
        elif method in ("notifications/initialized", "initialized"):
            pass  # notification: no reply
        elif method == "ping":
            result(rid, {})
        elif method == "tools/list":
            result(rid, {"tools": TOOLS})
        elif method == "tools/call":
            params = req.get("params") or {}
            name = params.get("name")
            a = params.get("arguments") or {}
            try:
                payload = archive.call(name, a)
                result(rid, {"content": [{"type": "text",
                                          "text": json.dumps(payload, ensure_ascii=False)}]})
            except Exception as exc:
                result(rid, {"content": [{"type": "text", "text": f"error: {exc}"}],
                             "isError": True})
        elif rid is not None:
            error(rid, -32601, f"method not found: {method}")


if __name__ == "__main__":
    main()
