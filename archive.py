#!/usr/bin/env python3
"""AuroraIRC - an IRC client and searchable archive.

Typical first run:

  ./archive.py network add libera --host irc.libera.chat --channels mychannel
  ./archive.py serve            # open the page and create the owner account
  ./archive.py live             # connect and start recording

Other commands: ingest, import, token, adduser, stats.
"""

import argparse
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from ircarchive import db, ingest as ingest_mod, server as server_mod

DEFAULT_DB = Path(__file__).resolve().parent / "archive.db"


def cmd_ingest(args):
    con = db.connect(args.db)
    kind = "event" if args.events else "message"
    print(f"Ingesting {kind}s into {args.db}")
    total = ingest_mod.ingest(con, args.paths, events=args.events)
    print(f"\n{total:,} new {kind}(s) stored.")
    con.execute("PRAGMA optimize")
    con.close()


def cmd_serve(args):
    server_mod.serve(args.db, host=args.host, port=args.port,
                     behind_proxy=args.behind_proxy,
                     proxy_hops=args.proxy_hops)


def cmd_live(args):
    """Run every configured network's archivist, plus outbound sending.

    Archivists are read-only and stay connected regardless of who is signed
    in; user messages go out over separate send-only connections.
    """
    import signal
    from ircarchive.connections import Manager

    con = db.connect(args.db)
    if not db.networks(con, enabled_only=True):
        # Say so, but stay running. A network can be added from Settings at any
        # moment and the manager notices within ten seconds. Exiting instead
        # makes a fresh install respawn forever under systemd or s6.
        print("No networks configured yet. Add one in Settings, or:")
        print("  ./archive.py network add libera --host irc.libera.chat "
              "--channels mychannel")
        print("Waiting for a network to be configured...")
    con.close()

    mgr = Manager(args.db, verbose=not args.quiet)
    signal.signal(signal.SIGINT, lambda *a: mgr.stop())
    signal.signal(signal.SIGTERM, lambda *a: mgr.stop())
    mgr.run()


def cmd_import(args):
    from ircarchive import backfill
    con = db.connect(args.db)
    print(f"Importing client logs into {args.db}")
    total = backfill.import_files(con, args.paths, fmt=args.format,
                                  channel=args.channel, year=args.year)
    print(f"\n{total:,} new message(s) stored.")
    con.execute("PRAGMA optimize")
    con.close()


def cmd_network(args):
    con = db.connect(args.db)
    if args.action == "list":
        for n in db.networks(con):
            chans = db.network_channels(con, n["id"], archived_only=False)
            state = "" if n["enabled"] else "  (disabled)"
            print(f"{n['id']}. {n['name']} — {n['host']}:{n['port']} "
                  f"{'TLS' if n['tls'] else 'plain'} as {n['archivist_nick']}{state}")
            print(f"     channels: {', '.join('#'+c for c in chans) or '(none)'}")
            if n["log_url"]:
                print(f"     backfill: {n['log_adapter']} {n['log_url']}")
    elif args.action == "add":
        cur = con.execute(
            "INSERT INTO networks(name, label, host, port, tls, archivist_nick, "
            "log_url, log_adapter, created) VALUES (?,?,?,?,?,?,?,?,?)",
            (args.name, args.label or args.name.upper(), args.host, args.port,
             0 if args.no_tls else 1, args.nick, args.log_url, args.log_adapter,
             int(time.time())))
        nid = cur.lastrowid
        for ch in (args.channels or "").split(","):
            ch = ch.strip().lstrip("#")
            if ch:
                con.execute("INSERT OR IGNORE INTO channels(name, network_id) "
                            "VALUES (?,?)", (ch, nid))
                con.execute("UPDATE channels SET network_id = ? WHERE name = ? "
                            "AND network_id IS NULL", (nid, ch))
        print(f"Added network '{args.name}' (#{nid}).")
    elif args.action == "channels":
        net = con.execute("SELECT * FROM networks WHERE name = ? COLLATE NOCASE",
                          (args.name,)).fetchone()
        if not net:
            print(f"No network called {args.name!r}.")
        else:
            for ch in (args.channels or "").split(","):
                ch = ch.strip().lstrip("#")
                if ch:
                    con.execute("INSERT OR IGNORE INTO channels(name, network_id) "
                                "VALUES (?,?)", (ch, net["id"]))
            print(f"{args.name}: " +
                  ", ".join("#" + c for c in db.network_channels(con, net["id"])))
    con.close()


def cmd_adduser(args):
    import getpass
    from ircarchive import auth
    con = db.connect(args.db)
    role = "owner" if args.owner else "member"
    if role == "owner" and auth.any_users(con) and not args.force:
        print("Users already exist. Invite from the app instead, or pass --force.")
        return
    name = args.username or input("Username: ").strip()
    new = getpass.getpass("Password: ")
    if new != getpass.getpass("Repeat: "):
        print("They don't match.")
        return
    try:
        auth.create_user(con, name, new, role=role, irc_nick=args.nick)
    except ValueError as exc:
        print(exc)
        return
    auth.log(con, "user_created_cli", username=name)
    print(f"Created {role} '{name}'. Sign in from the app.")
    con.close()


def cmd_token(args):
    from ircarchive import auth
    con = db.connect(args.db)
    u = auth.user_by_name(con, args.username)
    if not u:
        print(f"No user called {args.username!r}.")
        return
    tok = auth.mint_token(con, u["id"], args.name)
    auth.log(con, "token_create_cli", username=u["username"], detail=args.name)
    print(f"Token for {u['username']} ({args.name}):\n\n  {tok}\n")
    print("Shown once - only a hash is stored. Give it to the agent as:")
    print('  Authorization: Bearer <token>')
    con.close()


def cmd_passwd(args):
    """Kept as an alias so the old muscle memory still lands somewhere useful."""
    from ircarchive import auth
    con = db.connect(args.db)
    if not auth.any_users(con):
        print("No accounts yet. Create the owner with:\n  ./archive.py adduser --owner")
    else:
        print("Passwords are per-user now. Change yours in the app under Settings,")
        print("or add another account with:\n  ./archive.py adduser")
    con.close()


def cmd_stats(args):
    con = db.connect(args.db)
    row = con.execute(
        "SELECT COUNT(*) n, MIN(ts) a, MAX(ts) b FROM messages"
    ).fetchone()
    if not row["n"]:
        print("Archive is empty - run 'ingest' first.")
        return
    fmt = lambda t: con.execute(
        "SELECT datetime(?, 'unixepoch')", (t,)
    ).fetchone()[0]
    print(f"Database : {args.db}")
    print(f"Messages : {row['n']:,}")
    print(f"Range    : {fmt(row['a'])} .. {fmt(row['b'])} UTC\n")

    print("Per channel:")
    for r in con.execute(
        "SELECT c.name, COUNT(*) n, COUNT(DISTINCT m.nick_id) people "
        "FROM messages m JOIN channels c ON c.id = m.channel_id "
        "GROUP BY c.name ORDER BY n DESC"
    ):
        print(f"  #{r['name']:<16} {r['n']:>8,} messages  {r['people']:>5,} nicks")

    print("\nMost active nicks:")
    for r in con.execute(
        "SELECT n.name, COUNT(*) c FROM messages m JOIN nicks n ON n.id = m.nick_id "
        "GROUP BY n.name ORDER BY c DESC LIMIT 10"
    ):
        print(f"  {r['name']:<24} {r['c']:>7,}")

    live = con.execute(
        "SELECT COUNT(*) n FROM messages WHERE source = 'live'"
    ).fetchone()["n"]
    if live:
        print(f"\nCaptured live: {live:,}")
    con.close()


def main():
    # Redirected stdout is block-buffered, which would leave a long-running
    # serve/live log empty for hours - including the access token line.
    sys.stdout.reconfigure(line_buffering=True)

    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--db", default=str(DEFAULT_DB), help="database path")
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("ingest", help="import exported log files (idempotent)")
    p.add_argument("paths", nargs="+", help="files or directories")
    p.add_argument("--events", action="store_true",
                   help="import *-events.txt (joins/quits) instead of conversation")
    p.set_defaults(func=cmd_ingest)

    p = sub.add_parser("serve", help="run the web viewer")
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", type=int, default=8420)
    p.add_argument("--behind-proxy", action="store_true",
                   help="trust proxy headers (only behind a proxy you control)")
    p.add_argument("--proxy-hops", type=int, default=1,
                   help="how many proxies sit in front; the client IP is counted "
                        "in from the right of X-Forwarded-For")
    p.set_defaults(func=cmd_serve)

    p = sub.add_parser("live", help="run every network's archivist and send queue")
    p.add_argument("--quiet", action="store_true")
    p.set_defaults(func=cmd_live)

    p = sub.add_parser("import", help="import ZNC / irssi / WeeChat / HexChat logs")
    p.add_argument("paths", nargs="+", help="files or directories")
    p.add_argument("--format", choices=["znc", "irssi", "weechat", "hexchat"],
                   help="skip detection and force a format")
    p.add_argument("--channel", help="override the channel name")
    p.add_argument("--year", type=int,
                   help="starting year, for formats whose lines carry no year")
    p.set_defaults(func=cmd_import)

    p = sub.add_parser("network", help="configure IRC networks and channels")
    p.add_argument("action", choices=["list", "add", "channels"])
    p.add_argument("name", nargs="?")
    p.add_argument("--host")
    p.add_argument("--port", type=int, default=6697)
    p.add_argument("--label")
    p.add_argument("--nick", default="aurora", help="archivist nick for this network")
    p.add_argument("--channels", help="comma separated, without '#'")
    p.add_argument("--log-url", dest="log_url")
    p.add_argument("--log-adapter", dest="log_adapter", default=None,
                   help="web archive format, e.g. catirclogs")
    p.add_argument("--no-tls", action="store_true")
    p.set_defaults(func=cmd_network)

    p = sub.add_parser("stats", help="summarise archive contents")
    p.set_defaults(func=cmd_stats)

    p = sub.add_parser("adduser", help="create an account (the first one must be an owner)")
    p.add_argument("username", nargs="?")
    p.add_argument("--owner", action="store_true", help="make this account an owner")
    p.add_argument("--nick", help="IRC nick to send under (defaults to the username)")
    p.add_argument("--force", action="store_true")
    p.set_defaults(func=cmd_adduser)

    p = sub.add_parser("token", help="mint an API token for a remote agent")
    p.add_argument("username")
    p.add_argument("--name", default="agent", help="what this token is for")
    p.set_defaults(func=cmd_token)

    p = sub.add_parser("passwd", help="(moved) points at the per-user flow")
    p.set_defaults(func=cmd_passwd)

    args = ap.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
