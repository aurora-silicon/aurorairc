"""Connection manager: one archivist per network, send-only clients per user.

The shape, which is the whole point of the design:

  * Every enabled network gets exactly one **archivist** connection. It joins
    the archived channels, records messages and presence, and never sends a
    word. It stays up regardless of who is signed in, so the log never has a
    hole in it.

  * When a signed-in user posts, a **send-only** connection is opened under
    *their* nick. It registers, joins, sends, and ignores everything inbound.
    Their line comes back through the archivist like any other message, so it
    is recorded exactly once with correct attribution and there is no local
    echo to reconcile.

Send-only clients idle out after a few minutes, so a user who posts once does
not hold a socket open all day.
"""

import socket
import ssl
import threading
import time

from . import db
from .ircbot import Logger, parse_line

IDLE_CLOSE = 300          # seconds a send-only connection lingers unused
CONNECT_TIMEOUT = 30


class Sender:
    """A minimal, write-only IRC client for one nick on one network."""

    def __init__(self, host, port, nick, tls=True, verbose=False):
        self.host, self.port, self.nick, self.tls = host, port, nick, tls
        self.verbose = verbose
        self.sock = None
        self.ready = False
        self.joined = set()
        self.last_used = time.time()
        self.lock = threading.Lock()

    def _send(self, line):
        self.sock.sendall((line + "\r\n").encode("utf-8", "replace"))

    def connect(self):
        raw = socket.create_connection((self.host, self.port), timeout=CONNECT_TIMEOUT)
        if self.tls:
            raw = ssl.create_default_context().wrap_socket(raw, server_hostname=self.host)
        raw.settimeout(CONNECT_TIMEOUT)
        self.sock = raw
        self._send(f"NICK {self.nick}")
        self._send(f"USER {self.nick} 0 * :{self.nick}")

        # Read until the server welcomes us, answering PING on the way
        buf = ""
        deadline = time.time() + CONNECT_TIMEOUT
        while time.time() < deadline:
            try:
                chunk = self.sock.recv(4096).decode("utf-8", "replace")
            except socket.timeout:
                break
            if not chunk:
                break
            buf += chunk
            while "\r\n" in buf:
                line, _, buf = buf.partition("\r\n")
                prefix, cmd, params = parse_line(line)
                if cmd == "PING":
                    self._send("PONG :" + (params[-1] if params else ""))
                elif cmd == "001":
                    self.ready = True
                    return True
                elif cmd in ("433", "436"):
                    # Nick taken: fall back rather than fight over it
                    self.nick += "_"
                    self._send(f"NICK {self.nick}")
                elif cmd in ("464", "465"):
                    raise RuntimeError("rejected by the server")
        raise RuntimeError("timed out waiting for the server to register us")

    def drain(self):
        """Consume and discard inbound. This client never acts on it."""
        try:
            self.sock.settimeout(0.05)
            while True:
                chunk = self.sock.recv(4096)
                if not chunk:
                    return
                for line in chunk.decode("utf-8", "replace").split("\r\n"):
                    prefix, cmd, params = parse_line(line)
                    if cmd == "PING":
                        self._send("PONG :" + (params[-1] if params else ""))
        except (socket.timeout, OSError):
            pass
        finally:
            try:
                self.sock.settimeout(CONNECT_TIMEOUT)
            except OSError:
                pass

    def say(self, channel, text):
        with self.lock:
            if not self.ready:
                self.connect()
            self.drain()
            if channel not in self.joined:
                self._send(f"JOIN {channel}")
                self.joined.add(channel)
                time.sleep(0.4)          # let the join settle before speaking
            text = text.replace("\r", " ").replace("\n", " ").strip()
            if not text:
                return
            self._send(f"PRIVMSG {channel} :{text}")
            self.last_used = time.time()

    def close(self):
        try:
            if self.sock:
                self._send("QUIT :bye")
                self.sock.close()
        except OSError:
            pass
        self.sock = None
        self.ready = False
        self.joined.clear()


class Manager:
    """Runs the archivists and services the outbox."""

    def __init__(self, dbpath, verbose=True):
        self.dbpath = dbpath
        self.verbose = verbose
        self.senders = {}          # (network_id, nick) -> Sender
        self.archivists = {}       # network_id -> Logger
        self._stop = threading.Event()

    def log(self, *a):
        if self.verbose:
            print(*a, flush=True)

    # -- archivists -------------------------------------------------------

    def _run_archivist(self, net, channels):
        # The connection has to be opened in the thread that will use it:
        # SQLite objects are bound to their creating thread.
        con = db.connect(self.dbpath)
        bot = Logger(con, host=net["host"], port=net["port"],
                     nick=net["archivist_nick"], channels=channels,
                     tls=bool(net["tls"]), verbose=self.verbose,
                     network_id=net["id"])
        self.archivists[net["id"]] = bot
        try:
            bot.run()
        finally:
            con.close()

    def start_archivist(self, net):
        con = db.connect(self.dbpath)
        channels = db.network_channels(con, net["id"])
        con.close()
        if not channels:
            self.log(f"[{net['name']}] no archived channels yet, not connecting")
            return
        # Reserve the slot before the thread starts. The thread fills in the
        # real object, and until it does a config sync would otherwise see an
        # empty slot and start a second connection to the same network.
        self.archivists.setdefault(net["id"], None)
        t = threading.Thread(target=self._run_archivist, args=(net, channels),
                             name=f"archivist-{net['name']}", daemon=True)
        t.start()
        self.log(f"[{net['name']}] archivist {net['archivist_nick']} -> "
                 f"{net['host']}:{net['port']} {' '.join('#'+c for c in channels)}")

    # -- outbox -----------------------------------------------------------

    def sender_for(self, net, nick):
        key = (net["id"], nick)
        s = self.senders.get(key)
        if s is None:
            s = Sender(net["host"], net["port"], nick, tls=bool(net["tls"]),
                       verbose=self.verbose)
            self.senders[key] = s
        return s

    def pump(self, con):
        nets = {n["id"]: n for n in db.networks(con, enabled_only=True)}
        rows = con.execute(
            "SELECT id, channel, text, nick, network_id FROM outbox "
            "WHERE sent_at IS NULL ORDER BY id LIMIT 20").fetchall()
        for row in rows:
            net = nets.get(row["network_id"]) or next(iter(nets.values()), None)
            if not net:
                continue
            # No nick recorded means it predates per-user sending; fall back to
            # the archivist's identity rather than dropping the message.
            nick = row["nick"] or net["archivist_nick"]
            try:
                self.sender_for(net, nick).say(row["channel"], row["text"])
                con.execute("UPDATE outbox SET sent_at = ? WHERE id = ?",
                            (int(time.time()), row["id"]))
                self.log(f"   sent as {nick} -> {row['channel']}")
            except Exception as exc:
                con.execute("UPDATE outbox SET sent_at = ?, error = ? WHERE id = ?",
                            (int(time.time()), str(exc), row["id"]))
                self.senders.pop((net["id"], nick), None)
                self.log(f"   send failed as {nick}: {exc}")

    def sync_config(self, con):
        """Pick up channel and network edits made in Settings.

        Owners change these from the web UI, so the running process has to
        notice by itself - telling someone to restart a daemon is not a
        feature.
        """
        for net in db.networks(con, enabled_only=True):
            wanted = db.network_channels(con, net["id"])
            if net["id"] not in self.archivists:
                if wanted:                     # a network added since we started
                    self.log(f"[{net['name']}] newly configured, connecting")
                    self.start_archivist(net)
                continue
            bot = self.archivists.get(net["id"])
            if bot is not None:                # still starting up, try next pass
                bot.want_channels(wanted)

    def reap(self):
        now = time.time()
        for key, s in list(self.senders.items()):
            if s.ready and now - s.last_used > IDLE_CLOSE:
                s.close()
                self.senders.pop(key, None)
                self.log(f"   closed idle sender {key[1]}")
            elif s.ready:
                s.drain()          # keep answering PING while it lingers

    # -- main loop --------------------------------------------------------

    def stop(self, *_):
        self._stop.set()
        for bot in self.archivists.values():
            bot.stop()
        for s in self.senders.values():
            s.close()

    def run(self):
        con = db.connect(self.dbpath)
        nets = db.networks(con, enabled_only=True)
        if not nets:
            print("No networks configured yet.")
            return
        for net in nets:
            self.start_archivist(net)

        try:
            while not self._stop.is_set():
                try:
                    self.pump(con)
                    self.reap()
                    now = time.time()
                    if now - getattr(self, "_last_sync", 0) > 10:
                        self._last_sync = now
                        self.sync_config(con)
                except Exception as exc:
                    self.log(f"   pump error: {exc}")
                self._stop.wait(0.4)
        except KeyboardInterrupt:
            pass
        finally:
            self.stop()
            con.close()
            print("Stopped.")
