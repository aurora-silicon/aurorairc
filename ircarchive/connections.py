"""Connection manager: one archivist per network, send-only clients per user.

The shape, which is the whole point of the design:

  * Every enabled network gets exactly one **archivist** connection. It joins
    the archived channels, records messages and presence, and never sends a
    word. It stays up regardless of who is signed in, so the log never has a
    hole in it.

  * When a signed-in user posts or runs a private query, a separate connection
    is opened under *their* nick. It registers, joins when posting, and ignores
    inbound traffic except while collecting a bounded WHOIS/ISON-style reply.
    Channel speech comes back through the archivist like any other message, so
    it is recorded exactly once with correct attribution and no local echo.

Send-only clients idle out after a few minutes, so a user who posts once does
not hold a socket open all day.
"""

import json
import socket
import ssl
import threading
import time

from . import db
from .ircbot import Logger, parse_line

IDLE_CLOSE = 300          # seconds a send-only connection lingers unused
CONNECT_TIMEOUT = 30
PREWARM_MAX_AGE = 90      # ignore pre-open requests older than this


class Sender:
    """A minimal posting and private-query client for one nick on one network."""

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
        if self.sock is None:
            return              # closed underneath us, mid-shutdown
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
                if self.sock is not None:
                    self.sock.settimeout(CONNECT_TIMEOUT)
            except OSError:
                pass

    def ensure(self, channel=None):
        """Open, and optionally join, before there is anything to say.

        Registering and joining costs about twelve seconds. Paying it while the
        user is still typing is what makes the send itself look instant. Shares
        `lock` with say() so the two can never open two sockets for one nick.
        """
        with self.lock:
            if not self.ready:
                self.connect()
            if channel and channel not in self.joined:
                self._send(f"JOIN {channel}")
                self.joined.add(channel)
            self.drain()

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

    def query(self, line):
        """Send one read-only IRC command and collect its bounded reply.

        Sender connections normally discard inbound traffic. A command is the
        exception: while holding the same lock as say(), collect numerics and
        service notices until the command's standard end marker (or a short
        quiet period for NickServ) arrives. Returning parsed lines lets the web
        UI make common replies friendly without hiding the actual protocol.
        """
        with self.lock:
            if not self.ready:
                self.connect()
            self.drain()
            line = str(line or "").replace("\r", " ").replace("\n", " ").strip()
            if not line:
                return []
            self._send(line)
            self.last_used = time.time()

            name = line.split(None, 1)[0].upper()
            ends = {
                "WHOIS": {"318", "401", "402", "431"},
                "ISON": {"303", "461"},
                "NAMES": {"366", "403", "442"},
                "WHO": {"315", "403", "461"},
                "USERHOST": {"302", "461"},
                "WHOWAS": {"369", "406", "431"},
                "MOTD": {"376", "422"},
                "VERSION": {"351", "402"},
                "TIME": {"391", "402"},
            }.get(name, set())
            replies, buf = [], ""
            deadline = time.monotonic() + 10
            quiet_at = None
            try:
                self.sock.settimeout(0.35)
                while time.monotonic() < deadline:
                    try:
                        chunk = self.sock.recv(4096).decode("utf-8", "replace")
                    except socket.timeout:
                        if replies and quiet_at and time.monotonic() >= quiet_at:
                            break
                        continue
                    if not chunk:
                        raise RuntimeError("IRC closed the connection")
                    buf += chunk
                    while "\r\n" in buf:
                        raw, _, buf = buf.partition("\r\n")
                        prefix, cmd, params = parse_line(raw)
                        if cmd == "PING":
                            self._send("PONG :" + (params[-1] if params else ""))
                            continue
                        if cmd == "PONG":
                            continue
                        visible = list(params)
                        if visible and visible[0].lower() == self.nick.lower():
                            visible.pop(0)
                        replies.append({
                            "from": (prefix or "").split("!", 1)[0],
                            "code": cmd,
                            "params": visible,
                            "raw": raw,
                        })
                        quiet_at = time.monotonic() + 0.9
                        if cmd in ends:
                            return replies
                return replies
            finally:
                try:
                    if self.sock is not None:
                        self.sock.settimeout(CONNECT_TIMEOUT)
                except OSError:
                    pass

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


def probe(host, port, tls=True, nick="aurora", timeout=15):
    """Open a throwaway connection and confirm the server actually answers.

    Used by setup so nobody finishes the wizard with a typo in the hostname and
    a silent archivist. It registers far enough to get the welcome numeric,
    says QUIT, and closes - it never joins anything and never speaks.

    Returns ``{"ok": True, "server": ..., "ms": ..., "nick": ...}`` or
    ``{"ok": False, "error": "..."}``. Never raises.
    """
    started = time.time()
    sock = None
    try:
        raw = socket.create_connection((host, int(port)), timeout=timeout)
        if tls:
            raw = ssl.create_default_context().wrap_socket(
                raw, server_hostname=host)
        sock = raw
        sock.settimeout(timeout)
        use = str(nick or "aurora").strip() or "aurora"
        sock.sendall(f"NICK {use}\r\n".encode())
        sock.sendall(f"USER {use} 0 * :{use}\r\n".encode())
        buf, deadline, server = "", time.time() + timeout, host
        while time.time() < deadline:
            chunk = sock.recv(4096).decode("utf-8", "replace")
            if not chunk:
                break
            buf += chunk
            while "\r\n" in buf:
                line, _, buf = buf.partition("\r\n")
                prefix, cmd, params = parse_line(line)
                if cmd == "PING":
                    sock.sendall(("PONG :" + (params[-1] if params else "")
                                  + "\r\n").encode())
                elif cmd == "001":
                    if prefix:
                        server = prefix
                    return {"ok": True, "server": server, "nick": use,
                            "ms": int((time.time() - started) * 1000)}
                elif cmd in ("433", "436"):
                    use += "_"
                    sock.sendall(f"NICK {use}\r\n".encode())
                elif cmd in ("464", "465"):
                    return {"ok": False,
                            "error": params[-1] if params else
                                     "the server refused the connection"}
                elif cmd == "ERROR":
                    return {"ok": False,
                            "error": params[-1] if params else "connection closed"}
        return {"ok": False, "error": "the server never finished registering us"}
    except ssl.SSLError as exc:
        return {"ok": False, "error": f"TLS failed: {exc}. Try turning TLS off, "
                                      f"or port 6667."}
    except socket.timeout:
        return {"ok": False, "error": f"timed out after {timeout}s"}
    except OSError as exc:
        return {"ok": False, "error": str(exc)}
    except Exception as exc:                       # never let a probe 500
        return {"ok": False, "error": str(exc)}
    finally:
        try:
            if sock:
                sock.sendall(b"QUIT :bye\r\n")
                sock.close()
        except OSError:
            pass


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

    def pump_commands(self, con):
        """Run queued read-only commands without giving the web process a socket."""
        now = int(time.time())
        if now - getattr(self, "_last_command_cleanup", 0) > 3600:
            self._last_command_cleanup = now
            con.execute("DELETE FROM irc_commands WHERE finished_at IS NOT NULL "
                        "AND finished_at < ?", (now - 7 * 86400,))
        nets = {n["id"]: n for n in db.networks(con, enabled_only=True)}
        rows = con.execute(
            "SELECT id, user_id, network_id, nick, command, wire FROM irc_commands "
            "WHERE finished_at IS NULL ORDER BY id LIMIT 5").fetchall()
        for row in rows:
            net = nets.get(row["network_id"])
            if not net:
                con.execute("UPDATE irc_commands SET finished_at=?, error=? WHERE id=?",
                            (now, "that IRC network is unavailable", row["id"]))
                continue
            try:
                con.execute("UPDATE irc_commands SET sent_at=? WHERE id=?",
                            (now, row["id"]))
                replies = self.sender_for(net, row["nick"]).query(row["wire"])
                con.execute(
                    "UPDATE irc_commands SET finished_at=?, response=? WHERE id=?",
                    (int(time.time()), json.dumps(replies, ensure_ascii=False), row["id"]))
                self.log(f"   command as {row['nick']}: {row['command']}")
            except Exception as exc:
                con.execute("UPDATE irc_commands SET finished_at=?, error=? WHERE id=?",
                            (int(time.time()), str(exc), row["id"]))
                self.senders.pop((net["id"], row["nick"]), None)
                self.log(f"   command failed as {row['nick']}: {exc}")

    def prewarm(self, con):
        """Honour requests from the web server to open a sender in advance.

        The two processes only share the database, so the request arrives as a
        settings row. Connecting happens on its own thread: it can take the
        full connect timeout, and the outbox must not stall behind it.
        """
        rows = con.execute(
            "SELECT key, value FROM settings WHERE key LIKE 'prewarm:%'").fetchall()
        if not rows:
            return
        nets = {n["id"]: n for n in db.networks(con, enabled_only=True)}
        now = int(time.time())
        for row in rows:
            con.execute("DELETE FROM settings WHERE key = ?", (row["key"],))
            try:
                _, nid, nick = row["key"].split(":", 2)
                asked, _, channel = str(row["value"] or "").partition("|")
                nid, asked = int(nid), int(asked)
            except ValueError:
                continue
            # A stale request means the process was down; the user is long gone.
            if now - asked > PREWARM_MAX_AGE:
                continue
            net = nets.get(nid)
            if not net or not nick or (nid, nick) in self.senders:
                continue
            sender = self.sender_for(net, nick)
            threading.Thread(target=self._warm, args=(sender, nick, channel),
                             name=f"prewarm-{nick}", daemon=True).start()

    def _warm(self, sender, nick, channel):
        try:
            sender.ensure(channel or None)
            self.log(f"   ready to send as {nick}"
                     + (f" in {channel}" if channel else ""))
        except Exception as exc:
            # Not fatal: the send path will simply open it the slow way.
            self.log(f"   could not pre-open {nick}: {exc}")

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
                # A shutdown can close this from another thread mid-sweep, so
                # a dead socket here is ordinary rather than an error to shout
                # about on the way out.
                try:
                    s.drain()      # keep answering PING while it lingers
                except (OSError, AttributeError):
                    pass

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
            # Wait rather than exit. Networks are added from Settings while
            # this is running, and sync_config picks them up within ten
            # seconds. Exiting here means a fresh install respawns this
            # process forever under any supervisor that restarts it.
            print("No networks configured yet - waiting for one to be added.")
        for net in nets:
            self.start_archivist(net)

        try:
            while not self._stop.is_set():
                try:
                    self.pump(con)
                    self.pump_commands(con)
                    self.prewarm(con)
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
