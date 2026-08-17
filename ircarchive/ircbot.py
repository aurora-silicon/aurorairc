"""Minimal read-only IRC client that appends live messages to the archive.

Deliberately passive: it connects, joins the configured channels, and records
what it sees. It never sends a message, notice, or CTCP reply to a channel or
a user - the only things it ever transmits are NICK/USER registration, JOIN,
and PONG keepalives. Reconnects with exponential backoff so it can be left
running.

Presence is plain: the nick and realname are whatever you pass in, with no
tooling banner attached, so it looks like any other client idling in the
channel. Note that these channels are already publicly logged upstream, and
that networks and individual channels may have their own expectations about
unattended clients - worth a look before leaving one connected long-term.

Only conversation is stored (messages, /me actions, topic changes) - join/quit
traffic is ignored, matching what the exported chat logs contain.
"""

import socket
import ssl
import time
import signal
import threading

from . import db

CTCP = "\x01"


def strip_formatting(text):
    """Remove mIRC colour/format codes so stored text matches the web export."""
    out, i, n = [], 0, len(text)
    while i < n:
        c = text[i]
        if c == "\x03":  # colour: \x03[fg[,bg]]
            i += 1
            digits = 0
            while i < n and text[i].isdigit() and digits < 2:
                i += 1
                digits += 1
            if i < n and text[i] == "," and i + 1 < n and text[i + 1].isdigit():
                i += 1
                digits = 0
                while i < n and text[i].isdigit() and digits < 2:
                    i += 1
                    digits += 1
            continue
        if c in "\x02\x0f\x11\x16\x1d\x1e\x1f":  # bold/reset/mono/reverse/italic/strike/underline
            i += 1
            continue
        out.append(c)
        i += 1
    return "".join(out)


def parse_line(line):
    """Split an IRC protocol line into (prefix, command, params)."""
    prefix = ""
    if line.startswith(":"):
        prefix, _, line = line[1:].partition(" ")
    trailing = None
    if " :" in line:
        line, _, trailing = line.partition(" :")
    elif line.startswith(":"):
        trailing, line = line[1:], ""
    parts = line.split()
    command = parts[0].upper() if parts else ""
    params = parts[1:]
    if trailing is not None:
        params.append(trailing)
    return prefix, command, params


class Logger:
    def __init__(self, con, host=None, port=6697, nick=None,
                 channels=(), tls=True, verbose=True,
                 realname=None, username=None, network_id=None):
        self.con = con
        self.ids = db.Ids(con)
        self.network_id = network_id
        self.host, self.port, self.tls = host, port, tls
        if not nick:
            raise ValueError("a nick is required - pick one you are happy to be seen as")
        self.base_nick = nick
        self.nick = nick
        # Default the visible identity to the nick itself rather than anything
        # describing this tool, so presence in the channel is unremarkable.
        self.username = username or nick
        self.realname = realname or nick
        self.channels = [c if c.startswith("#") else "#" + c for c in channels]
        self.verbose = verbose
        self.sock = None
        self._stop = threading.Event()
        self._buf = b""
        self._last_beat = 0
        self._last_pump = 0
        self.registered = False

    # -- plumbing ---------------------------------------------------------

    def send(self, line):
        if self.verbose:
            print(f">> {line}")
        self.sock.sendall((line + "\r\n").encode("utf-8", "replace"))

    def connect(self):
        raw = socket.create_connection((self.host, self.port), timeout=60)
        if self.tls:
            ctx = ssl.create_default_context()
            raw = ctx.wrap_socket(raw, server_hostname=self.host)
        self.sock = raw
        # Short timeout so the read loop wakes promptly to drain the outbox
        # instead of blocking on recv - this is the floor on send latency.
        self.sock.settimeout(0.3)
        self._buf = b""
        self.registered = False
        self.send(f"NICK {self.nick}")
        self.send(f"USER {self.username} 0 * :{self.realname}")

    def lines(self):
        """Yield complete protocol lines from the socket."""
        while not self._stop.is_set():
            try:
                chunk = self.sock.recv(8192)
            except socket.timeout:
                self.pump()
                continue
            if not chunk:
                return
            self._buf += chunk
            while b"\r\n" in self._buf:
                line, _, self._buf = self._buf.partition(b"\r\n")
                yield line.decode("utf-8", "replace")

    # -- archiving --------------------------------------------------------

    def store(self, channel, nick, kind, text):
        text = strip_formatting(text).strip()
        if not text:
            return
        n = db.insert_messages(
            self.con, self.ids,
            [(channel, nick, int(time.time()), kind, text)],
            "live",
        )
        if self.verbose and n:
            print(f"   [{channel}] <{nick}> {text[:100]}")

    # -- outbound (web UI only) -------------------------------------------

    def pump(self):
        """Heartbeat only. This connection never sends to a channel.

        Outbound traffic belongs to ircarchive.connections, which opens a
        separate send-only client under the posting user's own nick. Keeping
        the archivist strictly read-only is what guarantees the log keeps
        running no matter who is signed in.
        """
        if time.time() - self._last_pump < 0.25:
            return
        self._last_pump = time.time()
        now = int(time.time())
        if now - self._last_beat >= 10:
            self._last_beat = now
            # Per-network keys: with several archivists running, a single
            # global set of keys means they overwrite each other's channel
            # list and sends get rejected as "not joined".
            suffix = f":{self.network_id}" if self.network_id else ""
            db.setting(self.con, "live_heartbeat" + suffix, now)
            db.setting(self.con, "live_nick" + suffix, self.nick)
            db.setting(self.con, "live_channels" + suffix, ",".join(self.channels))
            if self.network_id:
                # keep the unsuffixed keys as a summary for the status pill
                db.setting(self.con, "live_heartbeat", now)
                db.setting(self.con, "live_nick", self.nick)

    # -- inbound ----------------------------------------------------------

    def note(self, channel, nick, kind, detail):
        """Record presence traffic. Separate table, never mixed with chat."""
        if not channel.startswith("#") or not nick:
            return
        db.insert_events(self.con, self.ids,
                         [(channel, nick, int(time.time()), kind,
                           (detail or "").strip())],
                         "live")

    def handle(self, prefix, command, params):
        nick = prefix.split("!", 1)[0]

        if command == "PING":
            self.send("PONG :" + (params[-1] if params else ""))
        elif command == "001":  # welcome - safe to join now
            self.registered = True
            for ch in self.channels:
                self.send(f"JOIN {ch}")
        elif command in ("433", "436"):  # nick in use / collision
            self.nick += "_"
            print(f"   nick taken, retrying as {self.nick}")
            self.send(f"NICK {self.nick}")
        elif command == "PRIVMSG" and len(params) >= 2:
            target, text = params[0], params[-1]
            if not target.startswith("#"):
                return  # ignore private messages entirely
            if text.startswith(CTCP) and text.strip(CTCP).upper().startswith("ACTION"):
                self.store(target, nick, db.ACTION, text.strip(CTCP)[7:])
            elif not text.startswith(CTCP):
                self.store(target, nick, db.MSG, text)
        elif command == "TOPIC" and len(params) >= 2:
            self.store(params[0], nick, db.TOPIC, params[-1])

        # Presence traffic - recorded to the events table, never to messages
        elif command == "JOIN" and params:
            self.note(params[0], nick, db.EV_JOIN, "")
        elif command == "PART" and params:
            self.note(params[0], nick, db.EV_PART,
                      params[-1] if len(params) > 1 else "")
        elif command == "KICK" and len(params) >= 2:
            self.note(params[0], params[1], db.EV_KICK,
                      f"by {nick}" + (f" [{params[-1]}]" if len(params) > 2 else ""))
        elif command == "MODE" and params and params[0].startswith("#"):
            self.note(params[0], nick, db.EV_MODE, " ".join(params[1:]))
        elif command == "QUIT":
            # QUIT carries no channel, so it lands against every channel we hold
            for ch in self.channels:
                self.note(ch, nick, db.EV_QUIT, params[-1] if params else "")
        elif command == "NICK" and params:
            for ch in self.channels:
                self.note(ch, nick, db.EV_NICK, params[-1])

    # -- main loop --------------------------------------------------------

    def stop(self, *_):
        self._stop.set()
        try:
            if self.sock:
                self.sock.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass

    def run(self):
        # Only the main thread may install these. Under the connection manager
        # each archivist runs in its own thread, and the manager owns shutdown.
        if threading.current_thread() is threading.main_thread():
            signal.signal(signal.SIGINT, self.stop)
            signal.signal(signal.SIGTERM, self.stop)

        backoff = 5
        while not self._stop.is_set():
            try:
                print(f"Connecting to {self.host}:{self.port} as {self.nick} ...")
                self.connect()
                backoff = 5
                for line in self.lines():
                    prefix, command, params = parse_line(line)
                    self.handle(prefix, command, params)
                    self.pump()   # busy channels must not starve the send queue
            except Exception as exc:
                if self._stop.is_set():
                    break
                print(f"   connection error: {exc}")
            finally:
                try:
                    if self.sock:
                        self.sock.close()
                except OSError:
                    pass

            if self._stop.is_set():
                break
            print(f"   reconnecting in {backoff}s")
            if self._stop.wait(backoff):
                break
            backoff = min(backoff * 2, 300)

        print("Live logger stopped.")
