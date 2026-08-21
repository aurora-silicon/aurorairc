"""Minimal read-only IRC client that appends live messages to the archive.

Deliberately passive: it connects, joins the configured channels, and records
what it sees. It never sends a message, notice, or CTCP reply to a channel or
a user. Beyond NICK/USER registration, JOIN/PART and PONG keepalives, the only
query it emits is ISON when a signed-in reader explicitly refreshes somebody's
status. Reconnects with exponential backoff so it can be left running.

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
        self._wanted = None
        self._names = {}
        self._ison = None
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
        self._names = {}
        self._ison = None
        db.presence_reset_network(self.con, self.network_id)
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

    # -- quiet maintenance -------------------------------------------------

    def pump(self):
        """Heartbeat, channel changes, and one-at-a-time ISON lookups.

        Outbound traffic belongs to ircarchive.connections, which opens a
        separate send-only client under the posting user's own nick. Keeping
        channel speech away from the archivist is what guarantees the log keeps
        running no matter who is signed in. ISON is private server metadata: it
        never produces channel or user-visible text.
        """
        if time.time() - self._last_pump < 0.25:
            return
        self._last_pump = time.time()
        self.apply_channels()
        now = int(time.time())
        self.pump_presence_check(now)
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

    def pump_presence_check(self, now):
        """Issue at most one pending ISON lookup on this network at a time."""
        if self.network_id is None or not self.registered:
            return
        if self._ison:
            nick, started = self._ison
            if now - started <= 10:
                return
            self.con.execute(
                "UPDATE live_presence_checks SET checked_at=?, online=NULL, "
                "error='server did not answer ISON' WHERE network_id=? "
                "AND nick=? COLLATE NOCASE", (now, self.network_id, nick))
            self._ison = None
        row = self.con.execute(
            "SELECT nick FROM live_presence_checks WHERE network_id=? AND "
            "(checked_at IS NULL OR requested_at > checked_at) "
            "ORDER BY requested_at LIMIT 1", (self.network_id,)).fetchone()
        if not row:
            return
        nick = row["nick"]
        self._ison = (nick, now)
        self.send(f"ISON :{nick}")

    # -- inbound ----------------------------------------------------------

    def want_channels(self, wanted):
        """Ask for a different channel set. Safe to call from another thread.

        Only records the wish - the socket is written to solely by this
        connection's own thread, so the manager must not send on it directly.
        """
        self._wanted = sorted({c if c.startswith("#") else "#" + c for c in wanted})

    def apply_channels(self):
        """Act on a pending channel change, from our own thread."""
        want = getattr(self, "_wanted", None)
        if want is None or not self.registered:
            return
        self._wanted = None
        have = set(self.channels)
        if set(want) == have:
            return
        for ch in sorted(set(want) - have):
            self.send(f"JOIN {ch}")
            print(f"   joining {ch}")
        for ch in sorted(have - set(want)):
            self.send(f"PART {ch}")
            db.presence_clear_channel(self.con, self.network_id, ch)
            print(f"   leaving {ch}")
        self.channels = want

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
        elif command == "303":  # RPL_ISON
            if self._ison:
                asked, _ = self._ison
                online = any(n.lower() == asked.lower()
                             for n in (params[-1].split() if params else []))
                self.con.execute(
                    "UPDATE live_presence_checks SET checked_at=?, online=?, error=NULL "
                    "WHERE network_id=? AND nick=? COLLATE NOCASE",
                    (int(time.time()), 1 if online else 0, self.network_id, asked))
                self._ison = None
        elif command == "421" and self._ison and len(params) >= 2 and params[1].upper() == "ISON":
            asked, _ = self._ison
            self.con.execute(
                "UPDATE live_presence_checks SET checked_at=?, online=NULL, error=? "
                "WHERE network_id=? AND nick=? COLLATE NOCASE",
                (int(time.time()), "ISON is not supported by this network",
                 self.network_id, asked))
            self._ison = None
        elif command == "353" and len(params) >= 2:  # RPL_NAMREPLY
            channel = params[-2]
            if channel.startswith("#"):
                names = self._names.setdefault(channel.lower(), [])
                for raw in params[-1].split():
                    clean = raw.lstrip("~&@%+")
                    if clean:
                        names.append(clean)
        elif command == "366" and len(params) >= 2:  # RPL_ENDOFNAMES
            channel = params[-2]
            if channel.startswith("#"):
                names = self._names.pop(channel.lower(), [])
                # Preserve order while collapsing multi-prefix duplicates.
                names = list(dict.fromkeys(names))
                db.presence_replace_channel(
                    self.con, self.network_id, channel, names)
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
            db.presence_join(self.con, self.network_id, params[0], nick)
            self.note(params[0], nick, db.EV_JOIN, "")
        elif command == "PART" and params:
            if nick.lower() == self.nick.lower():
                db.presence_clear_channel(self.con, self.network_id, params[0])
            else:
                db.presence_part(self.con, self.network_id, params[0], nick)
            self.note(params[0], nick, db.EV_PART,
                      params[-1] if len(params) > 1 else "")
        elif command == "KICK" and len(params) >= 2:
            if params[1].lower() == self.nick.lower():
                db.presence_clear_channel(self.con, self.network_id, params[0])
            else:
                db.presence_part(self.con, self.network_id, params[0], params[1])
            self.note(params[0], params[1], db.EV_KICK,
                      f"by {nick}" + (f" [{params[-1]}]" if len(params) > 2 else ""))
        elif command == "MODE" and params and params[0].startswith("#"):
            self.note(params[0], nick, db.EV_MODE, " ".join(params[1:]))
        elif command == "QUIT":
            db.presence_quit(self.con, self.network_id, nick)
            # QUIT carries no channel, so it lands against every channel we hold
            for ch in self.channels:
                self.note(ch, nick, db.EV_QUIT, params[-1] if params else "")
        elif command == "NICK" and params:
            db.presence_rename(self.con, self.network_id, nick, params[-1])
            for ch in self.channels:
                self.note(ch, nick, db.EV_NICK, params[-1])
            if nick.lower() == self.nick.lower():
                self.nick = params[-1]

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
