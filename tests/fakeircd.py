#!/usr/bin/env python3
"""A tiny IRC server, just real enough to exercise the archive end to end.

Not an ircd. It speaks the handful of commands AuroraIRC actually uses -
NICK, USER, JOIN, PART, PRIVMSG, QUIT, PING - and relays between clients so a
message sent by one connection comes back through another. That is the exact
shape the app depends on: the archivist only ever listens, sends go out over a
separate connection, and the line returns through the archivist to be recorded.

Run it standalone to poke at by hand:

    python3 tests/fakeircd.py --port 6667
"""

import argparse
import socket
import threading
import time


class Client:
    def __init__(self, sock, addr, server):
        self.sock, self.addr, self.server = sock, addr, server
        self.nick = None
        self.user = None
        self.channels = set()
        self.registered = False
        self.buf = b""
        self.alive = True

    @property
    def prefix(self):
        return f"{self.nick}!{self.user or self.nick}@test"

    def send(self, line):
        if not self.alive:
            return
        try:
            self.sock.sendall((line + "\r\n").encode("utf-8", "replace"))
        except OSError:
            self.alive = False

    def close(self):
        self.alive = False
        try:
            self.sock.close()
        except OSError:
            pass


class FakeIRCd:
    def __init__(self, host="127.0.0.1", port=0, name="fake.test",
                 verbose=False):
        self.host, self.port, self.name = host, port, name
        self.verbose = verbose
        self.clients = []
        self.lock = threading.RLock()
        self.sock = socket.socket()
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind((host, port))
        self.sock.listen(16)
        self.port = self.sock.getsockname()[1]
        self._stop = threading.Event()
        self.seen = []                 # every PRIVMSG the server relayed

    def log(self, *a):
        if self.verbose:
            print("[ircd]", *a, flush=True)

    # -- lifecycle --------------------------------------------------------

    def start(self):
        threading.Thread(target=self._accept, daemon=True).start()
        return self

    def stop(self):
        self._stop.set()
        try:
            self.sock.close()
        except OSError:
            pass
        with self.lock:
            for c in list(self.clients):
                c.close()

    def _accept(self):
        while not self._stop.is_set():
            try:
                s, addr = self.sock.accept()
            except OSError:
                return
            c = Client(s, addr, self)
            with self.lock:
                self.clients.append(c)
            threading.Thread(target=self._serve, args=(c,), daemon=True).start()

    # -- per-client -------------------------------------------------------

    def _serve(self, c):
        c.sock.settimeout(0.5)
        try:
            while c.alive and not self._stop.is_set():
                try:
                    chunk = c.sock.recv(4096)
                except socket.timeout:
                    continue
                except OSError:
                    break
                if not chunk:
                    break
                c.buf += chunk
                while b"\r\n" in c.buf:
                    line, _, c.buf = c.buf.partition(b"\r\n")
                    self._handle(c, line.decode("utf-8", "replace"))
        finally:
            self._part_all(c, "connection closed")
            c.close()
            with self.lock:
                if c in self.clients:
                    self.clients.remove(c)

    def _handle(self, c, line):
        if not line:
            return
        self.log("<<", c.nick or "?", line)
        trailing = None
        if " :" in line:
            line, _, trailing = line.partition(" :")
        parts = line.split()
        if not parts:
            return
        cmd, args = parts[0].upper(), parts[1:]
        if trailing is not None:
            args.append(trailing)

        if cmd == "NICK" and args:
            want = args[0]
            with self.lock:
                taken = any(o is not c and o.nick == want for o in self.clients)
            if taken:
                c.send(f":{self.name} 433 {c.nick or '*'} {want} "
                       f":Nickname is already in use")
                return
            old = c.nick
            c.nick = want
            if old and c.registered:
                for peer in self._peers(c):
                    peer.send(f":{old}!{c.user or old}@test NICK :{want}")
            self._maybe_register(c)
        elif cmd == "USER" and args:
            c.user = args[0]
            self._maybe_register(c)
        elif cmd == "PING":
            c.send(f":{self.name} PONG {self.name} :{args[-1] if args else ''}")
        elif cmd == "PONG":
            pass
        elif cmd == "JOIN" and args:
            for ch in args[0].split(","):
                self._join(c, ch)
        elif cmd == "PART" and args:
            for ch in args[0].split(","):
                self._part(c, ch, args[-1] if len(args) > 1 else "")
        elif cmd == "PRIVMSG" and len(args) >= 2:
            self._privmsg(c, args[0], args[-1])
        elif cmd == "TOPIC" and len(args) >= 2:
            with self.lock:
                for peer in self.clients:
                    if args[0] in peer.channels:
                        peer.send(f":{c.prefix} TOPIC {args[0]} :{args[-1]}")
        elif cmd == "QUIT":
            self._part_all(c, args[-1] if args else "Client Quit")
            c.close()

    def _maybe_register(self, c):
        if c.registered or not (c.nick and c.user):
            return
        c.registered = True
        c.send(f":{self.name} 001 {c.nick} :Welcome to the test network, {c.nick}")
        c.send(f":{self.name} 002 {c.nick} :Your host is {self.name}")
        c.send(f":{self.name} 003 {c.nick} :This server was created today")
        c.send(f":{self.name} 004 {c.nick} {self.name} fake-1.0 o o")
        c.send(f":{self.name} 376 {c.nick} :End of /MOTD command.")
        self.log("registered", c.nick)

    # -- channels ---------------------------------------------------------

    def _members(self, channel):
        with self.lock:
            return [c for c in self.clients if channel in c.channels and c.alive]

    def _peers(self, c):
        """Everyone who shares a channel with c (not c itself)."""
        out = set()
        with self.lock:
            for ch in c.channels:
                for o in self.clients:
                    if o is not c and ch in o.channels:
                        out.add(o)
        return out

    def _join(self, c, channel):
        if not channel.startswith("#"):
            return
        if channel in c.channels:
            return
        c.channels.add(channel)
        for m in self._members(channel):
            m.send(f":{c.prefix} JOIN {channel}")
        names = " ".join(m.nick for m in self._members(channel) if m.nick)
        c.send(f":{self.name} 332 {c.nick} {channel} :Test channel {channel}")
        c.send(f":{self.name} 353 {c.nick} = {channel} :{names}")
        c.send(f":{self.name} 366 {c.nick} {channel} :End of /NAMES list.")
        self.log("join", c.nick, channel)

    def _part(self, c, channel, why=""):
        if channel not in c.channels:
            return
        for m in self._members(channel):
            m.send(f":{c.prefix} PART {channel} :{why}")
        c.channels.discard(channel)

    def _part_all(self, c, why):
        if not c.nick:
            return
        for peer in self._peers(c):
            peer.send(f":{c.prefix} QUIT :{why}")
        c.channels.clear()

    def _privmsg(self, c, target, text):
        self.seen.append((c.nick, target, text, time.time()))
        if not target.startswith("#"):
            return
        for m in self._members(target):
            if m is not c:
                m.send(f":{c.prefix} PRIVMSG {target} :{text}")
        self.log("msg", c.nick, target, text[:60])

    # -- helpers for tests -------------------------------------------------

    def inject(self, nick, channel, text, kind="msg"):
        """Speak into a channel as if some other person were there."""
        for m in self._members(channel):
            if kind == "action":
                m.send(f":{nick}!{nick}@test PRIVMSG {channel} "
                       f":\x01ACTION {text}\x01")
            elif kind == "topic":
                m.send(f":{nick}!{nick}@test TOPIC {channel} :{text}")
            else:
                m.send(f":{nick}!{nick}@test PRIVMSG {channel} :{text}")

    def inject_join(self, nick, channel):
        for m in self._members(channel):
            m.send(f":{nick}!{nick}@test JOIN {channel}")

    def inject_quit(self, nick, why="Ping timeout"):
        with self.lock:
            for m in self.clients:
                if m.channels:
                    m.send(f":{nick}!{nick}@test QUIT :{why}")


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=6667)
    ap.add_argument("--quiet", action="store_true")
    a = ap.parse_args()
    srv = FakeIRCd(a.host, a.port, verbose=not a.quiet).start()
    print(f"fake ircd on {a.host}:{srv.port}")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        srv.stop()


if __name__ == "__main__":
    main()
