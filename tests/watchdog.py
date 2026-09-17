#!/usr/bin/env python3
"""The archivist notices a dead link, gets its nick back, and rejoins.

Drives ircarchive.ircbot.Logger against tests/fakeircd.py with the timers
shrunk to seconds. Three things a long-running archivist must do without
anyone restarting it:

  * a link that goes silent without closing is abandoned and redialled
    (the failure mode: OFTC had ping-timed the client out, the socket never
    said so, and the heartbeat kept reporting "connected" for four days);
  * the wanted nick is asked for again once the ghost holding it is gone;
  * a channel that refuses us (474) or kicks us is retried, not forgotten.

    python3 tests/watchdog.py
"""

import sys
import tempfile
import threading
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))

from fakeircd import FakeIRCd                                  # noqa: E402
from ircarchive import db, ircbot                              # noqa: E402

PASS = "\033[32m✓\033[0m"
FAIL = "\033[31m✗\033[0m"
failures, checks = [], 0


def check(label, ok, detail=""):
    global checks
    checks += 1
    print(f"  {PASS if ok else FAIL} {label}" + ("" if ok else f"\n      {detail}"))
    if not ok:
        failures.append(label)


def wait_for(cond, timeout=10, step=0.05):
    end = time.time() + timeout
    while time.time() < end:
        v = cond()
        if v:
            return v
        time.sleep(step)
    return cond()


def main():
    # Seconds, not minutes: the logic is identical, only the clock is faster.
    ircbot.PING_AFTER, ircbot.DEAD_AFTER = 1, 3
    ircbot.REGAIN_EVERY = 1
    ircbot.REJOIN_MIN, ircbot.REJOIN_MAX = 1, 4

    ircd = FakeIRCd(port=0).start()
    tmp = tempfile.TemporaryDirectory()
    ircd.banned.add("#closed")

    # SQLite handles belong to the thread that opens them, so the bot is
    # built inside its own thread, exactly as the connection manager does.
    holder = {}
    ready = threading.Event()

    def run_bot():
        con = db.connect(Path(tmp.name) / "archive.db")
        holder["bot"] = ircbot.Logger(
            con, host="127.0.0.1", port=ircd.port, nick="aurora",
            channels=["#open", "#closed"], tls=False, verbose=False)
        ready.set()
        holder["bot"].run()
        con.close()

    threading.Thread(target=run_bot, daemon=True).start()
    ready.wait(5)
    bot = holder["bot"]

    print("\nA dead link is noticed and redialled")
    first = wait_for(lambda: ircd.client("aurora"))
    check("the archivist registers", bool(first))
    check("and joins the channel that will have it",
          bool(wait_for(lambda: "#open" in first.channels)))
    ircd.mute("aurora")
    t0 = time.time()
    second = wait_for(lambda: next((c for c in ircd.clients
                                    if c is not first and c.registered), None),
                      timeout=15)
    took = time.time() - t0
    check("a new connection appears within the dead-link window",
          bool(second) and took < 10, f"took {took:.1f}s")
    check("the socket was dropped for silence, not for anything the server said",
          bool(second) and first.muted)

    print("\nThe wanted nick comes back once the ghost is gone")
    check("meanwhile it registered on the fallback nick",
          bool(second) and second.nick == "aurora_", second and second.nick)
    first.close()                       # the server finally times the ghost out
    check("and reclaims 'aurora' by itself",
          bool(wait_for(lambda: second.nick == "aurora", timeout=8)), second.nick)
    check("the Logger agrees about its own name",
          bool(wait_for(lambda: bot.nick == "aurora", timeout=3)), bot.nick)

    print("\nA refused channel is retried until it opens")
    check("#closed is on the retry list",
          bool(wait_for(lambda: "#closed" in bot._rejoin, timeout=3)))
    check("#open is not", "#open" not in bot._rejoin)
    ircd.banned.discard("#closed")
    check("once the ban lifts the archivist is in #closed",
          bool(wait_for(lambda: "#closed" in second.channels, timeout=10)))
    check("and #closed leaves the retry list",
          bool(wait_for(lambda: "#closed" not in bot._rejoin, timeout=3)))

    print("\nA kick is answered with a rejoin")
    ircd.kick("aurora", "#open")
    check("the kick is noted for a retry",
          bool(wait_for(lambda: "#open" in bot._rejoin, timeout=3)))
    check("and it is back in #open shortly after",
          bool(wait_for(lambda: "#open" in second.channels, timeout=10)))

    bot.stop()
    ircd.stop()
    time.sleep(0.5)
    tmp.cleanup()
    print(f"\n{checks - len(failures)}/{checks} checks passed")
    if failures:
        print("failed: " + "; ".join(failures))
        sys.exit(1)


if __name__ == "__main__":
    main()
