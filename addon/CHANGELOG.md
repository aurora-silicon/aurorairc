# Changelog

## 1.0.4

- A throttled address can present a valid agent token again. The backoff was
  checked before the token, so the code that clears it on a good token could
  never run - locking out legitimate agents for up to fifteen minutes, which
  is the exact case the backoff was written to tolerate.

## 1.0.3

- Normalise message text on the way in. Trailing whitespace survives in a web
  export but not in live capture, and the text is part of the dedupe key, so a
  line seen both ways was stored twice.

## 1.0.2

- Fix the two-factor code field being invisible. A rule meant to hide empty
  placeholder containers also matched every `<input>`, because a void element
  has no children and so is always `:empty`.

## 1.0.1

- Adopt an archive left at `/share/aurorairc-import.db` on start, after
  checking it really is one. Home Assistant OS has no shell, so this is how an
  existing archive gets in, and how one is restored.
- Any archive already in place is moved aside rather than overwritten.

## 1.0.0

First add-on release.

- Runs the web client and the archivist as two supervised services, each
  restarted independently.
- Archive stored at `/data/archive.db`, so it survives restarts and updates and
  is picked up by Home Assistant backups.
- `behind_proxy` / `proxy_hops` options for running behind a tunnel.
- Waits for a network to be configured rather than exiting, so a fresh install
  sits idle instead of respawning.
