# Changelog

## 1.1.0

Bug fixes:

- A message you send is attributed to you the moment it lands. The grouping
  decision was made against a variable rather than the feed, so when the real
  message replaced its optimistic echo the row grouped itself under whoever
  spoke before it — your reply read as theirs until the page was reloaded.
- The conversation moves up as the composer grows. The reading pane shrank
  correctly but kept its scroll position, so a long message slid the newest
  lines in behind the box.
- Schema upgrades survive two processes opening the database at once. `serve`
  and `live` share one file and either can be first through the door after an
  upgrade; checking for a column and then adding it is a race the loser used
  to crash on.
- Times are the reader's own, and now say so. The clock was already local but
  its tooltip claimed UTC, and the date presets picked a UTC day — which is
  yesterday for most of an Australian one. Everything derived from a timestamp
  now goes through one place, and Appearance names the zone it is using.

New:

- **Setup is a walked path.** A fresh instance opens a wizard: welcome, server
  name, the owner account, a passkey or two-factor, invitations, then the IRC
  connection — which is tested against the real server before it can be saved,
  or deferred with "Set up later". It ends on a summary of everything that was
  configured, with no password anywhere in it. An invitation opens the same
  wizard, three steps long.
- **Invite passes.** One link several people can join on, revocable at any
  moment without touching the accounts already made on it. Owner-level links
  warn before they are minted.
- **Where an account came from.** View details on anyone in People: by whose
  link they joined, which link, and when.
- **Two-factor is its own step.** Once the password is accepted the fields that
  proved it are put away, and only the code is asked for.
- **The search bar remembers.** Recent searches come back in the bar, and the
  bookmark beside it saves the current one. Both are account features.
- **Filters and Settings redesigned.** One block rhythm, one row component and
  one set of controls throughout; presence folded into "Show", where it always
  belonged; Appearance moved into Settings, which is now a page with a section
  rail rather than a drawer.
- Message hover actions say what they do straight away, instead of relying on
  a native tooltip that arrives a second late, if at all.
- A network's TLS setting is editable, and "Test connection" tests what Save
  would actually write.

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
