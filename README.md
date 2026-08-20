# AuroraIRC

An IRC client and searchable archive. It joins the channels you configure,
records everything it sees, and serves a fast web client for reading, searching
and posting — plus a read-only MCP endpoint so agents can query the archive.

No dependencies. Python 3.9+ standard library and SQLite, nothing else to
install, nothing to compile.

By **RyanTheTide**.

---

## Quick start

```bash
git clone https://github.com/aurora-silicon/aurorairc
cd aurorairc

./archive.py serve            # open http://localhost:8420
./archive.py live             # connect and start recording
```

The first visit walks you through setup: name the server, create the owner
account, add a passkey or two-factor if you want one, hand out invitations, and
connect to a network — the connection is tested before it is saved, and can be
left until later. There is no default password and no public signup; after the
owner, further accounts exist only by invitation or by an owner's hand.

Nothing is configured out of the box: no networks, no channels, no accounts.

Networks can also be added from the command line if you prefer:

```bash
./archive.py network add libera --host irc.libera.chat --channels mychannel
```

---

## How it fits together

Three processes, sharing one SQLite file:

| Command | Does |
| --- | --- |
| `./archive.py serve` | the web client and JSON API |
| `./archive.py live` | connects to IRC, records, and sends queued messages |
| `./mcp_server.py` | read-only MCP over stdio, for agents |

**The archivist connection only ever listens.** It joins your channels, records
what it sees, and never transmits. When a signed-in user posts, a *separate*
send-only connection is opened under that user's own nick; their message comes
back through the archivist and is recorded once, correctly attributed. The
consequence is that logging never stops, whatever anyone else is doing.

---

## The client

- **Search** — SQLite FTS5. `"quoted phrases"` and `prefix*` work.
- **One search grammar** — `#channel`, `@person`, `&tag`, and free text combine:
  `#mychannel @someone &important term`. Typing any sigil offers completions.
- **The bar remembers** — recent searches come back in the bar itself, and the
  bookmark beside it saves the current one. Both are per account and follow you
  between devices; an anonymous reader gets neither.
- **Pictures open in place** — a quick look with zoom and pan, arrows through
  every picture on screen, and reply, save, open where it lives, copy the
  picture, copy its address, or read what it actually is. No leaving the
  archive to look at a screenshot.
- **Tags** — Finder-style coloured flags for marking messages worth finding again.
- **Jump to context** — land on any message in its surrounding conversation, with
  a linkable URL.
- **Live** — new messages arrive over server-sent events, typically within a
  second.
- **Your clock** — every time, day heading and date filter is rendered in the
  device's own zone, never the server's. 12- or 24-hour is yours to pick.
- **Presence** — joins and quits are recorded separately from conversation and
  are off by default, folded into quiet single lines when shown.
- Themes (system / light / dark / noir), accent colours, optional background,
  saved searches, and a mobile layout that is not an afterthought.

---

## Accounts

| | Read | Send | Tag | Manage |
| --- | --- | --- | --- | --- |
| Anonymous | yes | no | no | no |
| Member | yes | yes | yes | no |
| Owner | yes | yes | yes | yes |

Anonymous read-only access is the public product; every write sits behind a
session. The **first account created is root** and cannot be demoted, disabled
or removed by anyone, including other owners.

Sign in with a password, optionally with TOTP two-factor, or with a **passkey**.
The second factor is asked for as its own step, once the password has actually
been accepted — the fields that got you there are put away rather than left on
screen. Sessions live in the database, carry a CSRF token, and can be revoked
per device from Settings.

**Invitations and passes.** An owner mints a link. A plain link seats one
person; a **pass** seats several — five people joining a room from one link —
and either can be revoked at any moment without disturbing the accounts already
created on it. An owner-level link warns before it is minted, because whoever
uses it gets the server. Every redemption is recorded, so **View details** on
any account answers where it came from: by whose link, which link, and when.

> Passkeys need a secure context. They work on `localhost`, and over HTTPS once
> you put a reverse proxy or tunnel in front — but not over plain `http://` to a
> LAN address, where browsers hide the API entirely.

---

## Importing history

Ingest exported logs, or your own client logs — both are idempotent, so
re-running only adds what is new:

```bash
./archive.py import ~/.weechat/logs --channel mychannel
```

Recognised automatically: **ZNC, irssi, WeeChat, HexChat**, and the exported
log shape. Joins and quits are filtered out of conversation and stored
separately.

The same thing is in **Settings → Server**, which matters on Home Assistant
where there is no shell: give it a web address — a log file, or a directory
listing it may follow — or hand it files from your own machine. Either way the
text goes through the parsers above, so nothing is parsed twice or parsed
differently.

**Check it first** runs the whole import for real inside a transaction and
rolls it back, then shows you the format it recognised, the channels and dates
it found, and the first lines exactly as it read them — including how many are
already in the archive. Only then does Import light up.

Fetching a URL means this server makes a request somewhere you chose, so it is
kept on a short lead: http and https only, public addresses only — checked for
every address a name resolves to, and the socket is opened to the address that
was checked — a few redirects at most, each re-checked, and hard caps on size
and time. A log server on your own network is refused by default; start the
server with `--allow-local-fetch` if that is really what you want.

---

## Agents (MCP)

Read-only by construction: the connection is opened `mode=ro`, so the driver
itself refuses writes, and there is no tool that can send to IRC.

**Locally**, over stdio:

```json
{ "mcpServers": { "aurorairc": { "command": "/path/to/aurorairc/mcp_server.py" } } }
```

**Remotely**, over HTTP with a per-agent token:

```bash
./archive.py token alice --name "alice-laptop"
```

```json
{ "mcpServers": { "aurorairc": {
  "url": "https://chat.example.org/mcp",
  "headers": { "Authorization": "Bearer irc_..." }
} } }
```

Tokens are created and revoked from Account settings, stored only as hashes,
and shown once. Both transports share one tool definition, so they cannot drift
apart.

Tools: `search_messages`, `get_context`, `locate_message`, `list_channels`,
`list_nicks`, `list_tags`, `activity`, `archive_stats`.

---

## Exposing it publicly

The bundled server is `http.server`. It is fine behind something, and should
not be the thing facing the internet directly.

```bash
./archive.py serve --host 127.0.0.1 --behind-proxy
```

Put a tunnel or reverse proxy in front, terminate TLS there, and rate-limit
`/api/*` and `/mcp` at that layer. `--behind-proxy` makes the app read the real
client address from `CF-Connecting-IP`, or from the right-hand end of
`X-Forwarded-For` (`--proxy-hops N`) — the left-hand entries are attacker
controlled and are deliberately ignored.

Without a proxy, bind to your LAN with `--host 0.0.0.0` and accept that reading
is open to that network.

---

## Testing

Two suites, both self-contained. Neither touches a real IRC network or the
outside world: `tests/fakeircd.py` is a small server that speaks just enough
IRC to exercise the real pipeline, and messages sent by one connection come
back through another exactly as they would on a real network.

```bash
python3 tests/e2e.py          # the API and the live pipeline, end to end
python3 tests/uiserver.py     # the client itself, driven in a real browser
python3 tests/uiserver.py --hold    # or leave the stack up to poke at by hand
```

The browser suite needs Playwright and Chromium; it says so and exits cleanly
if they are not installed.

## Notes

- The archive is one SQLite file. Move hosts by copying `archive.db`; accounts,
  passkeys, tags and saved searches move with it. Passkeys are bound to the
  hostname, not the machine, so keep the domain stable.
- Runs comfortably on a Raspberry Pi 4. Put the database on an SSD rather than
  an SD card — live capture writes continuously and will wear a card out.
- Pictures are displayed straight from wherever they are hosted, exactly as
  before. Copying, saving and reading a picture's real type and size go through
  `/api/fetch/image` instead, because the page is locked to `connect-src 'self'`
  and script cannot touch cross-origin bytes at all. That route needs a session,
  serves only things browsers draw, and always as an attachment.
- WebAuthn verification (CBOR, ECDSA P-256, RSA PKCS#1 v1.5) is implemented in
  `ircarchive/webauthn.py` because no crypto library is assumed. It handles only
  public values — public keys, signatures, messages — so there are no secrets to
  leak through timing; signing happens on the authenticator. It is tested
  against published vectors, including forgery cases.

## Licence

MIT — see [LICENSE](LICENSE). Copyright © 2026 RyanTheTide.
