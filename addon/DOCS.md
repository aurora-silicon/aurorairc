# AuroraIRC

An IRC client and searchable archive that runs beside Home Assistant. It joins
the channels you configure, records everything it sees, and serves a fast web
client for reading, searching and posting — plus a read-only MCP endpoint so
agents can query the archive.

## Installing

1. **Settings → Add-ons → Add-on Store**, then **⋮ → Repositories**.
2. Add `https://github.com/aurora-silicon/aurorairc`.
3. Install **AuroraIRC**, then **Start**.
4. Open **`http://<your-ha-ip>:8420`** and create the owner account.

Nothing is configured out of the box: no networks, no channels, no accounts.
The first visit prompts you to create the owner; after that, further accounts
exist only by invitation.

## Adding a network

From the app: **Settings → Networks → Add**. Give it a host (for example
`irc.libera.chat`), a port, an archivist nick, and the channels to record.

The archivist connects within ten seconds of you saving — there is no need to
restart the add-on.

## Options

| Option | Meaning |
| --- | --- |
| `behind_proxy` | Read the real client address from `CF-Connecting-IP`, or the right-hand end of `X-Forwarded-For`. Turn this on **only** when something else terminates TLS in front, such as a Cloudflare Tunnel. |
| `proxy_hops` | How many proxies sit in front, counting from the right. Left-hand `X-Forwarded-For` entries are attacker-controlled and are deliberately ignored. |

Leaving `behind_proxy` on without a real proxy in front lets a client spoof its
own address and slip the login throttle, so keep it off until the tunnel is up.

## Where the data lives

Everything is one SQLite file at `/data/archive.db` inside the add-on, which
the Supervisor keeps across restarts and updates. Accounts, passkeys, tags and
saved searches all live there.

Included in Home Assistant's own backups, so a full backup captures the
archive. On a Pi that writes continuously, so put Home Assistant on an SSD
rather than an SD card — sustained SQLite writes will wear a card out.

## Passkeys and HTTPS

Passkeys need a secure context. They work over `localhost` and over HTTPS once
a tunnel or reverse proxy is in front, but **not** over plain `http://` to a
LAN address, where browsers hide the API entirely. Password and TOTP sign-in
work everywhere.

## Agents (MCP)

Read-only by construction: the database is opened `mode=ro`, so the driver
itself refuses writes, and no tool can send to IRC.

Create a token in **Account settings**, then point an agent at
`http://<your-ha-ip>:8420/mcp` with `Authorization: Bearer <token>`.

## Exposing it publicly

Pair it with a Cloudflare Tunnel add-on pointed at `http://<add-on>:8420`,
turn `behind_proxy` on, and rate-limit `/api/*` and `/mcp` at the edge. Do not
forward port 8420 on your router.
