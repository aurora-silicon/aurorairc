"""Fetching things from the internet on the server's behalf, carefully.

Two features need it and neither can be done in the browser:

  * importing history from a URL;
  * the image quick-look — copy, download, details — because the page is
    locked to ``connect-src 'self'`` and cross-origin bytes are unreachable
    from script.

Both mean this server makes a request to somewhere a *user* chose, which is
the shape of a server-side request forgery. So the rules here are strict:

  * ``http`` and ``https`` only — no ``file:``, no ``gopher:``, nothing else;
  * every address the name resolves to must be public. A name that resolves
    to loopback, a private range, link-local, or anything else reserved is
    refused outright;
  * the socket is opened to **the address that was checked**, with the
    hostname carried in the Host header and in TLS SNI, so a name cannot
    resolve to something harmless and then to something else a moment later;
  * redirects are followed by hand, a few hops at most, each one re-checked
    from scratch;
  * a byte cap and a time cap, both enforced while reading rather than after;
  * no cookies, no credentials, no authorization header — ever. A URL
    carrying userinfo is refused rather than quietly stripped.

Nothing here is reachable without a session; see the endpoints in
``ircarchive.server`` for who may call what.
"""

import http.client
import ipaddress
import socket
import ssl
from urllib.parse import urlsplit, urlunsplit, unquote

USER_AGENT = "AuroraIRC/1.1 (+archive importer)"

# Off by default, and deliberately awkward to turn on: `serve
# --allow-local-fetch`. A log server on the same LAN is a real thing to want
# to import from, but allowing it means an owner can point this at anything
# the machine can reach - including whatever else is on that network. It is a
# decision for whoever runs the server, not a default.
ALLOW_PRIVATE = False
MAX_HOPS = 4
DEFAULT_TIMEOUT = 20
DEFAULT_MAX_BYTES = 16 * 1024 * 1024


class FetchError(Exception):
    """Anything that stops a fetch. The message is shown to the user."""


def _public_addresses(host, port):
    """Every address `host` resolves to, refusing the moment one is private.

    All of them are checked, not just the first: a name that answers with one
    public address and one loopback address is an attack, not a mistake.
    """
    try:
        infos = socket.getaddrinfo(host, port, proto=socket.IPPROTO_TCP)
    except socket.gaierror as exc:
        raise FetchError(f"could not look up {host}: {exc.strerror or exc}")
    out = []
    for family, _type, _proto, _canon, sockaddr in infos:
        raw = sockaddr[0]
        try:
            ip = ipaddress.ip_address(raw)
        except ValueError:
            continue
        if (ip.is_private or ip.is_loopback or ip.is_link_local
                or ip.is_multicast or ip.is_reserved or ip.is_unspecified):
            if not ALLOW_PRIVATE:
                raise FetchError(
                    f"{host} resolves to {ip}, which is on this network — "
                    f"only public addresses can be fetched. Start the server "
                    f"with --allow-local-fetch if that is really what you want.")
        out.append((family, raw))
    if not out:
        raise FetchError(f"{host} has no usable address")
    return out


class _PinnedHTTP(http.client.HTTPConnection):
    """Connect to the address that was checked, not to a fresh lookup."""

    def __init__(self, host, ip, family, **kw):
        super().__init__(host, **kw)
        self._ip, self._family = ip, family

    def connect(self):
        self.sock = socket.create_connection(
            (self._ip, self.port), self.timeout)


class _PinnedHTTPS(http.client.HTTPSConnection):
    def __init__(self, host, ip, family, **kw):
        super().__init__(host, **kw)
        self._ip, self._family = ip, family

    def connect(self):
        # The hostname still drives SNI and certificate checking; only the
        # address the socket goes to is pinned.
        raw = socket.create_connection((self._ip, self.port), self.timeout)
        self.sock = self._context.wrap_socket(raw, server_hostname=self.host)


def _one_request(url, timeout, max_bytes, accept):
    parts = urlsplit(url)
    if parts.scheme not in ("http", "https"):
        raise FetchError("only http and https addresses can be fetched")
    if parts.username or parts.password:
        raise FetchError("addresses carrying a username or password are refused")
    host = parts.hostname
    if not host:
        raise FetchError("that address has no host in it")
    port = parts.port or (443 if parts.scheme == "https" else 80)
    family, ip = _public_addresses(host, port)[0]

    path = urlunsplit(("", "", parts.path or "/", parts.query, ""))
    kw = {"timeout": timeout}
    if parts.scheme == "https":
        ctx = ssl.create_default_context()
        conn = _PinnedHTTPS(host, ip, family, port=port, context=ctx, **kw)
    else:
        conn = _PinnedHTTP(host, ip, family, port=port, **kw)

    try:
        conn.request("GET", path, headers={
            "Host": host if port in (80, 443) else f"{host}:{port}",
            "User-Agent": USER_AGENT,
            "Accept": accept or "*/*",
            "Accept-Encoding": "identity",
            "Connection": "close",
        })
        res = conn.getresponse()
        status = res.status
        headers = {k.lower(): v for k, v in res.getheaders()}
        if status in (301, 302, 303, 307, 308):
            return {"redirect": headers.get("location", ""), "status": status}
        # Read with the cap enforced as we go, so a lying Content-Length or no
        # Content-Length at all cannot be used to make us swallow a stream.
        chunks, got = [], 0
        while True:
            block = res.read(64 * 1024)
            if not block:
                break
            got += len(block)
            if got > max_bytes:
                raise FetchError(
                    f"that is larger than the {max_bytes // (1024 * 1024)}MB limit")
            chunks.append(block)
        return {"status": status, "headers": headers, "body": b"".join(chunks),
                "url": url}
    except FetchError:
        raise
    except ssl.SSLError as exc:
        raise FetchError(f"TLS failed: {exc}")
    except socket.timeout:
        raise FetchError(f"timed out after {timeout}s")
    except OSError as exc:
        raise FetchError(str(exc))
    finally:
        try:
            conn.close()
        except OSError:
            pass


def fetch(url, *, timeout=DEFAULT_TIMEOUT, max_bytes=DEFAULT_MAX_BYTES,
          accept=None):
    """Fetch a URL. Returns {url, status, headers, body}. Raises FetchError."""
    seen = set()
    current = str(url or "").strip()
    if not current:
        raise FetchError("no address given")
    for _ in range(MAX_HOPS):
        if current in seen:
            raise FetchError("that address redirects in a loop")
        seen.add(current)
        res = _one_request(current, timeout, max_bytes, accept)
        if "redirect" not in res:
            if res["status"] >= 400:
                raise FetchError(f"the server answered {res['status']}")
            return res
        target = res["redirect"]
        if not target:
            raise FetchError("a redirect with nowhere to go")
        # Relative redirects are ordinary; resolve against where we just were
        from urllib.parse import urljoin
        current = urljoin(current, target)
    raise FetchError("too many redirects")


def charset_of(headers, default="utf-8"):
    ctype = headers.get("content-type", "")
    for bit in ctype.split(";")[1:]:
        name, _, value = bit.strip().partition("=")
        if name.lower() == "charset" and value:
            return value.strip('"').strip()
    return default


def fetch_text(url, **kw):
    """Fetch and decode as text. Never raises on a bad byte - logs are messy."""
    res = fetch(url, **kw)
    return res["body"].decode(charset_of(res["headers"]), "replace"), res


def filename_of(url, fallback="image"):
    """The last path segment, for a download name and for image details."""
    path = urlsplit(str(url or "")).path
    name = unquote(path.rsplit("/", 1)[-1]) if path else ""
    name = name.strip().replace("\\", "_").replace("/", "_")
    # A name is a name, not a path traversal or a control character
    name = "".join(c for c in name if c.isprintable() and c not in '"\r\n\t')
    return name[:120] or fallback
