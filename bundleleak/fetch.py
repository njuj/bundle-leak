"""Polite HTTP: GET only, the same files a browser downloads, inside a scope and a request budget.

Redirects are followed only while they stay in scope, bodies are size-capped (also after decompression),
and the User-Agent says what is asking.
"""

from __future__ import annotations

import ipaddress
import threading
import urllib.error
import urllib.request
import zlib
from dataclasses import dataclass, field
from email.message import Message
from urllib.parse import urlsplit

from . import __version__

USER_AGENT = f"bundle-leak/{__version__} (+https://github.com/njuj/bundle-leak; passive bundle audit)"
_TWO_LEVEL = {"co", "com", "org", "net", "gov", "edu", "ac", "or", "ne", "go"}


def site_of(host: str) -> str:
    """app.example.co.uk -> example.co.uk (good enough without the Public Suffix List). IPs stay as they are."""
    host = host.lower().rstrip(".")
    try:
        ipaddress.ip_address(host.strip("[]"))
        return host
    except ValueError:
        pass
    labels = host.split(".")
    if len(labels) >= 3 and labels[-2] in _TWO_LEVEL and len(labels[-1]) == 2:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


class Scope:
    def __init__(self, start_url: str, mode: str = "site"):
        self.mode = mode
        self.host = (urlsplit(start_url).hostname or "").lower()
        self.site = site_of(self.host)

    def allows(self, url: str) -> bool:
        parts = urlsplit(url)
        if parts.scheme not in ("http", "https"):
            return False
        host = (parts.hostname or "").lower()
        if self.mode == "any":
            return bool(host)
        if self.mode == "host":
            return host == self.host
        return host == self.site or host.endswith("." + self.site) or host == self.host


@dataclass
class Response:
    url: str                          # after redirects
    status: int
    headers: dict[str, str] = field(default_factory=dict)
    body: bytes = b""
    truncated: bool = False
    error: str | None = None

    @property
    def ok(self) -> bool:
        return self.error is None and 200 <= self.status < 300

    def text(self) -> str:
        msg = Message()
        msg["content-type"] = self.headers.get("content-type", "")
        charset = msg.get_content_charset() or "utf-8"
        try:
            return self.body.decode(charset, "replace")
        except LookupError:
            return self.body.decode("utf-8", "replace")


class _OutOfScope(Exception):
    pass


class _Redirects(urllib.request.HTTPRedirectHandler):
    max_redirections = 5

    def __init__(self, scope: Scope):
        self.scope = scope

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        if not self.scope.allows(newurl):
            raise _OutOfScope(newurl)
        return super().redirect_request(req, fp, code, msg, headers, newurl)


class Fetcher:
    def __init__(self, scope: Scope, max_requests: int = 400, max_bytes: int = 25 * 1024 * 1024,
                 timeout: float = 15.0, headers: dict[str, str] | None = None, user_agent: str = USER_AGENT):
        self.scope, self.max_requests, self.max_bytes, self.timeout = scope, max_requests, max_bytes, timeout
        self.headers = {"User-Agent": user_agent, "Accept-Encoding": "gzip, deflate", **(headers or {})}
        self.requests = 0
        self.budget_hit = False
        self._lock = threading.Lock()
        self._opener = urllib.request.build_opener(_Redirects(scope))

    def get(self, url: str) -> Response | None:
        """None when out of scope or out of budget; otherwise a Response (maybe an error one)."""
        if not self.scope.allows(url):
            return None
        with self._lock:
            if self.requests >= self.max_requests:
                self.budget_hit = True
                return None
            self.requests += 1
        req = urllib.request.Request(url, headers=self.headers, method="GET")
        try:
            with self._opener.open(req, timeout=self.timeout) as r:
                raw = r.read(self.max_bytes + 1)
                headers = {k.lower(): v for k, v in r.headers.items()}
                status, final = r.status, r.geturl()
        except _OutOfScope as e:
            return Response(url, 0, error=f"redirects out of scope to {e}")
        except urllib.error.HTTPError as e:
            return Response(url, e.code, error=f"HTTP {e.code}")
        except (urllib.error.URLError, OSError, ValueError) as e:
            reason = getattr(e, "reason", e)
            return Response(url, 0, error=str(reason)[:200])
        truncated = len(raw) > self.max_bytes
        body = raw[:self.max_bytes]
        encoding = headers.get("content-encoding", "").lower()
        if encoding in ("gzip", "x-gzip", "deflate"):
            # "deflate" should be zlib-wrapped, but plenty of servers send raw deflate: try both
            for wbits in ((16 + zlib.MAX_WBITS,) if "gzip" in encoding else (zlib.MAX_WBITS, -zlib.MAX_WBITS)):
                try:
                    d = zlib.decompressobj(wbits)
                    inflated = d.decompress(body, self.max_bytes)   # capped: a decompression bomb stops here
                    truncated = truncated or bool(d.unconsumed_tail)
                    body = inflated
                    break
                except zlib.error as e:
                    error = f"bad {encoding} body: {e}"
            else:
                return Response(final, status, headers, error=error)
        return Response(final, status, headers, body, truncated)
