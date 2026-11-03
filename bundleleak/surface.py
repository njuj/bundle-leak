"""Attack surface: the hosts and routes a bundle tells every visitor about."""

from __future__ import annotations

import ipaddress
import re
from urllib.parse import urlsplit

# No leading \b or re.I: both stop re from searching fast for the literal start of the pattern.
URL = re.compile(r"(?:https?|wss?)://[^\s\"'`<>\\)(\]\[{}|^,;]+")
API_PATH = re.compile(r"[\"'`](/(?:api|v\d+|graphql|rest|rpc|admin|internal|debug|_internal|private)"
                      r"(?:/[\w.:{}$-]*)*)[\"'`?]")

_INTERNAL_SUFFIX = (".local", ".internal", ".lan", ".corp", ".intranet", ".home.arpa", ".localdomain", ".test")
_NONPROD = re.compile(r"(?:^|[-.])(?:staging|stage|stg|dev|develop|test|qa|uat|preview|sandbox)(?:$|[-.\d])", re.I)
_BAAS = [
    (re.compile(r"^([a-z0-9]{20})\.supabase\.co$"), "Supabase project"),
    (re.compile(r"\.firebaseio\.com$|\.firebasedatabase\.app$"), "Firebase Realtime Database"),
    (re.compile(r"\.firebaseapp\.com$|\.web\.app$"), "Firebase Hosting / Auth"),
    (re.compile(r"\.appspot\.com$|^firebasestorage\.googleapis\.com$"), "Firebase / Cloud Storage"),
    (re.compile(r"\.s3[.-](?:[a-z0-9-]+\.)?amazonaws\.com$|^s3[.-]"), "Amazon S3"),
    (re.compile(r"^storage\.googleapis\.com$"), "Google Cloud Storage"),
    (re.compile(r"\.blob\.core\.windows\.net$"), "Azure Blob Storage"),
    (re.compile(r"\.r2\.cloudflarestorage\.com$|\.r2\.dev$"), "Cloudflare R2"),
    (re.compile(r"\.convex\.cloud$"), "Convex"),
    (re.compile(r"\.appwrite\.(?:io|global)$"), "Appwrite"),
    (re.compile(r"\.execute-api\.[a-z0-9-]+\.amazonaws\.com$|\.lambda-url\.[a-z0-9-]+\.on\.aws$"), "AWS API Gateway / Lambda"),
    (re.compile(r"\.cloudfunctions\.net$|\.run\.app$"), "Google Cloud Functions / Run"),
    (re.compile(r"\.azurewebsites\.net$"), "Azure App Service"),
]


_HOSTNAME = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*")
# single-label names that are documentation placeholders, not machines
_PLACEHOLDER_HOSTS = {"host", "hostname", "server", "domain", "example", "foo", "bar", "baz", "your", "yourhost",
                      "myhost", "myserver", "ip", "address", "url", "site", "web", "www", "api", "localhost"}
# public services whose host names happen to contain "dev", "test" ...: dev.azure.com is not a staging server
_PUBLIC_SITES = {"azure.com", "w3.org", "mozilla.org", "mozilla.net", "github.com", "github.io", "githubusercontent.com",
                 "npmjs.org", "npmjs.com", "microsoft.com", "visualstudio.com", "office.com", "live.com", "google.com",
                 "googleapis.com", "gstatic.com", "apple.com", "android.com", "chromium.org", "jsdelivr.net",
                 "unpkg.com", "cloudflare.com", "python.org", "nodejs.org", "readthedocs.io", "stackoverflow.com",
                 "wikipedia.org", "ietf.org", "whatwg.org", "schema.org", "mdn.dev", "web.dev", "developer.chrome.com"}


def valid_host(host: str) -> bool:
    host = host.strip("[]").lower().rstrip(".")
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return len(host) <= 253 and bool(_HOSTNAME.fullmatch(host))


def host_kind(host: str) -> str | None:
    """'internal', 'non-production' or None. Junk from URL templates ($1, ${host}, _x_) is None."""
    host = host.strip("[]").lower().rstrip(".")
    if not host or not valid_host(host):
        return None
    try:
        ip = ipaddress.ip_address(host)
        return "internal" if (ip.is_private or ip.is_loopback or ip.is_link_local) and not ip.is_unspecified \
            else None
    except ValueError:
        pass
    if host == "localhost" or host.endswith(_INTERNAL_SUFFIX):
        return "internal"
    if "." not in host:                              # http://db:5432, http://redis: a machine on a private network
        return "internal" if host not in _PLACEHOLDER_HOSTS and len(host) > 1 and not host.isdigit() else None
    from .fetch import site_of
    if site_of(host) in _PUBLIC_SITES or host in _PUBLIC_SITES:
        return None
    labels = host.split(".")[:-1]                   # the TLD never counts: react.dev is not a dev server
    if any(_NONPROD.search(label) for label in labels):
        return "non-production"
    return None


def baas(host: str) -> str | None:
    for rx, name in _BAAS:
        if rx.search(host.lower()):
            return name
    return None


def hosts(text: str) -> list[tuple[str, str]]:
    """(url, host) for every absolute URL in the text."""
    out = []
    for m in URL.finditer(text):
        if m.start() and (text[m.start() - 1].isalnum() or text[m.start() - 1] in "_+.-"):
            continue                                    # "xhttp://", "git+https://": not a URL start
        url = m.group(0).rstrip(".")
        try:
            host = urlsplit(url).hostname or ""
        except ValueError:
            continue
        if host and valid_host(host) and "${" not in url and "%s" not in url:
            out.append((url, host))
    return out


def api_paths(text: str) -> list[str]:
    return [m.group(1) for m in API_PATH.finditer(text)]
