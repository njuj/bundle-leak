"""Which files make up the app: the scripts a page loads, and the chunks those scripts load later.

Lazy chunks never appear in the HTML; they are named inside the JavaScript, as ES imports, as Vite's
dependency lists, in Next.js' build manifest, or computed by webpack's runtime from an id -> hash table.
All of these are read statically; nothing is executed.
"""

from __future__ import annotations

import re
from html.parser import HTMLParser
from urllib.parse import urljoin, urlsplit


class _Page(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.base: str | None = None
        self.scripts: list[str] = []          # src of <script> and preloaded modules
        self.inline: list[str] = []           # bodies of inline <script>
        self._in_script = False
        self._buf: list[str] = []

    def handle_starttag(self, tag, attrs):
        a = {k.lower(): (v or "") for k, v in attrs}
        if tag == "base" and a.get("href") and self.base is None:
            self.base = a["href"]
        elif tag == "script":
            if a.get("src"):
                self.scripts.append(a["src"])
            else:
                self._in_script, self._buf = True, []
        elif tag == "link" and a.get("href"):
            rel = a.get("rel", "").lower().split()
            if "modulepreload" in rel or ("preload" in rel and a.get("as") == "script") or (
                    "prefetch" in rel and re.search(r"\.m?js(?:\?|$)", a["href"])):
                self.scripts.append(a["href"])

    def handle_endtag(self, tag):
        if tag == "script" and self._in_script:
            self._in_script = False
            body = "".join(self._buf)
            if body.strip():
                self.inline.append(body)

    def handle_data(self, data):
        if self._in_script:
            self._buf.append(data)


def page(html: str, url: str) -> tuple[list[str], list[str]]:
    """(absolute script URLs, inline script bodies) of an HTML page."""
    p = _Page()
    try:
        p.feed(html)
        p.close()
    except Exception:                                  # html.parser is lenient, but never let a page crash a scan
        pass
    base = urljoin(url, p.base) if p.base else url
    return _unique(urljoin(base, s.strip()) for s in p.scripts if not s.strip().startswith(("data:", "blob:"))), \
        p.inline


# ── chunk references inside JavaScript ────────────────────────────────────────

_IMPORT = re.compile(r"""(?:\bimport\s*\(\s*|\bimport\s*|\bfrom\s*|\bimportScripts\s*\(\s*|\bnew\s+Worker\s*\(\s*|"""
                     r"""\bnew\s+URL\s*\(\s*)(["'`])([^"'`\s]{1,300}?\.m?js(?:\?[^"'`\s]*)?)\1""")
_PATHLIKE = re.compile(r"""(["'`])((?:\.{1,2}/|/)?(?:[\w@.~-]+/)+[\w@.~-]+\.m?js)\1""")
_PUBLIC_PATH = re.compile(r"""\b\w{1,3}\.p\s*=\s*["']([^"']{1,200})["']""")
_WEBPACK_CHUNKS = re.compile(
    r"""["']((?:[\w.@~-]+/)*)["']\s*\+\s*\(*\s*(?:\{([^{}]{0,200000})\}\s*\[\s*(\w+)\s*\]\s*\|\|\s*\w+|(\w+))\s*\)*"""
    r"""\s*\+\s*["']([.-])["']\s*\+\s*\{([^{}]{1,500000})\}\s*\[\s*\w+\s*\]\s*\+\s*["']((?:\.[\w-]+)*\.js)["']""")
_PAIR = re.compile(r"""(?:"([^"]+)"|'([^']+)'|(\w+))\s*:\s*["']([^"']+)["']""")


def _pairs(body: str) -> dict[str, str]:
    return {(m.group(1) or m.group(2) or m.group(3)): m.group(4) for m in _PAIR.finditer(body)}


def chunks(js: str, script_url: str, page_url: str) -> list[str]:
    """Absolute URLs of the scripts this script can load."""
    base = _base_for_bare(js, script_url, page_url)
    found = []
    for m in _IMPORT.finditer(js):
        found.append(_resolve(m.group(2), script_url, base, esm=True))
    for m in _PATHLIKE.finditer(js):
        path = m.group(2)
        if "node_modules" in path or path.startswith("//"):
            continue
        found.append(_resolve(path, script_url, base, esm=False))
    for m in _WEBPACK_CHUNKS.finditer(js):            # "static/chunks/"+e+"."+{12:"9f3a..."}[e]+".js"
        prefix, names, sep, hashes, suffix = m.group(1), _pairs(m.group(2) or ""), m.group(5), _pairs(m.group(6)), \
            m.group(7)
        for cid, h in list(hashes.items())[:2000]:
            found.append(_resolve(f"{prefix}{names.get(cid, cid)}{sep}{h}{suffix}", script_url, base, esm=False))
    return _unique(u for u in found if u)


def _base_for_bare(js: str, script_url: str, page_url: str) -> str:
    """Where a path like "static/chunks/x.js" or "assets/x.js" is relative to."""
    path = urlsplit(script_url).path
    if "/_next/" in path:                               # Next.js: everything under <basePath>/_next/
        return urljoin(script_url, path[:path.index("/_next/") + len("/_next/")])
    m = _PUBLIC_PATH.search(js)                         # webpack's __webpack_require__.p = "/static/"
    if m and m.group(1) not in ("", "auto"):
        return urljoin(page_url, m.group(1))
    return urljoin(page_url, "/")                       # Vite's __vite__mapDeps paths are relative to the base


def _resolve(path: str, script_url: str, base: str, esm: bool) -> str | None:
    if path.startswith(("http://", "https://")):
        return path
    if path.startswith(("./", "../", "/")) or esm:
        return urljoin(script_url, path)
    return urljoin(base, path)


def _unique(items) -> list:
    seen, out = set(), []
    for item in items:
        if item and item not in seen:
            seen.add(item)
            out.append(item)
    return out
