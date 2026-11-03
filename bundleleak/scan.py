"""The scan itself: collect the assets (from a live site or a build folder), read them, report."""

from __future__ import annotations

import bisect
import os
import re
import time
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urljoin, urlsplit

from . import detectors, discover, env, sourcemap, surface
from .detectors import RANK, redact
from .fetch import Fetcher, Response, Scope


@dataclass
class Location:
    asset: str                       # URL or path of the file the hit is in
    line: int                        # 1-based, in the asset (or in `source` when that is set)
    column: int
    source: str | None = None        # an original file inside a source map
    mapped: str | None = None        # bundle position translated through its map: "src/x.ts:4:27"


@dataclass
class Finding:
    rule: str
    title: str
    severity: str
    evidence: str
    detail: str
    advice: str
    locations: list[Location] = field(default_factory=list)
    key: str = ""                    # what makes two hits the same finding (never printed)


@dataclass
class MapInfo:
    url: str
    bundle: str
    how: str                         # declared / hidden / inline / header
    sources: int
    app_sources: int
    readable: int                    # app sources whose original text is in the map
    notable: list[str]


@dataclass
class Report:
    target: str
    mode: str                        # url / dir
    assets: list[tuple[str, str, int]] = field(default_factory=list)     # (where, kind, bytes)
    findings: list[Finding] = field(default_factory=list)
    env: dict[str, str | None] = field(default_factory=dict)
    maps: list[MapInfo] = field(default_factory=list)
    hosts: dict[str, dict] = field(default_factory=dict)
    api_paths: Counter = field(default_factory=Counter)
    third_party: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    suppressed_library_hits: int = 0
    budget_hit: bool = False
    requests: int = 0
    elapsed: float = 0.0

    @property
    def bytes(self) -> int:
        return sum(a[2] for a in self.assets)


class _Lines:
    """Offset -> (line, column), with the line index built on first use."""

    def __init__(self, text: str):
        self.text = text
        self.starts: list[int] | None = None

    def at(self, offset: int) -> tuple[int, int]:
        """0-based (line, column)."""
        if self.starts is None:
            self.starts = [0] + [m.end() for m in re.finditer("\n", self.text)]
        i = bisect.bisect_right(self.starts, offset) - 1
        return i, offset - self.starts[i]


_NOTABLE = re.compile(r"(?i)(?:^|/)(?:\.env[^/]*|[^/]*(?:config|secret|key|auth|supabase|firebase|admin|api|stripe|"
                      r"openai|credential|token|server|db|database)[^/]*)$")
_TEXT_EXT = {".js", ".mjs", ".cjs", ".html", ".htm", ".json", ".map", ".txt", ".xml", ".webmanifest"}
_SKIP_DIRS = {"node_modules", ".git", ".svn", "__pycache__", ".turbo", ".cache"}
_SKIP_FILES = {"package-lock.json", "yarn.lock", "pnpm-lock.yaml", "npm-shrinkwrap.json"}


class Scanner:
    def __init__(self, show_secrets: bool = False, include_libraries: bool = False):
        self.show_secrets = show_secrets
        self.include_libraries = include_libraries
        self.report: Report | None = None
        self._by_key: dict[str, Finding] = {}

    # ── findings ──────────────────────────────────────────────────────────────

    def _add(self, rule, title, severity, evidence, detail, advice, loc: Location, key: str):
        f = self._by_key.get(key)
        if f is None:
            f = Finding(rule, title, severity, evidence, detail, advice, [], key)
            self._by_key[key] = f
            self.report.findings.append(f)
        elif RANK[severity] < RANK[f.severity]:
            f.severity, f.title = severity, title
        if len(f.locations) < 50 and loc not in f.locations:
            f.locations.append(loc)

    def _evidence(self, hit: detectors.Hit) -> str:
        if hit.rule == "private-key":
            return hit.secret                             # the PEM header, not the key
        if hit.rule in ("database-url", "url-credentials"):
            return hit.detail + ("" if not self.show_secrets else f"  (password: {hit.secret})")
        return hit.secret if self.show_secrets else redact(hit.secret)

    def scan_text(self, text: str, asset: str, sm: sourcemap.SourceMap | None = None, source: str | None = None,
                  library: bool = False):
        """Secrets, public env vars and hosts in one file (or one original source inside a map)."""
        hits = detectors.scan(text)
        lines = _Lines(text)
        mapped = {}
        if sm is not None and hits:
            try:
                mapped = sm.lookup([lines.at(h.start) for h in hits])
            except ValueError as e:
                self.report.errors.append(f"{asset}: unreadable source map mappings ({e})")
        for h in hits:
            line, col = lines.at(h.start)
            m = mapped.get((line, col))
            if (library or (m and m[0].library)) and not self.include_libraries:
                self.report.suppressed_library_hits += 1
                continue
            loc = Location(asset, line + 1, col + 1, source,
                           f"{m[0].path}:{m[1]}:{m[2]}" if m else None)
            detail = h.detail
            self._add(h.rule, h.title, h.severity, self._evidence(h), detail, h.advice, loc, f"{h.rule}|{h.secret}")
        for var in env.find(text):
            if library and not self.include_libraries:
                continue
            if var.value is not None or var.name not in self.report.env:
                self.report.env[var.name] = var.value
            kind = env.classify(var.name)
            if kind:
                line, col = lines.at(var.start)
                shown = var.name if var.value is None else \
                    f"{var.name} = {var.value if self.show_secrets else redact(var.value)}"
                if kind == "secret":
                    self._add("public-env-secret", f"Secret-named variable shipped with a public prefix: {var.name}",
                              "high", shown, "every NEXT_PUBLIC_ / VITE_ / REACT_APP_ variable is copied into the "
                              "bundle at build time", "Drop the public prefix, rotate the value and use it from "
                              "server code only.", Location(asset, line + 1, col + 1, source), f"env|{var.name}")
                else:
                    self._add("public-env-key", f"API key shipped through a public variable: {var.name}", "low",
                              shown, "fine for publishable / browser keys, a leak for anything else",
                              "Check the provider's docs: is this key meant to be public, and is it restricted?",
                              Location(asset, line + 1, col + 1, source), f"env|{var.name}")
        if not library:
            for url, host in surface.hosts(text):
                rec = self.report.hosts.setdefault(host, {"kind": surface.host_kind(host), "service": surface.baas(host),
                                                          "count": 0, "example": url, "where": asset})
                rec["count"] += 1
            self.report.api_paths.update(surface.api_paths(text))

    def scan_map(self, sm: sourcemap.SourceMap, map_url: str, bundle: str, how: str):
        sources = sm.all_sources()
        app = [s for s in sources if not s.library]
        readable = [s for s in app if s.content]
        notable = [s.path for s in app if _NOTABLE.search(s.path)][:8]
        self.report.maps.append(MapInfo(map_url, bundle, how, len(sources), len(app), len(readable), notable))
        for s in sources:
            if s.content and (not s.library or self.include_libraries):
                self.scan_text(s.content, map_url, source=s.path, library=s.library)

    # ── after collection ──────────────────────────────────────────────────────

    def _summarise(self):
        r = self.report
        if r.maps:
            readable = sum(m.readable for m in r.maps)
            hows = Counter(m.how for m in r.maps)
            how = ", ".join(f"{n} {k}" for k, n in hows.items())
            if readable:
                title, sev = f"Source maps expose the original code of {readable} file(s)", "medium"
            else:
                title, sev = "Source maps are public (file names and structure, no source text)", "low"
            notable = sorted({p for m in r.maps for p in m.notable})[:6]
            detail = f"{len(r.maps)} map(s): {how}" + (f" · notable: {', '.join(notable)}" if notable else "")
            if hows.get("hidden"):
                detail += " · 'hidden' = the bundle does not reference it, but the server hands it out anyway"
            advice = ("Stop deploying .map files (or keep them behind auth / upload them to your error tracker "
                      "and delete them from the build), e.g. Vite build.sourcemap: false, Next.js "
                      "productionBrowserSourceMaps: false.")
            for m in r.maps[:20]:
                self._add("source-map-exposed", title, sev, f"{m.app_sources} app file(s)", detail, advice,
                          Location(m.url, 1, 1), "source-maps")
        internal = {h: v for h, v in r.hosts.items() if v["kind"] == "internal" and h not in ("localhost",)
                    and not h.startswith("127.")}
        if internal:
            names = ", ".join(sorted(internal)[:8])
            for h, v in list(internal.items())[:20]:
                self._add("internal-host", "Internal hostnames or private IPs in the shipped code", "low", names,
                          "they map your network for whoever reads the bundle",
                          "Keep internal addresses in server-side configuration.", Location(v["where"], 1, 1),
                          "internal-hosts")
        nonprod = {h: v for h, v in r.hosts.items() if v["kind"] == "non-production"}
        if nonprod:
            names = ", ".join(sorted(nonprod)[:8])
            for h, v in list(nonprod.items())[:20]:
                self._add("non-production-host", "Staging / development hosts referenced", "info", names,
                          "non-production environments are often less protected than production",
                          "Make sure they require authentication, or drop them from production builds.",
                          Location(v["where"], 1, 1), "nonprod-hosts")
        r.findings.sort(key=lambda f: (RANK[f.severity], f.title))

    # ── build folder ──────────────────────────────────────────────────────────

    def scan_dir(self, root: Path) -> Report:
        started = time.perf_counter()
        self.report = Report(str(root), "dir")
        self._by_key = {}
        root = root.resolve()
        files = []
        for dirpath, dirnames, filenames in os.walk(root):
            dirnames[:] = sorted(d for d in dirnames if d not in _SKIP_DIRS)
            for name in sorted(filenames):
                files.append(Path(dirpath, name))
        maps_done: set[Path] = set()
        for path in files:
            rel = path.relative_to(root).as_posix()
            ext = path.suffix.lower()
            is_env = path.name.startswith(".env")
            if path.name in _SKIP_FILES or not (ext in _TEXT_EXT or is_env) or ext == ".map":
                continue
            text = self._read(path, rel)
            if text is None:
                continue
            self.report.assets.append((rel, "env" if is_env else ext.lstrip("."), len(text)))
            if is_env:
                self._add("env-file", "Environment file inside the build output", "critical", rel,
                          "everything in the output folder is served to the public", "Delete it from the output, "
                          "rotate every secret it holds, and fix the build step that copied it.",
                          Location(rel, 1, 1), f"envfile|{rel}")
            sm = None
            if ext in (".js", ".mjs", ".cjs"):
                sm, map_path, how = self._local_map(path, text, root)
                if sm is not None:
                    if map_path:
                        maps_done.add(map_path)
                    self.scan_map(sm, _rel(map_path, root) if map_path else rel + " (inline)", rel, how)
            self.scan_text(text, rel, sm)
        for path in files:                                   # maps no bundle pointed at
            if path.suffix.lower() == ".map" and path.resolve() not in maps_done:
                rel = path.relative_to(root).as_posix()
                text = self._read(path, rel)
                if text is None:
                    continue
                try:
                    sm = sourcemap.parse(text)
                except ValueError:
                    continue
                self.report.assets.append((rel, "map", len(text)))
                self.scan_map(sm, rel, rel[:-4], "unreferenced")
        self._summarise()
        self.report.elapsed = time.perf_counter() - started
        return self.report

    def _read(self, path: Path, rel: str) -> str | None:
        try:
            if path.stat().st_size > 50 * 1024 * 1024:
                self.report.errors.append(f"{rel}: larger than 50 MB, skipped")
                return None
            return path.read_bytes().decode("utf-8-sig", "replace")
        except OSError as e:
            self.report.errors.append(f"{rel}: {e.strerror or e}")
            return None

    def _local_map(self, js_path: Path, js: str, root: Path):
        ref = sourcemap.map_reference(js)
        how = "declared"
        if ref:
            inline = sourcemap.inline_map(ref)
            if inline is not None:
                try:
                    return sourcemap.parse(inline), None, "inline"
                except ValueError:
                    return None, None, ""
            if re.match(r"^[a-z][a-z0-9+.-]*://", ref, re.I):
                return None, None, ""                    # an absolute URL: not in this folder
            candidate = (js_path.parent / ref.split("?")[0]).resolve()
        else:
            candidate, how = js_path.with_name(js_path.name + ".map").resolve(), "hidden"
        if candidate.is_file():
            rel = _rel(candidate, root)
            text = self._read(candidate, rel)
            if text is not None:
                try:
                    sm = sourcemap.parse(text)
                    self.report.assets.append((rel, "map", len(text)))
                    return sm, candidate, how
                except ValueError:
                    pass
        return None, None, ""

    # ── live site ─────────────────────────────────────────────────────────────

    def scan_url(self, url: str, scope: str = "site", max_requests: int = 400, probe_maps: bool = True,
                 concurrency: int = 4, timeout: float = 15.0, headers: dict | None = None) -> Report:
        started = time.perf_counter()
        self.report = Report(url, "url")
        self._by_key = {}
        fetcher = Fetcher(Scope(url, scope), max_requests=max_requests, timeout=timeout, headers=headers)
        first = fetcher.get(url)
        if first is None or not first.ok:
            self.report.errors.append(f"{url}: {first.error if first else 'out of scope'}")
            self.report.elapsed = time.perf_counter() - started
            return self.report
        page_url = first.url
        scripts: list[str] = []
        if _is_html(first):
            html = first.text()
            self.report.assets.append((first.url, "html", len(first.body)))
            found, inline = discover.page(html, first.url)
            scripts += found
            for i, body in enumerate(inline, 1):
                self.scan_text(body, f"{first.url} (inline script #{i})")
                scripts += discover.chunks(body, first.url, first.url)
            self.scan_text(re.sub(r"<script\b[^>]*>.*?</script>", " ", html, flags=re.S | re.I), first.url)
        else:
            scripts.append(first.url)
        seen: set[str] = set()
        wave = scripts
        with ThreadPoolExecutor(max_workers=max(1, concurrency)) as pool:
            while wave:
                todo = []
                for s in wave:
                    key = s.split("#")[0]
                    if key in seen:
                        continue
                    seen.add(key)
                    if not fetcher.scope.allows(key):
                        self.report.third_party.append(key)
                        continue
                    todo.append(key)
                results = list(pool.map(lambda u: (u, self._fetch_script(fetcher, u, probe_maps)), todo))
                wave = []
                for u, got in results:
                    if got is None:
                        continue
                    js, final, sm, map_url, how = got
                    self.report.assets.append((final, "js", len(js)))
                    if sm is not None:
                        self.scan_map(sm, map_url, final, how)
                    self.scan_text(js, final, sm)
                    wave += discover.chunks(js, final, page_url)
        self.report.third_party = sorted(set(self.report.third_party))
        self.report.budget_hit = fetcher.budget_hit
        self.report.requests = fetcher.requests
        self._summarise()
        self.report.elapsed = time.perf_counter() - started
        return self.report

    def _fetch_script(self, fetcher: Fetcher, url: str, probe_maps: bool):
        r = fetcher.get(url)
        if r is None:
            return None
        if not r.ok:
            if r.status != 404:
                self.report.errors.append(f"{url}: {r.error}")
            return None
        if _is_html(r):                                   # an SPA answering every path with index.html
            return None
        js = r.text()
        ref = sourcemap.map_reference(js) or r.headers.get("sourcemap") or r.headers.get("x-sourcemap")
        how = "declared" if sourcemap.map_reference(js) else "header"
        sm, map_url = None, None
        if ref:
            inline = sourcemap.inline_map(ref)
            if inline is not None:
                try:
                    return js, r.url, sourcemap.parse(inline), r.url + " (inline)", "inline"
                except ValueError:
                    return js, r.url, None, None, ""
            map_url = urljoin(r.url, ref)
        elif probe_maps:
            map_url, how = r.url.split("?")[0] + ".map", "hidden"
        if map_url:
            m = fetcher.get(map_url)
            if m is not None and m.ok and not _is_html(m):
                try:
                    sm = sourcemap.parse(m.text())
                    self.report.assets.append((m.url, "map", len(m.body)))
                except ValueError:
                    sm = None
        return js, r.url, sm, map_url if sm else None, how


def _rel(path: Path, root: Path) -> str:
    try:
        return path.relative_to(root).as_posix()
    except ValueError:                                   # a map outside the folder (../): show it as it is
        return path.as_posix()


def _is_html(r: Response) -> bool:
    ctype = r.headers.get("content-type", "").lower()
    head = r.body[:200].lstrip().lower()
    return "text/html" in ctype or head.startswith((b"<!doctype html", b"<html"))


def short(where: str, target: str) -> str:
    """https://app.example.com/assets/x.js -> assets/x.js when it is on the scanned origin."""
    t, w = urlsplit(target), urlsplit(where)
    if w.scheme and (w.scheme, w.netloc) == (t.scheme, t.netloc):
        return w.path.lstrip("/") + (("?" + w.query) if w.query else "") or "/"
    return where
