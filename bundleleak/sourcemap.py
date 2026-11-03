"""Source Map v3: read the original files out of a map and translate bundle positions back to them.

Maps get large (tens of MB of mappings for a big app), so nothing is decoded up front: lookups are
batched and answered in one streaming pass over the mappings.
"""

from __future__ import annotations

import base64
import binascii
import bisect
import functools
import json
import re
from dataclasses import dataclass, field

_B64 = {c: i for i, c in enumerate("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/")}


@functools.lru_cache(maxsize=1 << 16)          # real mappings repeat the same few segments endlessly
def vlq_decode(segment: str) -> tuple[int, ...]:
    """'2H' -> (123,), 'AAgBC' -> (0, 0, 16, 1). Raises ValueError on garbage."""
    values, shift, value = [], 0, 0
    for ch in segment:
        try:
            digit = _B64[ch]
        except KeyError:
            raise ValueError(f"bad VLQ character {ch!r}") from None
        value += (digit & 31) << shift
        if digit & 32:
            shift += 5
            continue
        values.append(-(value >> 1) if value & 1 else value >> 1)
        value = shift = 0
    if shift:
        raise ValueError("truncated VLQ value")
    return tuple(values)


_PREFIXES = re.compile(r"^(?:webpack://[^/]*/|webpack:///|turbopack:///(?:\[project\]/)?|vite://|file:///?|"
                       r"rollup://|ng://|/@fs/)")


def clean_path(path: str) -> str:
    """webpack://my-app/./src/x.ts -> src/x.ts"""
    path = _PREFIXES.sub("", path.replace("\\", "/"))
    path = re.sub(r"\?[^/]*$", "", path)               # ?vue&type=script ...
    while path.startswith(("./", "../")):
        path = path.split("/", 1)[1]
    return path.lstrip("/") or "(unnamed)"


def is_library(path: str) -> bool:
    p = path.lower()
    return ("node_modules/" in p or p.startswith(("(webpack)", "webpack/", "external ", "vite/", "\0", "ignored|"))
            or "/.pnpm/" in p or "/.yarn/" in p or p.startswith("~/"))


@dataclass
class Source:
    path: str
    content: str | None
    library: bool


@dataclass
class SourceMap:
    sources: list[Source]
    mappings: str = ""
    sections: list[tuple[int, int, "SourceMap"]] = field(default_factory=list)   # (line, column, map)

    @property
    def has_content(self) -> bool:
        return any(s.content for s in self.all_sources())

    def all_sources(self) -> list[Source]:
        if self.sections:
            return [s for _, _, m in self.sections for s in m.all_sources()]
        return self.sources

    def lookup(self, positions: list[tuple[int, int]]) -> dict[tuple[int, int], tuple[Source, int, int]]:
        """0-based (line, column) in the bundle -> (original source, 1-based line, 1-based column)."""
        if self.sections:
            out = {}
            for i, (line, col, sub) in enumerate(self.sections):
                nxt = self.sections[i + 1][:2] if i + 1 < len(self.sections) else (1 << 60, 0)
                mine = [p for p in positions if (line, col) <= p < nxt]
                rel = {(p[0] - line, p[1] - (col if p[0] == line else 0)): p for p in mine}
                for r, hit in sub.lookup(list(rel)).items():
                    out[rel[r]] = hit
            return out
        return _lookup(self, positions)


def _lookup(sm: SourceMap, positions):
    wanted: dict[int, list[int]] = {}
    for line, col in positions:
        wanted.setdefault(line, []).append(col)
    out = {}
    if not wanted:
        return out
    last_line = max(wanted)
    src = oline = ocol = name = 0
    for gline, text in enumerate(sm.mappings.split(";")):
        if gline > last_line:
            break
        gcol, segments = 0, []
        for seg in text.split(","):
            if not seg:
                continue
            v = vlq_decode(seg)
            gcol += v[0]
            if len(v) >= 4:
                src, oline, ocol = src + v[1], oline + v[2], ocol + v[3]
                if len(v) >= 5:
                    name += v[4]
                segments.append((gcol, src, oline, ocol))
            else:
                segments.append((gcol, -1, 0, 0))       # a one-field segment: the code from here is unmapped
        if gline in wanted and segments:
            cols = [s[0] for s in segments]               # in column order: binary search
            for col in wanted[gline]:
                i = bisect.bisect_right(cols, col) - 1
                if i >= 0 and 0 <= segments[i][1] < len(sm.sources):
                    best = segments[i]
                    out[(gline, col)] = (sm.sources[best[1]], best[2] + 1, best[3] + 1)
    return out


def parse(text: str) -> SourceMap:
    """A JSON source map (plain or indexed). Raises ValueError when it is not one."""
    try:
        data = json.loads(text.lstrip(")]}'\n"))        # some servers prefix maps with an XSSI guard
    except json.JSONDecodeError as e:
        raise ValueError(f"not JSON: {e.msg}") from None
    if not isinstance(data, dict):
        raise ValueError("not a source map object")
    if isinstance(data.get("sections"), list):
        sections = []
        for s in data["sections"]:
            if isinstance(s, dict) and isinstance(s.get("map"), dict):
                off = s.get("offset") or {}
                sections.append((int(off.get("line", 0)), int(off.get("column", 0)), parse(json.dumps(s["map"]))))
        return SourceMap([], sections=sections)
    sources = data.get("sources")
    if not isinstance(sources, list) or not isinstance(data.get("mappings", ""), str):
        raise ValueError("no sources / mappings")
    root = data.get("sourceRoot") or ""
    contents = data.get("sourcesContent") or []
    out = []
    for i, s in enumerate(sources):
        path = clean_path((root.rstrip("/") + "/" if root else "") + (s or ""))
        content = contents[i] if i < len(contents) and isinstance(contents[i], str) else None
        out.append(Source(path, content, is_library(path)))
    return SourceMap(out, data.get("mappings", ""))


_INLINE = re.compile(r"^data:application/json(?:;charset=[\w-]+)?;base64,([A-Za-z0-9+/=]+)$")


def inline_map(url: str) -> str | None:
    """The JSON of a data: URI source map, or None."""
    m = _INLINE.match(url.strip())
    if not m:
        return None
    try:
        return base64.b64decode(m.group(1)).decode("utf-8")
    except (binascii.Error, UnicodeDecodeError):
        return None


_MAP_COMMENT = re.compile(r"(?://[#@]|/\*[#@])\s*sourceMappingURL=([^\s'\"*]+)")


def map_reference(js: str) -> str | None:
    """The last sourceMappingURL comment in a script (the spec says the last one wins)."""
    tail = js[-4096:] if len(js) > 4096 else js
    found = _MAP_COMMENT.findall(tail) or _MAP_COMMENT.findall(js)
    return found[-1] if found else None
