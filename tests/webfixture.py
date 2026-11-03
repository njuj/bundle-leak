"""Test fixtures: real source-map encoding, and a local web server that behaves like production hosting."""

import gzip
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

B64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"


def vlq(n: int) -> str:
    v = ((-n) << 1) | 1 if n < 0 else n << 1
    out = ""
    while True:
        digit, v = v & 31, v >> 5
        out += B64[digit | (32 if v else 0)]
        if not v:
            return out


def mappings(lines) -> str:
    """lines[i] = [(generated column, source index, original line, original column), ...] (0-based, absolute)."""
    src = oline = ocol = 0
    out = []
    for segments in lines:
        gcol, parts = 0, []
        for seg in segments:
            if len(seg) == 1:
                parts.append(vlq(seg[0] - gcol))
                gcol = seg[0]
                continue
            g, s, line, col = seg
            parts.append(vlq(g - gcol) + vlq(s - src) + vlq(line - oline) + vlq(col - ocol))
            gcol, src, oline, ocol = g, s, line, col
        out.append(",".join(parts))
    return ";".join(out)


def source_map(file, sources, contents, lines) -> str:
    return json.dumps({"version": 3, "file": file, "sources": sources, "sourcesContent": contents, "names": [],
                       "mappings": mappings(lines)})


class Site:
    """routes: {path: body | (status, headers, body)}. Unknown paths answer like an SPA host: 200 + index.html."""

    def __init__(self, routes: dict, spa_fallback: bool = True):
        self.routes, self.spa_fallback = routes, spa_fallback
        self.requests: list[tuple[str, str]] = []          # (path, user agent)
        site = self

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                site.requests.append((self.path, self.headers.get("User-Agent", "")))
                route = site.routes.get(self.path)
                if route is None and site.spa_fallback:
                    route = (200, {"Content-Type": "text/html"}, site.routes.get("/", ""))
                if route is None:
                    route = (404, {}, "not found")
                if not isinstance(route, tuple):
                    ctype = "text/html" if self.path.endswith("/") or self.path.endswith(".html") else \
                        "application/json" if self.path.endswith(".map") else "application/javascript"
                    route = (200, {"Content-Type": ctype}, route)
                status, headers, body = route
                data = body.encode() if isinstance(body, str) else body
                if headers.get("Content-Encoding") == "gzip":
                    data = gzip.compress(data)
                self.send_response(status)
                for k, v in headers.items():
                    self.send_header(k, v)
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def log_message(self, *args):
                pass

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.port = self.server.server_address[1]
        self.url = f"http://127.0.0.1:{self.port}"
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def close(self):
        self.server.shutdown()
        self.server.server_close()

    def paths(self) -> list[str]:
        return [p for p, _ in self.requests]
