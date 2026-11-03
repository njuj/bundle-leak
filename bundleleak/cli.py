"""Command-line entry point. Exit codes: 0 nothing at or above --fail-on · 1 findings · 2 could not scan."""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

from . import __version__
from .detectors import RANK, SEVERITIES
from .scan import Location, Report, Scanner, short

ICON = {"critical": "✖", "high": "✖", "medium": "⚠", "low": "•", "info": "·"}
ICON_ASCII = {"critical": "X", "high": "X", "medium": "!", "low": "*", "info": "-"}
COLOR = {"critical": "1;31", "high": "31", "medium": "33", "low": "36", "info": "2"}


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(
        prog="bundle-leak",
        description="Find what a web app ships to every visitor that it should not: secret keys, public env vars "
                    "with secret names, exposed source maps, internal hosts. Scans a live site (only the files a "
                    "browser downloads) or a build folder before you deploy it.")
    ap.add_argument("targets", nargs="+", metavar="URL|DIR", help="a page URL, or a build output folder (dist/, .next/, build/)")
    ap.add_argument("--json", action="store_true", help="machine-readable report")
    ap.add_argument("--sarif", type=Path, metavar="FILE", help="also write SARIF 2.1.0 (GitHub code scanning)")
    ap.add_argument("--fail-on", choices=SEVERITIES, default="high",
                    help="exit 1 when a finding is at least this severe (default: high)")
    ap.add_argument("--min-severity", choices=SEVERITIES, default="info", help="hide findings below this")
    ap.add_argument("--show-secrets", action="store_true", help="print secrets in full (default: redacted)")
    ap.add_argument("--include-libraries", action="store_true",
                    help="also report hits that a source map attributes to node_modules")
    web = ap.add_argument_group("live sites")
    web.add_argument("--scope", choices=["site", "host", "any"], default="site",
                     help="which hosts may be fetched: the same site (default), the exact host, or any")
    web.add_argument("--max-requests", type=int, default=400, metavar="N", help="request budget (default: 400)")
    web.add_argument("--no-map-probe", action="store_true",
                     help="only fetch source maps the bundles declare (default: also try <bundle>.map)")
    web.add_argument("--header", action="append", default=[], metavar="'Name: value'",
                     help="extra request header, e.g. a cookie for a staging site you own (repeatable)")
    web.add_argument("--timeout", type=float, default=15.0, metavar="SECONDS")
    web.add_argument("--concurrency", type=int, default=4, metavar="N")
    ap.add_argument("--no-color", action="store_true", help="disable ANSI colours")
    ap.add_argument("-V", "--version", action="version", version=f"%(prog)s {__version__}")
    return ap


def _glyphs(stream) -> tuple[dict, str, str]:
    try:
        "✖⚠•·└→".encode(getattr(stream, "encoding", None) or "ascii")
        return ICON, "└", "→"
    except (UnicodeEncodeError, LookupError):
        return ICON_ASCII, "`-", "->"


def _where(loc: Location, target: str, arrow: str) -> str:
    asset = short(loc.asset, target)
    if loc.source:
        return f"{loc.source}:{loc.line}:{loc.column}  (inside {asset})"
    if loc.line == 1 and loc.column == 1 and not loc.mapped:
        return asset
    out = f"{asset}:{loc.line}:{loc.column}"
    return out + (f"  {arrow}  {loc.mapped}" if loc.mapped else "")


def render(reports: list[Report], min_sev: str, color: bool, stream) -> str:
    icons, fix, arrow = _glyphs(stream)

    def paint(text, code):
        return f"\033[{code}m{text}\033[0m" if color else text

    out = []
    for r in reports:
        kb = r.bytes / 1024
        size = f"{kb / 1024:.1f} MB" if kb >= 1024 else f"{kb:.0f} KB"
        maps = f"  ·  {len(r.maps)} source map(s)" if r.maps else ""
        net = f"  ·  {r.requests} request(s)" if r.mode == "url" else ""
        out += [paint(f" bundle-leak v{__version__}", "1;36") +
                paint(f"  ·  {r.target}  ·  {len(r.assets)} file(s), {size}{maps}{net}  ·  {r.elapsed:.1f}s", "2"), ""]
        shown = [f for f in r.findings if RANK[f.severity] <= RANK[min_sev]]
        if shown:
            out.append(paint(" FINDINGS", "1"))
            for f in shown:
                sev = f.severity.upper()
                out.append(f"  {paint(icons[f.severity] + ' ' + sev.ljust(8), COLOR[f.severity])} {f.title}")
                out.append(f"             {fix} {_where(f.locations[0], r.target, arrow)}")
                for loc in f.locations[1:3]:
                    out.append(f"               {_where(loc, r.target, arrow)}")
                if len(f.locations) > 3:
                    out.append(paint(f"               … and {len(f.locations) - 3} more place(s)", "2"))
                out.append(f"               {f.evidence}" + (paint(f"   {f.detail}", "2") if f.detail else ""))
                if RANK[f.severity] <= RANK["medium"]:
                    out.append(paint(f"               {f.advice}", "2"))
            out.append("")
        else:
            out += [paint(" no findings", "32"), ""]
        if r.env:
            out.append(paint(" PUBLIC ENV VARIABLES (in the bundle)", "1"))
            for name in sorted(r.env)[:40]:
                value = r.env[name]
                out.append(f"   {name}" + ("" if value is None else paint("  (value inlined)", "2")))
            out.append("")
        services = {h: v for h, v in r.hosts.items() if v["service"]}
        if services or r.api_paths:
            out.append(paint(" ATTACK SURFACE", "1"))
            for h, v in sorted(services.items())[:15]:
                out.append(f"   {v['service']:<28} {h}")
            for path, n in r.api_paths.most_common(12):
                out.append(f"   {'API route':<28} {path}" + (paint(f"  ×{n}", "2") if n > 1 else ""))
            out.append("")
        if r.third_party:
            out.append(paint(f" THIRD-PARTY SCRIPTS (not fetched: out of scope)", "1"))
            out += [f"   {u}" for u in r.third_party[:10]]
            if len(r.third_party) > 10:
                out.append(paint(f"   … and {len(r.third_party) - 10} more", "2"))
            out.append("")
        notes = []
        if r.suppressed_library_hits:
            notes.append(f"{r.suppressed_library_hits} hit(s) inside node_modules code hidden (--include-libraries)")
        if r.budget_hit:
            notes.append("request budget reached: raise --max-requests for a complete scan")
        notes += r.errors[:5]
        for n in notes:
            out.append(paint(f" note: {n}", "2"))
        counts = {s: sum(1 for f in r.findings if f.severity == s) for s in SEVERITIES}
        summary = "  ·  ".join(f"{n} {s}" for s, n in counts.items() if n) or "clean"
        if out[-1]:
            out.append("")
        out += [paint(f" {summary}", "1"), ""]
    return "\n".join(out).rstrip() + "\n"


def to_json(r: Report) -> dict:
    return {
        "version": __version__, "target": r.target, "mode": r.mode, "elapsed": round(r.elapsed, 3),
        "requests": r.requests, "budget_hit": r.budget_hit,
        "assets": [{"where": w, "kind": k, "bytes": b} for w, k, b in r.assets],
        "findings": [{"rule": f.rule, "severity": f.severity, "title": f.title, "evidence": f.evidence,
                      "detail": f.detail, "advice": f.advice,
                      "locations": [vars(loc) for loc in f.locations]} for f in r.findings],
        "env": r.env, "source_maps": [vars(m) for m in r.maps],
        "hosts": r.hosts, "api_paths": dict(r.api_paths.most_common()), "third_party": r.third_party,
        "suppressed_library_hits": r.suppressed_library_hits, "errors": r.errors,
    }


def to_sarif(reports: list[Report]) -> dict:
    level = {"critical": "error", "high": "error", "medium": "warning", "low": "note", "info": "note"}
    rules, results = {}, []
    for r in reports:
        for f in r.findings:
            rules.setdefault(f.rule, {"id": f.rule, "name": f.rule, "shortDescription": {"text": f.title},
                                      "help": {"text": f.advice}})
            for loc in f.locations:
                region = {"startLine": loc.line, "startColumn": loc.column}
                results.append({
                    "ruleId": f.rule, "level": level[f.severity],
                    "message": {"text": f"{f.title}: {f.evidence}" + (f" ({f.detail})" if f.detail else "")},
                    "properties": {"severity": f.severity},
                    "locations": [{"physicalLocation": {
                        "artifactLocation": {"uri": (loc.source if loc.source else loc.asset)},
                        "region": region}}]})
    return {"$schema": "https://json.schemastore.org/sarif-2.1.0.json", "version": "2.1.0",
            "runs": [{"tool": {"driver": {"name": "bundle-leak", "version": __version__,
                                          "informationUri": "https://github.com/njuj/bundle-leak",
                                          "rules": list(rules.values())}},
                      "results": results}]}


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    headers = {}
    for h in args.header:
        name, sep, value = h.partition(":")
        if not sep or not name.strip():
            print(f"bundle-leak: --header needs 'Name: value', got {h!r}", file=sys.stderr)
            return 2
        headers[name.strip()] = value.strip()
    reports = []
    for target in args.targets:
        scanner = Scanner(show_secrets=args.show_secrets, include_libraries=args.include_libraries)
        if target.startswith(("http://", "https://")):
            report = scanner.scan_url(target, scope=args.scope, max_requests=max(1, args.max_requests),
                                      probe_maps=not args.no_map_probe, concurrency=args.concurrency,
                                      timeout=args.timeout, headers=headers)
            if not report.assets:
                print(f"bundle-leak: could not fetch {target}: {'; '.join(report.errors) or 'nothing found'}",
                      file=sys.stderr)
                return 2
        elif Path(target).is_dir():
            report = scanner.scan_dir(Path(target))
        else:
            print(f"bundle-leak: {target} is neither an http(s) URL nor a folder", file=sys.stderr)
            return 2
        reports.append(report)
    if args.sarif:
        args.sarif.write_text(json.dumps(to_sarif(reports), indent=2), encoding="utf-8")
    if args.json:
        data = [to_json(r) for r in reports]
        print(json.dumps(data[0] if len(data) == 1 else data, indent=2))   # ASCII: valid in any console encoding
    else:
        if hasattr(sys.stdout, "reconfigure"):
            sys.stdout.reconfigure(errors="replace")
        color = not args.no_color and "NO_COLOR" not in os.environ and sys.stdout.isatty()
        sys.stdout.write(render(reports, args.min_severity, color, sys.stdout))
    worst = min((RANK[f.severity] for r in reports for f in r.findings), default=99)
    return 1 if worst <= RANK[args.fail_on] else 0
