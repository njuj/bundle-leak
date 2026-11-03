"""End to end: a build folder, and live sites served from a local web server."""

import tempfile
import unittest
from pathlib import Path

import fakes as F
from webfixture import Site, source_map
from bundleleak.scan import Scanner


def rules(report):
    return {(f.rule, f.severity) for f in report.findings}


def vite_app(service: str, stripe: str, github: str) -> dict:
    """A Vite-style deploy: entry chunk with an env object and a declared map, a lazy chunk with a hidden map,
    a dependency-list chunk served gzipped, and a vendor chunk whose .map request gets the SPA's index.html."""
    entry = (f'const e={{VITE_SUPABASE_URL:"https://x.supabase.co",VITE_SUPABASE_SERVICE_ROLE_KEY:"{service}"}};'
             f'const A=()=>import("./Admin-C1.js");'
             f'const __vite__mapDeps=(i,m=__vite__mapDeps,d=(m.f||(m.f=["assets/Settings-D1.js"])));'
             f'fetch("/api/admin/users");\n//# sourceMappingURL=index-A1.js.map\n')
    original = f"import {{ createClient }} from '@supabase/supabase-js'\nexport const db = createClient(url,\n  '{service}')\n"
    col = entry.index(service) - 1                       # the quote before the key
    return {
        "/": '<!doctype html><script type="module" src="/assets/index-A1.js"></script>'
             '<link rel="modulepreload" href="/assets/vendor-B1.js">'
             '<script src="https://cdn.example.com/analytics.js"></script><script src="/go"></script>',
        "/assets/index-A1.js": entry,
        "/assets/index-A1.js.map": source_map("index-A1.js", ["../../src/lib/db.ts"], [original],
                                              [[(0, 0, 0, 0), (col, 0, 2, 2)]]),
        "/assets/Admin-C1.js": f'export const k="{stripe}";',
        "/assets/Admin-C1.js.map": source_map("Admin-C1.js", ["../../src/pages/Admin.tsx"], ["// admin page\n"], []),
        "/assets/Settings-D1.js": (200, {"Content-Type": "application/javascript", "Content-Encoding": "gzip"},
                                   f'const t="{github}";'),
        "/assets/vendor-B1.js": "export const v=1;",
    }


class Live(unittest.TestCase):
    def setUp(self):
        self.service, self.stripe, self.github = F.supabase_jwt("service_role"), F.stripe(), F.github()
        self.site = Site(vite_app(self.service, self.stripe, self.github))
        self.addCleanup(self.site.close)
        routes = self.site.routes
        routes["/go"] = (302, {"Location": f"http://localhost:{self.site.port}/assets/x.js"}, "")   # another host

    def test_vite_app(self):
        r = Scanner().scan_url(self.site.url + "/")
        self.assertTrue({("jwt", "critical"), ("public-env-secret", "high"), ("stripe-secret-key", "critical"),
                         ("github-token", "critical"), ("source-map-exposed", "medium")} <= rules(r), rules(r))
        jwt = next(f for f in r.findings if f.rule == "jwt")
        mapped = [loc.mapped for loc in jwt.locations if loc.mapped]
        self.assertIn("src/lib/db.ts:3:3", mapped)                       # bundle position -> original source
        self.assertNotIn(self.service, jwt.evidence)                      # redacted
        self.assertEqual(sorted(m.how for m in r.maps), ["declared", "hidden"])
        self.assertIn("/api/admin/users", r.api_paths)
        self.assertEqual(r.third_party, ["https://cdn.example.com/analytics.js"])

    def test_politeness(self):
        Scanner().scan_url(self.site.url + "/")
        paths = self.site.paths()
        self.assertTrue(all("bundle-leak/" in ua for _, ua in self.site.requests))
        self.assertEqual(len(paths), len(set(paths)), "no file is fetched twice")
        self.assertNotIn("/assets/x.js", paths)                           # the redirect left the site
        self.assertIn("/assets/vendor-B1.js.map", paths)                  # probed, got index.html, ignored

    def test_redirect_out_of_scope_is_reported_not_followed(self):
        r = Scanner().scan_url(self.site.url + "/")
        self.assertTrue(any("redirects out of scope" in e for e in r.errors), r.errors)

    def test_budget(self):
        r = Scanner().scan_url(self.site.url + "/", max_requests=2)
        self.assertTrue(r.budget_hit)
        self.assertEqual(r.requests, 2)

    def test_no_map_probe(self):
        r = Scanner().scan_url(self.site.url + "/", probe_maps=False)
        self.assertEqual([m.how for m in r.maps], ["declared"])
        self.assertNotIn("/assets/Admin-C1.js.map", self.site.paths())

    def test_unreachable(self):
        r = Scanner().scan_url("http://127.0.0.1:9/", timeout=2)
        self.assertEqual(r.assets, [])
        self.assertTrue(r.errors)


class NextApp(unittest.TestCase):
    def test_webpack_chunks_and_build_manifest(self):
        key = F.openai()
        site = Site({
            "/": '<script src="/_next/static/chunks/webpack-1.js"></script>'
                 '<script src="/_next/static/b1/_buildManifest.js"></script>',
            "/_next/static/chunks/webpack-1.js": 'r.u=e=>"static/chunks/"+e+"."+{42:"abcd1234ef"}[e]+".js";r.p="/_next/";',
            "/_next/static/b1/_buildManifest.js": 'self.__BUILD_MANIFEST={"/admin":["static/chunks/pages/admin-77.js"]}',
            "/_next/static/chunks/42.abcd1234ef.js": f'const o="{key}"',
            "/_next/static/chunks/pages/admin-77.js": 'fetch("/api/internal/stats")',
        }, spa_fallback=False)
        self.addCleanup(site.close)
        r = Scanner().scan_url(site.url + "/")
        self.assertIn(("openai-api-key", "critical"), rules(r))
        self.assertIn("/_next/static/chunks/pages/admin-77.js", site.paths())
        self.assertIn("/api/internal/stats", r.api_paths)


class BuildFolder(unittest.TestCase):
    def build(self, files: dict) -> Path:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        root = Path(tmp.name)
        for rel, text in files.items():
            path = root / rel
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(text, encoding="utf-8")
        return root

    def test_dist_folder(self):
        lib = F.github()
        root = self.build({
            "index.html": '<script src="/assets/app.js"></script>',
            "assets/app.js": f'const a="{F.stripe()}";const b="{lib}";',          # second key comes from a library
            "assets/app.js.map": source_map("app.js", ["../src/main.ts", "../node_modules/some-lib/index.js"],
                                            ["// main\n", None], [[(0, 0, 0, 0), (40, 1, 0, 0)]]),
            ".env.production": f"OPENAI_API_KEY={F.openai()}\n",
            "assets/orphan.js.map": source_map("orphan.js", ["../src/old.ts"], [f"const pw = '{F.password()}x9'\n"], []),
            "node_modules/x/index.js": f'const k="{F.npm()}"',                     # never scanned
        })
        r = Scanner().scan_dir(root)
        found = rules(r)
        self.assertIn(("stripe-secret-key", "critical"), found)
        self.assertIn(("env-file", "critical"), found)
        self.assertIn(("openai-api-key", "critical"), found)
        self.assertNotIn(("npm-token", "critical"), found)
        self.assertNotIn("github-token", {f.rule for f in r.findings})        # attributed to node_modules
        self.assertEqual(r.suppressed_library_hits, 1)
        self.assertEqual(sorted(m.how for m in r.maps), ["hidden", "unreferenced"])

    def test_include_libraries(self):
        root = self.build({"a.js": f'x="{F.stripe()}";y="{F.github()}"',
                           "a.js.map": source_map("a.js", ["../node_modules/l/i.js"], [None], [[(0, 0, 0, 0)]])})
        self.assertIn("github-token", {f.rule for f in Scanner(include_libraries=True).scan_dir(root).findings})

    def test_clean_build(self):
        root = self.build({"index.html": "<p>hi</p>", "assets/app.js": 'console.log("hello")'})
        self.assertEqual(Scanner().scan_dir(root).findings, [])

    def test_same_secret_twice_is_one_finding(self):
        key = F.stripe()
        root = self.build({"a.js": f'k="{key}"', "b.js": f'k="{key}"'})
        findings = Scanner().scan_dir(root).findings
        self.assertEqual(len(findings), 1)
        self.assertEqual(len(findings[0].locations), 2)


if __name__ == "__main__":
    unittest.main()
