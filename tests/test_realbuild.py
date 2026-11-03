"""A real production build: esbuild bundles, splits, minifies and writes source maps; bundle-leak must find
the keys in its output and trace them back to the original files. Runs when esbuild is available (CI
installs it: set ESBUILD to its path, or put it on PATH); skipped otherwise."""

import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

import fakes as F
from webfixture import Site
from bundleleak.scan import Scanner

ESBUILD = os.environ.get("ESBUILD") or shutil.which("esbuild")


@unittest.skipUnless(ESBUILD, "esbuild not installed")
class RealBuild(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        root = Path(cls.tmp.name)
        src, cls.dist = root / "src", root / "dist"
        src.mkdir()
        cls.service, cls.stripe = F.supabase_jwt("service_role"), F.stripe()
        (src / "main.js").write_text(
            'import { createClient } from "./db.js";\n'
            'export const client = createClient("https://x.supabase.co", import.meta.env.VITE_SUPABASE_SERVICE_ROLE_KEY);\n'
            'export const loadAdmin = () => import("./admin.js");\n', encoding="utf-8")
        (src / "db.js").write_text('export function createClient(url, key) {\n'
                                   '  return { url, key, ping: () => fetch(url + "/rest/v1/") };\n}\n', encoding="utf-8")
        (src / "admin.js").write_text(f'export const stripeKey = "{cls.stripe}";\n'
                                      'export function charge() { return fetch("/api/admin/charge", '
                                      '{ headers: { Authorization: stripeKey } }); }\n', encoding="utf-8")
        subprocess.run([ESBUILD, str(src / "main.js"), "--bundle", "--minify", "--sourcemap", "--splitting",
                        "--format=esm", f"--outdir={cls.dist}", "--entry-names=[name]-[hash]",
                        f'--define:import.meta.env.VITE_SUPABASE_SERVICE_ROLE_KEY="{cls.service}"'],
                       check=True, capture_output=True)
        entry = next(p.name for p in cls.dist.glob("main-*.js"))
        (cls.dist / "index.html").write_text(f'<!doctype html><script type="module" src="/{entry}"></script>',
                                             encoding="utf-8")

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def check(self, report):
        by_rule = {f.rule: f for f in report.findings}
        self.assertEqual(by_rule["stripe-secret-key"].severity, "critical")
        self.assertEqual(by_rule["jwt"].title, "Supabase service_role key")
        stripe_mapped = [loc.mapped for loc in by_rule["stripe-secret-key"].locations if loc.mapped]
        self.assertTrue(any(m.startswith("src/admin.js:1:") for m in stripe_mapped), stripe_mapped)
        jwt_mapped = [loc.mapped for loc in by_rule["jwt"].locations if loc.mapped]
        self.assertTrue(any(m.startswith("src/main.js:2:") for m in jwt_mapped), jwt_mapped)
        self.assertIn("source-map-exposed", by_rule)
        self.assertIn("/api/admin/charge", report.api_paths)

    def test_build_folder(self):
        self.check(Scanner().scan_dir(self.dist))

    def test_served_like_production(self):
        routes = {"/" + p.relative_to(self.dist).as_posix(): p.read_text(encoding="utf-8")
                  for p in self.dist.rglob("*") if p.is_file()}
        routes["/"] = routes.pop("/index.html")
        site = Site(routes, spa_fallback=False)
        self.addCleanup(site.close)
        report = Scanner().scan_url(site.url + "/")
        self.check(report)
        self.assertTrue(any("admin-" in a[0] for a in report.assets), "the lazy chunk was discovered")


if __name__ == "__main__":
    unittest.main()
