"""Files a deploy should never serve: found by their content on a live site and in a build folder, and never
mistaken for an SPA's index.html or a soft 404."""

import io
import tempfile
import unittest
import zipfile
from pathlib import Path

import fakes as F
from webfixture import Site
from bundleleak import exposed
from bundleleak.cli import main  # noqa: F401
from bundleleak.scan import Scanner

INDEX = '<!doctype html><title>app</title><script type="module" src="/assets/app.js"></script>'


def rules(report):
    return {(f.rule, f.severity) for f in report.findings}


def zipped() -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("src/config.ts", "export const x = 1\n")
    return buf.getvalue()


class LiveSite(unittest.TestCase):
    def serve(self, routes, spa=True):
        site = Site({"/": INDEX, "/assets/app.js": "export const a=1;", **routes}, spa_fallback=spa)
        self.addCleanup(site.close)
        return site

    def test_env_git_and_backup_served_by_mistake(self):
        stripe = F.stripe()
        site = self.serve({
            "/.env": (200, {"Content-Type": "text/plain"},
                      f"# production\nDATABASE_URL=postgres://app@db.internal/app\nSTRIPE_SECRET_KEY={stripe}\n"
                      "export NODE_ENV=production\n"),
            "/.git/HEAD": (200, {"Content-Type": "text/plain"}, "ref: refs/heads/main\n"),
            "/.git/config": (200, {"Content-Type": "text/plain"},
                             "[core]\n\trepositoryformatversion = 0\n\tbare = false\n[remote \"origin\"]\n"),
            "/backup.zip": (200, {"Content-Type": "application/zip"}, zipped()),
        })
        r = Scanner().scan_url(site.url + "/")
        found = rules(r)
        self.assertTrue({("env-file-served", "critical"), ("stripe-secret-key", "critical"), ("git-exposed", "high"),
                         ("archive-served", "high")} <= found, found)
        env = next(f for f in r.findings if f.rule == "env-file-served")
        self.assertEqual(env.evidence, "DATABASE_URL, STRIPE_SECRET_KEY, NODE_ENV")
        self.assertNotIn(stripe, env.evidence)
        git = [f for f in r.findings if f.rule == "git-exposed"]
        self.assertEqual(len(git), 1)                                    # HEAD and config: one repository
        self.assertEqual(len(git[0].locations), 2)
        self.assertEqual(git[0].evidence, "ref: refs/heads/main")
        self.assertNotIn(("env-file-served", "critical"), {(f.rule, f.severity) for f in r.findings
                                                            if f.locations[0].asset.endswith(".env.local")})

    def test_spa_fallback_and_soft_404s_are_not_files(self):
        site = self.serve({})                                            # every unknown path: 200 + index.html
        r = Scanner().scan_url(site.url + "/")
        self.assertFalse({f.rule for f in r.findings} & {p.rule for p in exposed.PROBES})
        self.assertIn("/.env", site.paths())
        soft = self.serve({p: (200, {"Content-Type": "text/plain"}, "Not Found") for p in
                           ("/" + q.path for q in exposed.PROBES)}, spa=False)
        r = Scanner().scan_url(soft.url + "/")
        self.assertFalse({f.rule for f in r.findings} & {p.rule for p in exposed.PROBES})

    def test_app_in_a_subfolder_is_probed_there_too(self):
        site = self.serve({"/app/": INDEX, "/app/.env.production": (200, {}, "API_KEY=x1\nAPI_URL=https://x\n")})
        r = Scanner().scan_url(site.url + "/app/")
        self.assertIn(("env-file-served", "critical"), rules(r))
        self.assertIn("/.env", site.paths())

    def test_no_file_probe(self):
        site = self.serve({})
        Scanner().scan_url(site.url + "/", probe_files=False)
        self.assertFalse([p for p in site.paths() if p.startswith(("/.env", "/.git", "/backup"))])


class BuildFolder(unittest.TestCase):
    def test_git_folder_npmrc_and_compose_in_the_output(self):
        npm = F.npm()
        with tempfile.TemporaryDirectory() as d:
            dist = Path(d, "dist")
            (dist / ".git").mkdir(parents=True)
            (dist / ".git" / "HEAD").write_text("ref: refs/heads/main\n")
            (dist / ".npmrc").write_text(f"//registry.npmjs.org/:_authToken={npm}\n")
            (dist / "docker-compose.yml").write_text("services:\n  db:\n    image: postgres:16\n")
            (dist / "index.html").write_text(INDEX)
            r = Scanner().scan_dir(dist)
        found = rules(r)
        self.assertTrue({("git-exposed", "high"), ("npmrc-served", "critical"), ("npm-token", "critical"),
                         ("compose-served", "medium")} <= found, found)

    def test_content_checks(self):
        self.assertTrue(exposed.match(".env", b"A=1\n# c\nB = two\n"))
        self.assertFalse(exposed.match(".env", b"export default function(){return 1}\nconst a = 2;\n"))
        self.assertFalse(exposed.match(".env", b"<!DOCTYPE html><p>A=1</p>"))
        self.assertFalse(exposed.match(".env", b'{"A": "1"}'))
        self.assertTrue(exposed.match(".git/HEAD", b"0123456789abcdef0123456789abcdef01234567\n"))
        self.assertFalse(exposed.match(".git/HEAD", b"ref: see the docs\n"))
        self.assertTrue(exposed.match(".htpasswd", b"admin:$apr1$abc$def\n"))
        self.assertFalse(exposed.match(".htpasswd", b"hello world\n"))
        self.assertFalse(exposed.match(".DS_Store", b"\x00\x00\x00\x01Nope"))


if __name__ == "__main__":
    unittest.main()
