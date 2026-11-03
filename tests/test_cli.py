"""The command line: output formats, exit codes, redaction."""

import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path

import fakes as F
from bundleleak import __version__
from bundleleak.cli import main


def run(*argv):
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        code = main([str(a) for a in argv])
    return code, out.getvalue(), err.getvalue()


class Cli(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        self.key = F.stripe()
        (self.root / "dist").mkdir()
        (self.root / "dist" / "app.js").write_text(f'const k="{self.key}";fetch("http://10.1.2.3/x")', encoding="utf-8")
        (self.root / "clean").mkdir()
        (self.root / "clean" / "app.js").write_text('console.log("hi")', encoding="utf-8")

    def test_text_report_is_redacted(self):
        code, out, _ = run(self.root / "dist", "--no-color")
        self.assertEqual(code, 1)
        self.assertIn(f"bundle-leak v{__version__}", out)
        self.assertIn("CRITICAL", out)
        self.assertIn("app.js:1:10", out)
        self.assertNotIn(self.key, out)
        self.assertIn(self.key[:12], out)

    def test_show_secrets(self):
        _, out, _ = run(self.root / "dist", "--no-color", "--show-secrets")
        self.assertIn(self.key, out)

    def test_exit_codes(self):
        self.assertEqual(run(self.root / "clean")[0], 0)
        self.assertEqual(run(self.root / "dist", "--fail-on", "critical")[0], 1)
        low_only = self.root / "low"
        low_only.mkdir()
        (low_only / "a.js").write_text('fetch("http://10.1.2.3/x")', encoding="utf-8")
        self.assertEqual(run(low_only)[0], 0)                       # low is below the default --fail-on high
        self.assertEqual(run(low_only, "--fail-on", "low")[0], 1)
        self.assertEqual(run(self.root / "missing")[0], 2)
        self.assertEqual(run("ftp://example.com")[0], 2)
        self.assertEqual(run(self.root / "dist", "--header", "no-colon")[0], 2)

    def test_min_severity(self):
        _, out, _ = run(self.root / "dist", "--no-color", "--min-severity", "critical")
        self.assertNotIn("Internal hostnames", out)
        self.assertIn("1 critical", out)                            # the summary still counts everything

    def test_json(self):
        code, out, _ = run(self.root / "dist", "--json")
        data = json.loads(out)
        self.assertEqual(code, 1)
        self.assertEqual(data["mode"], "dir")
        self.assertEqual({f["rule"] for f in data["findings"]}, {"stripe-secret-key", "internal-host"})
        self.assertNotIn(self.key, out)

    def test_sarif(self):
        sarif = self.root / "out.sarif"
        run(self.root / "dist", "--sarif", sarif, "--no-color")
        data = json.loads(sarif.read_text(encoding="utf-8"))
        self.assertEqual(data["version"], "2.1.0")
        results = data["runs"][0]["results"]
        hit = next(r for r in results if r["ruleId"] == "stripe-secret-key")
        self.assertEqual(hit["level"], "error")
        self.assertEqual(hit["locations"][0]["physicalLocation"]["artifactLocation"]["uri"], "app.js")
        self.assertEqual(hit["locations"][0]["physicalLocation"]["region"], {"startLine": 1, "startColumn": 10})
        self.assertNotIn(self.key, sarif.read_text(encoding="utf-8"))

    def test_several_targets(self):
        _, out, _ = run(self.root / "dist", self.root / "clean", "--json")
        self.assertEqual(len(json.loads(out)), 2)


if __name__ == "__main__":
    unittest.main()
