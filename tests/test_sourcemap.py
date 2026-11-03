"""Source Map v3 decoding: VLQ, lookups, indexed maps, inline maps, paths."""

import base64
import json
import unittest

from webfixture import mappings, source_map, vlq
from bundleleak import sourcemap as S


class Vlq(unittest.TestCase):
    def test_known_values(self):
        self.assertEqual(S.vlq_decode("A"), (0,))
        self.assertEqual(S.vlq_decode("C"), (1,))
        self.assertEqual(S.vlq_decode("D"), (-1,))
        self.assertEqual(S.vlq_decode("2H"), (123,))
        self.assertEqual(S.vlq_decode("AAgBC"), (0, 0, 16, 1))

    def test_round_trip(self):
        for n in (0, 1, -1, 15, 16, -16, 1023, -4096, 123456789):
            self.assertEqual(S.vlq_decode(vlq(n)), (n,))

    def test_garbage(self):
        for bad in ("!", "g", "AA$"):                 # a bad character, a value cut off mid-way
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                S.vlq_decode(bad)


class Lookup(unittest.TestCase):
    def setUp(self):
        # line 0: col 0 -> a.ts 0:0, col 10 -> b.ts 4:2, col 30 unmapped; line 1: col 5 -> a.ts 9:7
        self.sm = S.parse(source_map("out.js", ["src/a.ts", "src/b.ts"], ["a", "b"],
                                     [[(0, 0, 0, 0), (10, 1, 4, 2), (30,)], [(5, 0, 9, 7)]]))

    def test_positions(self):
        got = self.sm.lookup([(0, 0), (0, 9), (0, 10), (0, 25), (1, 6)])
        self.assertEqual({k: (v[0].path, v[1], v[2]) for k, v in got.items()},
                         {(0, 0): ("src/a.ts", 1, 1), (0, 9): ("src/a.ts", 1, 1), (0, 10): ("src/b.ts", 5, 3),
                          (0, 25): ("src/b.ts", 5, 3), (1, 6): ("src/a.ts", 10, 8)})

    def test_unmapped_ranges_stay_unmapped(self):
        self.assertEqual(self.sm.lookup([(0, 31), (1, 2), (7, 0)]), {})

    def test_indexed_map(self):
        inner = json.loads(source_map("x", ["src/second.ts"], [None], [[(0, 0, 2, 4)]]))
        first = json.loads(source_map("x", ["src/first.ts"], [None], [[(0, 0, 0, 0)]]))
        sm = S.parse(json.dumps({"version": 3, "sections": [{"offset": {"line": 0, "column": 0}, "map": first},
                                                            {"offset": {"line": 3, "column": 10}, "map": inner}]}))
        got = sm.lookup([(0, 5), (3, 12)])
        self.assertEqual((got[(0, 5)][0].path, got[(3, 12)][0].path, got[(3, 12)][1]), ("src/first.ts", "src/second.ts", 3))


class Parsing(unittest.TestCase):
    def test_paths_and_libraries(self):
        sm = S.parse(json.dumps({"version": 3, "sourceRoot": "", "mappings": "",
                                 "sources": ["webpack://app/./src/x.ts", "../../node_modules/react/index.js",
                                             "vite://src/App.vue?vue&type=script"],
                                 "sourcesContent": ["a", "b", None]}))
        self.assertEqual([(s.path, s.library, s.content) for s in sm.sources],
                         [("src/x.ts", False, "a"), ("node_modules/react/index.js", True, "b"),
                          ("src/App.vue", False, None)])

    def test_xssi_prefix_and_errors(self):
        self.assertEqual(S.parse(")]}'\n" + source_map("x", ["a.ts"], ["a"], [])).sources[0].path, "a.ts")
        for bad in ("not json", "[1, 2]", '{"version": 3}'):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                S.parse(bad)

    def test_inline_and_references(self):
        payload = source_map("x", ["a.ts"], ["a"], [])
        url = "data:application/json;charset=utf-8;base64," + base64.b64encode(payload.encode()).decode()
        self.assertEqual(S.inline_map(url), payload)
        self.assertIsNone(S.inline_map("app.js.map"))
        js = "var a=1;\n//# sourceMappingURL=old.js.map\nvar b=2;\n//# sourceMappingURL=app.js.map\n"
        self.assertEqual(S.map_reference(js), "app.js.map")           # the last one wins
        self.assertEqual(S.map_reference("a{}/*# sourceMappingURL=s.css.map */"), "s.css.map")
        self.assertIsNone(S.map_reference("var a=1"))

    def test_encoder_follows_the_spec(self):
        # only the generated column restarts on each line; the original column stays relative (5 -> 0 is -5, "L")
        self.assertEqual(mappings([[(0, 0, 0, 0), (5, 0, 0, 5)], [(0, 0, 1, 0)]]), "AAAA,KAAK;AACL")


if __name__ == "__main__":
    unittest.main()
