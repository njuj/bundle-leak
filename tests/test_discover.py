"""Finding every file of an app: page scripts and the chunks they load later."""

import unittest

from bundleleak.discover import chunks, page
from bundleleak.env import classify, find
from bundleleak.surface import api_paths, baas, host_kind, hosts

PAGE = "https://app.example.com/dashboard/"


class Page(unittest.TestCase):
    def test_scripts_preloads_and_inline(self):
        html = ('<html><head><base href="/"><script type="module" src="assets/index-A1.js"></script>'
                '<link rel="modulepreload" href="/assets/vendor-B2.js"><link rel="preload" as="script" href="/r.js">'
                '<link rel="stylesheet" href="/s.css"><script src="data:text/javascript,1"></script>'
                '<script>window.__ENV__={VITE_X:"1"}</script></head></html>')
        scripts, inline = page(html, PAGE)
        self.assertEqual(scripts, ["https://app.example.com/assets/index-A1.js",
                                   "https://app.example.com/assets/vendor-B2.js", "https://app.example.com/r.js"])
        self.assertEqual(inline, ['window.__ENV__={VITE_X:"1"}'])

    def test_broken_html_does_not_crash(self):
        self.assertEqual(page("<script src='/a.js'><div <<< </script", PAGE)[0], ["https://app.example.com/a.js"])


class Chunks(unittest.TestCase):
    def test_esm_imports_resolve_against_the_importing_script(self):
        js = 'import"./vendor-C.js";const A=()=>import("./Admin-D.js");new Worker("./w.js")'
        self.assertEqual(chunks(js, "https://app.example.com/assets/index.js", PAGE),
                         ["https://app.example.com/assets/vendor-C.js", "https://app.example.com/assets/Admin-D.js",
                          "https://app.example.com/assets/w.js"])

    def test_vite_dependency_lists_resolve_against_the_base(self):
        js = 'const __vite__mapDeps=(i,m=__vite__mapDeps,d=(m.f||(m.f=["assets/Settings-E.js","assets/x.css"])))'
        self.assertEqual(chunks(js, "https://app.example.com/assets/index.js", PAGE),
                         ["https://app.example.com/assets/Settings-E.js"])

    def test_next_build_manifest(self):
        js = 'self.__BUILD_MANIFEST={"/":["static/chunks/pages/index-9f8e.js"],"/admin":["static/chunks/pages/admin-77.js"]}'
        self.assertEqual(chunks(js, "https://app.example.com/_next/static/abc/_buildManifest.js", PAGE),
                         ["https://app.example.com/_next/static/chunks/pages/index-9f8e.js",
                          "https://app.example.com/_next/static/chunks/pages/admin-77.js"])

    def test_webpack_chunk_map(self):
        js = ('r.u=e=>"static/chunks/"+({12:"settings"}[e]||e)+"."+{12:"0a1b2c3d4e",77:"ffee001122"}[e]+".js";'
              'r.p="/_next/";')
        self.assertEqual(sorted(chunks(js, "https://app.example.com/_next/static/chunks/webpack-1.js", PAGE)),
                         ["https://app.example.com/_next/static/chunks/77.ffee001122.js",
                          "https://app.example.com/_next/static/chunks/settings.0a1b2c3d4e.js"])

    def test_create_react_app_public_path(self):
        js = 'n.p="/static-root/",n.u=e=>"static/js/"+e+"."+{5:"aa11bb22"}[e]+".chunk.js"'
        self.assertEqual(chunks(js, "https://app.example.com/static-root/static/js/main.js", PAGE),
                         ["https://app.example.com/static-root/static/js/5.aa11bb22.chunk.js"])

    def test_node_modules_and_protocol_relative_paths_are_ignored(self):
        self.assertEqual(chunks('"node_modules/x/y.js";"//cdn.example.org/z/q.js"', "https://a.example.com/x.js", PAGE), [])


class Env(unittest.TestCase):
    def test_env_objects_and_uses(self):
        js = ('{BASE_URL:"/",VITE_SUPABASE_URL:"https://x.supabase.co","NEXT_PUBLIC_STRIPE_SECRET_KEY":"abc",'
              'REACT_APP_FLAG:!0} if(import.meta.env.VITE_ADMIN_TOKEN){}')
        self.assertEqual([(v.name, v.value) for v in find(js)],
                         [("VITE_SUPABASE_URL", "https://x.supabase.co"), ("NEXT_PUBLIC_STRIPE_SECRET_KEY", "abc"),
                          ("REACT_APP_FLAG", "!0"), ("VITE_ADMIN_TOKEN", None)])

    def test_classify(self):
        self.assertEqual(classify("VITE_SUPABASE_SERVICE_ROLE_KEY"), "secret")
        self.assertEqual(classify("NEXT_PUBLIC_DATABASE_URL"), "secret")
        self.assertEqual(classify("VITE_OPENAI_API_KEY"), "key")
        self.assertIsNone(classify("NEXT_PUBLIC_STRIPE_PUBLISHABLE_KEY"))
        self.assertIsNone(classify("VITE_SUPABASE_ANON_KEY"))
        self.assertIsNone(classify("VITE_API_URL"))


class Surface(unittest.TestCase):
    def test_host_kinds(self):
        for host, kind in (("10.0.4.12", "internal"), ("db.corp", "internal"), ("api-staging.example.com", "non-production"),
                           ("dev.api.example.com", "non-production"), ("react.dev", None), ("dev.azure.com", None),
                           ("developer.mozilla.org", None), ("api.example.com", None), ("$1", None), ("_chats", None),
                           ("8.8.8.8", None)):
            with self.subTest(host=host):
                self.assertEqual(host_kind(host), kind)

    def test_services_urls_and_routes(self):
        self.assertEqual(baas("abcdefghijklmnopqrst.supabase.co"), "Supabase project")
        self.assertEqual(baas("my-bucket.s3.eu-west-1.amazonaws.com"), "Amazon S3")
        self.assertEqual([h for _, h in hosts('a("https://x.example.com/p");b("git+https://y.example.com");'
                                              'c("https://${host}/q")')], ["x.example.com"])
        self.assertEqual(api_paths('fetch("/api/admin/users");fetch(`/graphql`);"/about"'), ["/api/admin/users", "/graphql"])


if __name__ == "__main__":
    unittest.main()
