"""Write the build output of a typical AI-built app, with the mistakes such apps tend to ship, to
examples/demo-dist/ (or the folder given). Every key is fake, generated here at run time: the repository
itself contains no secret-shaped string.

    python examples/make_demo.py
    bundle-leak examples/demo-dist
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "tests"))
import fakes as F  # noqa: E402
from webfixture import source_map  # noqa: E402


def main(out: Path) -> None:
    ref = "qwhxkzlpmyrtvbnsdfga"
    service = F.jwt({"iss": "supa" + "base", "ref": ref, "role": "service_role", "iat": 1735689600, "exp": 2051222400})
    openai = F.openai()
    lib = (f"import {{ createClient }} from '@supabase/supabase-js'\n\n"
           f"// TODO: move this to the server before launch\n"
           f"export const supabase = createClient('https://{ref}.supabase.co',\n"
           f"  '{service}')\n")
    entry = (f'const e={{BASE_URL:"/",MODE:"production",DEV:!1,PROD:!0,VITE_SUPABASE_URL:"https://{ref}.supabase.co",'
             f'VITE_OPENAI_API_KEY:"{openai}"}};'
             f'const s=Ft("https://{ref}.supabase.co","{service}");'
             f'fetch("/api/admin/users");fetch("http://10.0.4.12:8080/internal/metrics");'
             f'\n//# sourceMappingURL=index-Bq3xK9.js.map\n')
    env_col, key_col = entry.index("VITE_OPENAI_API_KEY") - 1, entry.index(service) - 1
    smap = source_map("index-Bq3xK9.js", ["../../src/lib/supabase.ts", "../../src/config.ts"],
                      [lib, "export const env = import.meta.env\n"],
                      [[(0, 1, 0, 0), (env_col, 1, 0, 13), (key_col, 0, 4, 2)]])
    files = {
        "index.html": '<!doctype html><html><head><script type="module" src="/assets/index-Bq3xK9.js"></script>'
                      '</head><body><div id="root"></div></body></html>\n',
        "assets/index-Bq3xK9.js": entry,
        "assets/index-Bq3xK9.js.map": smap,
    }
    for rel, text in files.items():
        path = out / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8", newline="")
    print(out)


if __name__ == "__main__":
    main(Path(sys.argv[1]) if len(sys.argv) > 1 else Path(__file__).resolve().parent / "demo-dist")
