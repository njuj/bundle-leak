"""Public environment variables: the ones a framework copies into the bundle at build time.

NEXT_PUBLIC_*, VITE_*, REACT_APP_* and friends are inlined into the JavaScript every visitor downloads.
That is fine for a publishable key and a disaster for a secret someone gave the prefix "to make the
error go away", the classic AI-generated-app leak.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

PREFIXES = ("NEXT_PUBLIC_", "VITE_", "REACT_APP_", "NUXT_PUBLIC_", "EXPO_PUBLIC_", "GATSBY_", "VUE_APP_",
            "PUBLIC_", "STORYBOOK_", "SANITY_STUDIO_", "REDWOOD_ENV_")
_NAME = r"((?:" + "|".join(PREFIXES) + r")[A-Z0-9_]*[A-Z0-9])"
_VALUE = r"(\"(?:[^\"\\\n]|\\.){0,2000}\"|'(?:[^'\\\n]|\\.){0,2000}'|`[^`$\\]{0,2000}`|!?[01]|true|false|null|\d+)"

# {VITE_API_URL:"https://...", "NEXT_PUBLIC_X":"..."}: an env object that survived into the bundle
_PAIR = re.compile(r"(?<![\w$.])[\"']?" + _NAME + r"[\"']?\s*:\s*" + _VALUE)
# process.env.NEXT_PUBLIC_X / import.meta.env.VITE_X / process.env["X"]: a use in original source
_USE = re.compile(r"(?:process\.env|import\.meta\.env)(?:\.|\[\s*[\"'])" + _NAME)

# Names that say "secret". A public prefix in front of one of these is the leak, whatever the value.
_SECRET_NAME = re.compile(r"SECRET|PRIVATE|SERVICE_?ROLE|SERVICE_KEY|PASSWORD|PASSWD|_PWD\b|ADMIN_(?:KEY|TOKEN)|"
                          r"DATABASE_URL|DB_URL|DB_PASS|POSTGRES_|MONGO(?:DB)?_URI|SIGNING|ENCRYPTION_KEY|"
                          r"WEBHOOK_SECRET|_SK$|CLIENT_SECRET|ACCESS_KEY_SECRET|SECRET_ACCESS_KEY")
# Names that say "API key" without saying "public": worth a look, not an alarm
_KEY_NAME = re.compile(r"API_?KEY|_TOKEN$|ACCESS_KEY|AUTH_KEY|_KEY$")
_PUBLIC_NAME = re.compile(r"PUBLISHABLE|PUBLIC_KEY|ANON|SITE_KEY|CLIENT_ID|MEASUREMENT_ID|_DSN|RECAPTCHA|MAPS|"
                          r"FIREBASE_API_KEY|APP_ID|PROJECT_ID|SENTRY|POSTHOG|MIXPANEL|SEGMENT|AMPLITUDE|ALGOLIA_SEARCH")


@dataclass
class EnvVar:
    name: str
    value: str | None          # None when only the name was seen (a use in original source)
    start: int                 # offset of the occurrence in the scanned text


def classify(name: str) -> str | None:
    """'secret' / 'key' / None (looks public)."""
    bare = name
    for p in PREFIXES:
        if name.startswith(p):
            bare = name[len(p):]
            break
    if _PUBLIC_NAME.search(bare):
        return None
    if _SECRET_NAME.search(bare):
        return "secret"
    if _KEY_NAME.search(bare):
        return "key"
    return None


def _unquote(v: str) -> str:
    if v[:1] in "\"'`" and v[-1:] == v[:1]:
        return re.sub(r"\\(.)", r"\1", v[1:-1])
    return v


# literal anchors: the patterns above start with lookbehinds, which would make re test every position
_PREFIX = re.compile("|".join(PREFIXES))
_ENV_OBJECT = re.compile(r"process\.env|import\.meta\.env")


def find(text: str) -> list[EnvVar]:
    out, seen = [], set()
    for a in _PREFIX.finditer(text):                   # NAME: value pairs, anchored on the prefix
        m = _PAIR.search(text, max(0, a.start() - 1), min(len(text), a.end() + 2200))
        if m and m.start(1) == a.start():
            out.append(EnvVar(m.group(1), _unquote(m.group(2)), m.start(1)))
            seen.add(m.start(1))
    for a in _ENV_OBJECT.finditer(text):               # process.env.NAME uses
        m = _USE.match(text, a.start())
        if m and m.start(1) not in seen:
            out.append(EnvVar(m.group(1), None, m.start(1)))
    return out
