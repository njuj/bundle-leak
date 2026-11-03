"""What counts as a leak.

Every rule is narrow on purpose. A scanner that cries wolf on every minified bundle gets switched off,
so each one keys on a provider's documented token format, then a check throws out placeholders,
low-entropy strings and public-by-design keys. Severity follows what the key unlocks, not how scary
the name sounds: a Stripe publishable key is fine in a bundle, but a Supabase service_role key there
bypasses every Row Level Security policy.
"""

from __future__ import annotations

import base64
import binascii
import bisect
import json
import math
import re
from collections import Counter
from dataclasses import dataclass
from typing import Callable

SEVERITIES = ["critical", "high", "medium", "low", "info"]
RANK = {s: i for i, s in enumerate(SEVERITIES)}


@dataclass
class Hit:
    rule: str
    title: str
    severity: str
    start: int
    end: int
    secret: str                       # the sensitive part: shown redacted unless asked otherwise
    detail: str = ""                  # what we learned without revealing it (JWT claims, host, ...)
    advice: str = ""


@dataclass(frozen=True)
class Rule:
    id: str
    title: str
    severity: str
    pattern: re.Pattern
    advice: str
    group: int = 1
    # (match, text) -> None to drop the hit, or (severity, title, detail) to keep it
    check: Callable[[re.Match, str], tuple[str, str, str] | None] | None = None
    # A cheap literal anchor that every match contains. Python's re only searches fast for a pattern that
    # starts with a literal, and the token boundaries (lookbehinds) defeat that, so the full pattern only
    # runs in a window around anchor hits: from 45 characters before the anchor to `window` after it.
    prefilter: re.Pattern | None = None
    window: int = 260
    lowercase: bool = False          # run the prefilter on text.lower() (a case-insensitive anchor, fast)


# ── helpers ───────────────────────────────────────────────────────────────────

def entropy(s: str) -> float:
    if not s:
        return 0.0
    n = len(s)
    return -sum(c / n * math.log2(c / n) for c in Counter(s).values())


_FAKE_WORDS = ("xxxx", "your", "example", "sample", "dummy", "placeholder", "changeme", "redacted", "insert",
               "replace", "fake", "test1234", "<", ">", "${", "{{", "****", "....", "todo")


def looks_fake(value: str) -> bool:
    """Documentation keys, placeholders and templates: never a real leak."""
    low = value.lower()
    if any(w in low for w in _FAKE_WORDS):
        return True
    if re.search(r"(.)\1{7,}", value):                    # aaaaaaaa, 00000000
        return True
    return bool(re.search(r"(?:0123456789|123456789|abcdefghij|ABCDEFGHIJ)", value))


def redact(secret: str, keep: int = 4) -> str:
    """sk_live_51Hx…(99)…Qx9w: enough to recognise and rotate, not enough to use."""
    m = re.match(r"[a-z]{2,8}[_-](?:[a-z]{2,8}[_-])?", secret)
    prefix = m.group(0) if m else ""
    head = min(len(prefix) + keep, len(secret) // 3)
    if len(secret) <= 12:
        return secret[:2] + "…" + f"({len(secret)})"
    return f"{secret[:head]}…({len(secret)})…{secret[-keep:]}"


def jwt_claims(token: str) -> dict | None:
    try:
        payload = token.split(".")[1]
        data = base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4))
        claims = json.loads(data)
        return claims if isinstance(claims, dict) else None
    except (IndexError, ValueError, binascii.Error, UnicodeDecodeError):
        return None


def _near(text: str, m: re.Match, pattern: str, radius: int = 600) -> re.Match | None:
    return re.search(pattern, text[max(0, m.start() - radius):m.end() + radius])


def _real(severity, title, detail=""):
    def check(m, text):
        return None if looks_fake(m.group(1)) else (severity, title, detail)
    return check


# ── provider-specific checks ──────────────────────────────────────────────────

_AWS_SECRET = r"(?<![A-Za-z0-9/+])[A-Za-z0-9/+]{40}(?![A-Za-z0-9/+=])"


def _aws(m, text):
    key = m.group(1)
    if looks_fake(key):
        return None
    temporary = key.startswith("ASIA")
    for s in re.finditer(_AWS_SECRET, text[max(0, m.start() - 400):m.end() + 400]):
        v = s.group(0)
        if entropy(v) > 4.0 and re.search(r"[a-z]", v) and re.search(r"[A-Z]", v) and re.search(r"\d", v) \
                and not looks_fake(v):
            return ("high" if temporary else "critical", "AWS access key pair (id and secret)",
                    "a session token is also needed (temporary ASIA key)" if temporary else
                    "the secret access key sits next to the id")
    return ("medium", "AWS access key id", "no secret next to it; the pair usually travels together")


def _stripe(m, text):
    key = m.group(1)
    if looks_fake(key):
        return None
    restricted, live = key.startswith("rk_"), "_live_" in key
    if not live:
        return ("medium", "Test-mode secret API key (Stripe / Clerk format)", "test mode: no real money moves")
    return ("high" if restricted else "critical",
            "Live restricted API key (Stripe format)" if restricted else "Live secret API key (Stripe / Clerk format)",
            "")


def _google(m, text):
    if looks_fake(m.group(1)):
        return None
    if _near(text, m, r"authDomain|projectId|firebaseapp\.com|messagingSenderId|storageBucket"):
        return ("info", "Firebase web config", "public by design: what protects the data are the security rules")
    return ("medium", "Google API key", "")


def _jwt(m, text):
    claims = jwt_claims(m.group(1))
    if claims is None:
        return None
    role = str(claims.get("role", "")).lower()
    iss, ref = str(claims.get("iss", "")), claims.get("ref")
    shown = " · ".join(f"{k}={claims[k]}" for k in ("role", "ref", "iss") if k in claims)
    if role == "service_role":
        return ("critical", "Supabase service_role key", shown)
    if role == "anon" and ("supabase" in iss or ref):
        return ("info", "Supabase anon key", shown + " (public by design; Row Level Security must be on)")
    if role in ("admin", "superuser", "root") or claims.get("admin") is True or claims.get("is_admin") is True:
        return ("high", "JWT that grants admin rights", shown or "admin=true")
    return ("low", "Signed JWT embedded in the bundle", shown or ", ".join(sorted(claims)[:6]))


_KEY_KINDS = {"RSA": "RSA", "EC": "EC", "DSA": "DSA", "OPENSSH": "OpenSSH", "PGP": "PGP", "ENCRYPTED": "Encrypted"}


def _private_key(m, text):
    kind = m.group(2).split()[0]
    name = f"{_KEY_KINDS[kind]} private key" if kind in _KEY_KINDS else "Private key"
    if not re.match(r"\s*(?:\\[rn]|[\r\n])*[A-Za-z0-9+/=:\-\s\\]{40}", text[m.end():m.end() + 200]):
        return None                                      # a header with no key material: docs, parsers, regexes
    return ("high" if kind == "ENCRYPTED" else "critical", name, "PEM block with key material")


_LOCAL_HOST = re.compile(r"^(?:localhost|127\.\d+\.\d+\.\d+|0\.0\.0\.0|\[?::1\]?|host\.docker\.internal|db|database|"
                         r"postgres|mysql|redis|mongo)$", re.I)
_PLACEHOLDER_CREDS = {"user", "username", "password", "pass", "passwd", "pwd", "secret", "admin", "root", "postgres",
                      "test", "guest", "login", "name", "token", "foo", "bar", "baz"}


def _credentials(kind):
    def check(m, text):
        user, password, host = m.group(2), m.group(3), m.group(4)
        if looks_fake(password) or password.lower() in _PLACEHOLDER_CREDS or re.fullmatch(r"[:$%{].*", password):
            return None
        if "*" in password or password.startswith("<") or not re.search(r"[A-Za-z0-9]", password):
            return None                                  # masked (***, •••) or a template, not a credential
        scheme = m.group(1).split("://")[0]
        detail = f"{scheme}://{user}:•••@{host}"
        if _LOCAL_HOST.match(host):
            return ("medium", f"{kind} with a password (local development host)", detail)
        return ("critical" if kind == "Database URL" else "high", f"{kind} with a password", detail)
    return check


_SECRET_WORD = r"(?:secret|private[_-]?key|access[_-]?token|auth[_-]?token|refresh[_-]?token|password|passwd)"
_SECRETISH_NAME = re.compile(
    r"(?i)(?<![A-Za-z0-9_$])([A-Za-z0-9_-]{0,40}?" + _SECRET_WORD + r"[A-Za-z0-9_-]{0,40})"
    r"[\"']?\s*[:=]\s*[\"']([^\"'\s\\]{12,200})[\"']")


def random_looking(value: str) -> bool:
    """Generated secrets interleave letters and digits; names, labels and setting ids do not."""
    if not (re.search(r"[A-Za-z]", value) and re.search(r"\d", value)) or entropy(value) < 3.5:
        return False
    flips = len(re.findall(r"(?<=[A-Za-z])(?=\d)|(?<=\d)(?=[A-Za-z])", value))
    classes = sum(bool(re.search(p, value)) for p in (r"[a-z]", r"[A-Z]", r"\d", r"[^A-Za-z0-9]"))
    return flips >= 4 or (flips >= 2 and classes >= 3)


def _assignment(m, text):
    value = m.group(2)
    if looks_fake(value) or not random_looking(value) or re.match(r"(?:https?:|/|\.|#)", value):
        return None
    return ("medium", f"Possible hard-coded secret in '{m.group(1)}'", "")


# ── the rules ─────────────────────────────────────────────────────────────────

_B = r"(?<![A-Za-z0-9_])"          # token boundary before
_A = r"(?![A-Za-z0-9_])"           # and after

ROTATE = "Revoke and rotate it now (it is public already), then move the call that needs it to a server."

RULES: list[Rule] = [
    Rule("aws-access-key", "AWS access key", "critical",
         re.compile(r"(?<![A-Z0-9])((?:AKIA|ASIA)[A-Z0-9]{16})(?![A-Z0-9])"), ROTATE, check=_aws,
         prefilter=re.compile(r"AKIA|ASIA")),
    Rule("stripe-secret-key", "Live secret API key", "critical",
         re.compile(_B + r"((?:sk|rk)_(?:live|test)_[0-9A-Za-z]{20,247})(?![0-9A-Za-z])"), ROTATE, check=_stripe,
         prefilter=re.compile(r"k_(?:live|test)_"), window=300),
    Rule("openai-api-key", "OpenAI API key", "critical",
         re.compile(r"(?<![A-Za-z0-9_-])(sk-(?:proj-|svcacct-|admin-)?[A-Za-z0-9_-]{8,}T3BlbkFJ[A-Za-z0-9_-]{8,})"
                    r"(?![A-Za-z0-9_-])"),
         "Anyone can spend on this account. " + ROTATE, check=_real("critical", "OpenAI API key"),
         prefilter=re.compile(r"sk-"), window=400),
    Rule("anthropic-api-key", "Anthropic API key", "critical",
         re.compile(r"(?<![A-Za-z0-9_-])(sk-ant-(?:api|admin)\d{2}-[A-Za-z0-9_-]{80,120})(?![A-Za-z0-9_-])"),
         "Anyone can spend on this account. " + ROTATE, check=_real("critical", "Anthropic API key"),
         prefilter=re.compile(r"sk-ant-")),
    Rule("github-token", "GitHub token", "critical",
         re.compile(_B + r"(gh[pousr]_[A-Za-z0-9]{36,255}|github_pat_[A-Za-z0-9_]{60,255})" + _A), ROTATE,
         check=_real("critical", "GitHub token"), prefilter=re.compile(r"gh[pousr]_|github_pat_"), window=300),
    Rule("supabase-secret-key", "Supabase secret key", "critical",
         re.compile(_B + r"(sb_secret_[A-Za-z0-9_-]{20,})(?![A-Za-z0-9_-])"),
         "It bypasses Row Level Security on every table. " + ROTATE, check=_real("critical", "Supabase secret key"),
         prefilter=re.compile(r"sb_secret_")),
    Rule("jwt", "JSON Web Token", "low",
         re.compile(r"(?<![A-Za-z0-9_.-])(eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})"
                    r"(?![A-Za-z0-9_-])"),
         "A service_role key bypasses Row Level Security: anyone can read and write every table. " + ROTATE,
         check=_jwt, prefilter=re.compile(r"eyJ"), window=8192),
    Rule("sendgrid-api-key", "SendGrid API key", "critical",
         re.compile(r"(?<![A-Za-z0-9_-])(SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43})(?![A-Za-z0-9_-])"),
         "Anyone can send mail as you. " + ROTATE, check=_real("critical", "SendGrid API key"),
         prefilter=re.compile(r"SG\.")),
    Rule("npm-token", "npm access token", "critical", re.compile(_B + r"(npm_[A-Za-z0-9]{36})" + _A),
         "Anyone can publish packages as you. " + ROTATE, check=_real("critical", "npm access token"),
         prefilter=re.compile(r"npm_")),
    Rule("private-key", "Private key", "critical",
         re.compile(r"(-----BEGIN ((?:RSA |EC |DSA |OPENSSH |ENCRYPTED |PGP )?PRIVATE KEY(?: BLOCK)?)-----)"),
         "Treat the key pair as compromised: replace it everywhere it is trusted.", check=_private_key,
         prefilter=re.compile(r"-----BEGIN ")),
    Rule("azure-storage-key", "Azure Storage connection string", "critical",
         re.compile(r"(DefaultEndpointsProtocol=https?;AccountName=[A-Za-z0-9]{3,24};AccountKey=[A-Za-z0-9+/]{86}==)"),
         ROTATE, check=_real("critical", "Azure Storage connection string"),
         prefilter=re.compile(r"DefaultEndpointsProtocol="), window=400),
    Rule("database-url", "Database URL with a password", "critical",
         re.compile(r"(?<![A-Za-z0-9+.-])((?:postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|rediss?|amqps?|mssql|"
                    r"sqlserver)://([^:/?#\s\"'`@]{1,128}):([^@/?#\s\"'`]{1,256})@([^/?#\s\"'`:]{1,253}))"),
         "Change the password and keep connection strings on the server.", group=3,
         check=_credentials("Database URL"),
         prefilter=re.compile(r"://"),
         window=1024),
    Rule("url-credentials", "URL with embedded credentials", "high",
         re.compile(r"(?<![A-Za-z0-9+.-])((?:https?|ftp)://([^:/?#\s\"'`@]{1,128}):([^@/?#\s\"'`]{1,256})@"
                    r"([A-Za-z0-9.-]{1,253}))"),
         "Change the password; credentials in a URL travel to every visitor.", group=3, check=_credentials("URL"),
         prefilter=re.compile(r"://"), window=1024),
    Rule("slack-token", "Slack token", "high", re.compile(r"(?<![A-Za-z0-9-])(xox[baprse]-[0-9A-Za-z-]{10,250})"
                                                       r"(?![0-9A-Za-z-])"), ROTATE,
         check=_real("high", "Slack token"), prefilter=re.compile(r"xox[baprse]-"), window=300),
    Rule("slack-webhook", "Slack incoming webhook", "high",
         re.compile(r"(https://hooks\.slack\.com/(?:services|workflows|triggers)/[A-Za-z0-9/_-]{20,})"),
         "Anyone can post into that channel. Regenerate the webhook.", check=_real("high", "Slack incoming webhook"),
         prefilter=re.compile(r"hooks\.slack\.com/")),
    Rule("discord-webhook", "Discord webhook", "high",
         re.compile(r"(https://(?:ptb\.|canary\.)?discord(?:app)?\.com/api/webhooks/\d{15,22}/[\w-]{40,})"),
         "Anyone can post as that webhook. Delete and recreate it.", check=_real("high", "Discord webhook"),
         prefilter=re.compile(r"discord(?:app)?\.com/api/webhooks/"), window=300),
    Rule("telegram-bot-token", "Telegram bot token", "high",
         re.compile(r"(?<![\w:])(\d{8,10}:AA[A-Za-z0-9_-]{33})(?![\w-])"),
         "Anyone can control the bot. Revoke it with @BotFather.", check=_real("high", "Telegram bot token"),
         prefilter=re.compile(r":AA")),
    Rule("huggingface-token", "Hugging Face token", "high", re.compile(_B + r"(hf_[A-Za-z]{34})" + _A), ROTATE,
         check=_real("high", "Hugging Face token"), prefilter=re.compile(r"hf_")),
    Rule("groq-api-key", "Groq API key", "high", re.compile(_B + r"(gsk_[A-Za-z0-9]{52})" + _A), ROTATE,
         check=_real("high", "Groq API key"), prefilter=re.compile(r"gsk_")),
    Rule("xai-api-key", "xAI API key", "high", re.compile(r"(?<![A-Za-z0-9_-])(xai-[A-Za-z0-9]{80})(?![A-Za-z0-9])"),
         ROTATE, check=_real("high", "xAI API key"), prefilter=re.compile(r"xai-")),
    Rule("replicate-token", "Replicate API token", "high", re.compile(_B + r"(r8_[A-Za-z0-9]{37})" + _A), ROTATE,
         check=_real("high", "Replicate API token"), prefilter=re.compile(r"r8_")),
    Rule("shopify-token", "Shopify access token", "high", re.compile(_B + r"(shp(?:at|ca|pa|ss)_[a-fA-F0-9]{32})" + _A),
         ROTATE, check=_real("high", "Shopify access token"), prefilter=re.compile(r"shp(?:at|ca|pa|ss)_")),
    Rule("mapbox-secret-token", "Mapbox secret token", "high",
         re.compile(r"(?<![A-Za-z0-9_-])(sk\.eyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,})(?![A-Za-z0-9_-])"),
         "Secret tokens (sk.) never belong in a browser; public ones (pk.) do. " + ROTATE,
         check=_real("high", "Mapbox secret token"), prefilter=re.compile(r"sk\.eyJ"), window=2048),
    Rule("google-oauth-secret", "Google OAuth client secret", "high",
         re.compile(_B + r"(GOCSPX-[A-Za-z0-9_-]{28})(?![A-Za-z0-9_-])"), ROTATE,
         check=_real("high", "Google OAuth client secret"), prefilter=re.compile(r"GOCSPX-")),
    Rule("mailgun-api-key", "Mailgun API key", "high", re.compile(r"(?<![A-Za-z0-9_-])(key-[0-9a-f]{32})(?![0-9a-zA-Z])"),
         ROTATE, check=_real("high", "Mailgun API key"), prefilter=re.compile(r"key-")),
    Rule("google-api-key", "Google API key", "medium",
         re.compile(r"(?<![A-Za-z0-9_-])(AIza[0-9A-Za-z_-]{35})(?![0-9A-Za-z_-])"),
         "Google keys are often meant for the browser, but only safe when restricted (HTTP referrers + specific "
         "APIs) in Cloud Console; for Firebase, lock down the Firestore / Realtime Database / Storage rules.",
         check=_google, prefilter=re.compile(r"AIza")),
    Rule("twilio-api-key", "Twilio API key SID", "medium",
         re.compile(r"(?<![A-Za-z0-9])(SK[0-9a-f]{32})(?![0-9a-zA-Z])"),
         "The SID is half of a key pair; look for its secret nearby, and keep both on the server.",
         check=_real("medium", "Twilio API key SID"), prefilter=re.compile(r"SK[0-9a-f]")),
    Rule("hardcoded-secret", "Possible hard-coded secret", "medium", _SECRETISH_NAME,
         "If this is a real credential, rotate it and keep it on the server.", group=2, check=_assignment,
         prefilter=re.compile(_SECRET_WORD), lowercase=True),
]


def _matches(rule: Rule, text: str, lower: str | None):
    """The rule's matches, found by running the full pattern only around its anchor's hits."""
    if rule.prefilter is None:
        yield from rule.pattern.finditer(text)
        return
    if rule.lowercase:
        anchors = rule.prefilter.finditer(lower) if lower is not None else \
            re.compile(rule.prefilter.pattern, re.I).finditer(text)
    else:
        anchors = rule.prefilter.finditer(text)
    seen = -1
    for p in anchors:
        if p.start() < seen:
            continue                                  # inside the previous match
        pos, end = max(0, p.start() - 45, seen), min(len(text), p.end() + rule.window)
        while pos <= p.start():
            m = rule.pattern.search(text, pos, end)
            if not m or m.start() > p.start():
                break
            if p.start() < m.end():                   # the match that holds this anchor
                seen = m.end()
                yield m
                break
            pos = m.end() if m.end() > m.start() else m.start() + 1


def scan(text: str) -> list[Hit]:
    """Every rule over the text; overlapping hits keep the most severe (then the longest)."""
    hits = []
    lower = text.lower()
    lower = lower if len(lower) == len(text) else None      # some characters change length when lowered
    for rule in RULES:
        for m in _matches(rule, text, lower):
            verdict = rule.check(m, text) if rule.check else (rule.severity, rule.title, "")
            if verdict is None:
                continue
            severity, title, detail = verdict
            hits.append(Hit(rule.id, title, severity, m.start(rule.group), m.end(rule.group), m.group(rule.group),
                            detail, rule.advice))
    hits.sort(key=lambda h: (RANK[h.severity], -(h.end - h.start)))
    kept: list[Hit] = []
    taken: list[tuple[int, int]] = []                 # sorted, non-overlapping spans already kept
    for h in hits:
        i = bisect.bisect_left(taken, (h.start, h.end))
        if (i > 0 and taken[i - 1][1] > h.start) or (i < len(taken) and taken[i][0] < h.end):
            continue
        taken.insert(i, (h.start, h.end))
        kept.append(h)
    return sorted(kept, key=lambda h: h.start)
