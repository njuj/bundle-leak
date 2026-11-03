"""Fake credentials in the real formats, assembled at run time.

No file in this repository contains a contiguous secret-shaped string: secret scanners (and GitHub
push protection) would rightly flag one. Every token here is built from pieces, from a seeded RNG, so
the tests are deterministic and the values are worthless.
"""

import base64
import json
import random
import string

_R = random.Random(20261103)
ALNUM = string.ascii_letters + string.digits
URLSAFE = ALNUM + "-_"


def rand(n: int, alphabet: str = ALNUM) -> str:
    return "".join(_R.choice(alphabet) for _ in range(n))


def j(*parts: str) -> str:
    return "".join(parts)


def _b64url(data: dict) -> str:
    return base64.urlsafe_b64encode(json.dumps(data, separators=(",", ":")).encode()).decode().rstrip("=")


def jwt(claims: dict) -> str:
    return j(_b64url({"alg": "HS256", "typ": "JWT"}), ".", _b64url(claims), ".", rand(43, URLSAFE))


def supabase_jwt(role: str) -> str:
    return jwt({"iss": "supa" + "base", "ref": rand(20, string.ascii_lowercase), "role": role,
                "iat": 1735689600, "exp": 2051222400})


def aws_key_id() -> str:
    return j("AK", "IA", rand(16, string.ascii_uppercase + string.digits))


def aws_secret() -> str:
    return rand(40, ALNUM + "/+")


def stripe(kind: str = "sk", mode: str = "live") -> str:
    return j(kind, "_", mode, "_", rand(32))


def openai() -> str:
    return j("sk", "-proj-", rand(24, URLSAFE), "T3Blbk", "FJ", rand(24, URLSAFE))


def anthropic() -> str:
    return j("sk", "-ant-", "api03-", rand(95, URLSAFE))


def github() -> str:
    return j("gh", "p_", rand(36))


def github_pat() -> str:
    return j("github", "_pat_", rand(82, ALNUM + "_"))


def sendgrid() -> str:
    return j("S", "G.", rand(22, URLSAFE), ".", rand(43, URLSAFE))


def npm() -> str:
    return j("np", "m_", rand(36))


def slack_token() -> str:
    return j("xo", "xb-", rand(12, string.digits), "-", rand(13, string.digits), "-", rand(24))


def slack_webhook() -> str:
    return j("https://hooks.", "slack.com/services/T", rand(8, string.ascii_uppercase + string.digits), "/B",
             rand(8, string.ascii_uppercase + string.digits), "/", rand(24))


def discord_webhook() -> str:
    return j("https://discord.", "com/api/webhooks/", rand(18, string.digits), "/", rand(68, URLSAFE))


def telegram() -> str:
    return j(rand(10, string.digits), ":A", "A", rand(33, URLSAFE))


def huggingface() -> str:
    return j("h", "f_", rand(34, string.ascii_letters))


def groq() -> str:
    return j("gs", "k_", rand(52))


def xai() -> str:
    return j("xa", "i-", rand(80))


def replicate() -> str:
    return j("r", "8_", rand(37))


def shopify() -> str:
    return j("sh", "pat_", rand(32, "0123456789abcdef"))


def mapbox_secret() -> str:
    return j("sk", ".eyJ", rand(40, URLSAFE), ".", rand(22, URLSAFE))


def google_oauth_secret() -> str:
    return j("GOC", "SPX-", rand(28, URLSAFE))


def mailgun() -> str:
    return j("ke", "y-", rand(32, "0123456789abcdef"))


def google_api_key() -> str:
    return j("AI", "za", rand(35, URLSAFE))


def twilio_sid() -> str:
    return j("S", "K", rand(32, "0123456789abcdef"))


def supabase_secret() -> str:
    return j("sb", "_secret_", rand(32, URLSAFE))


def azure_conn() -> str:
    return j("DefaultEndpoints", "Protocol=https;AccountName=", rand(12, string.ascii_lowercase + string.digits),
             ";AccountKey=", rand(86, ALNUM + "+/"), "==")


def private_key(kind: str = "RSA ") -> str:
    body = "\\n".join(rand(64, ALNUM + "+/") for _ in range(4))
    return j("-----BEGIN ", kind, "PRIVATE", " KEY-----\\n", body, "\\n-----END ", kind, "PRIVATE KEY-----")


def password() -> str:
    """Random-looking, the way a generated password is."""
    while True:
        p = rand(20, ALNUM + "!%")                     # no '#': it would end a URL's userinfo
        if sum(c.isdigit() for c in p) >= 3 and any(c.isalpha() for c in p):
            return p
