"""Every rule: what it must catch, at what severity, and what it must leave alone."""

import time
import unittest

import fakes as F
from bundleleak.detectors import entropy, jwt_claims, looks_fake, random_looking, redact, scan


def found(text):
    return [(h.rule, h.severity) for h in scan(text)]


class Providers(unittest.TestCase):
    def check(self, token, rule, severity, wrap='const k="{}";'):
        hits = scan(wrap.format(token))
        self.assertEqual([(h.rule, h.severity) for h in hits], [(rule, severity)], token[:12])
        self.assertEqual(hits[0].secret, token)

    def test_critical_keys(self):
        for token, rule in ((F.stripe(), "stripe-secret-key"), (F.openai(), "openai-api-key"),
                            (F.anthropic(), "anthropic-api-key"), (F.github(), "github-token"),
                            (F.github_pat(), "github-token"), (F.sendgrid(), "sendgrid-api-key"),
                            (F.npm(), "npm-token"), (F.supabase_secret(), "supabase-secret-key"),
                            (F.azure_conn(), "azure-storage-key")):
            with self.subTest(rule=rule):
                self.check(token, rule, "critical")

    def test_high_keys(self):
        for token, rule in ((F.stripe("rk"), "stripe-secret-key"), (F.slack_token(), "slack-token"),
                            (F.slack_webhook(), "slack-webhook"), (F.discord_webhook(), "discord-webhook"),
                            (F.telegram(), "telegram-bot-token"), (F.huggingface(), "huggingface-token"),
                            (F.groq(), "groq-api-key"), (F.xai(), "xai-api-key"), (F.replicate(), "replicate-token"),
                            (F.shopify(), "shopify-token"), (F.mapbox_secret(), "mapbox-secret-token"),
                            (F.google_oauth_secret(), "google-oauth-secret"), (F.mailgun(), "mailgun-api-key")):
            with self.subTest(rule=rule):
                self.check(token, rule, "high")

    def test_lower_severities(self):
        self.check(F.stripe(mode="test"), "stripe-secret-key", "medium")
        self.check(F.google_api_key(), "google-api-key", "medium")
        self.check(F.twilio_sid(), "twilio-api-key", "medium")

    def test_publishable_keys_are_not_leaks(self):
        self.assertEqual(found(f'const k="{F.stripe("pk")}"'), [])

    def test_firebase_config_is_public_by_design(self):
        text = f'initializeApp({{apiKey:"{F.google_api_key()}",authDomain:"demo-app.firebaseapp.com",projectId:"demo"}})'
        self.assertEqual(found(text), [("google-api-key", "info")])

    def test_aws_pair(self):
        self.assertEqual(found(f'id:"{F.aws_key_id()}"'), [("aws-access-key", "medium")])
        self.assertEqual(found(f'{{accessKeyId:"{F.aws_key_id()}",secretAccessKey:"{F.aws_secret()}"}}')[:1],
                         [("aws-access-key", "critical")])
        self.assertEqual(found(F.j("AKIA", "IOSFODNN7", "EXAMPLE")), [])        # AWS's documentation key

    def test_tokens_inside_longer_words_do_not_count(self):
        self.assertEqual(found("x" + F.github() + "y"), [])
        self.assertEqual(found("my" + F.npm()), [])


class Jwt(unittest.TestCase):
    def test_supabase_roles(self):
        self.assertEqual(found(f'createClient(u,"{F.supabase_jwt("service_role")}")'), [("jwt", "critical")])
        self.assertEqual(found(f'createClient(u,"{F.supabase_jwt("anon")}")'), [("jwt", "info")])

    def test_other_jwts(self):
        self.assertEqual(found(F.jwt({"sub": "42", "role": "authenticated"})), [("jwt", "low")])
        self.assertEqual(found(F.jwt({"sub": "42", "admin": True})), [("jwt", "high")])

    def test_claims_are_reported_not_the_token(self):
        hit = scan(F.supabase_jwt("service_role"))[0]
        self.assertEqual(hit.title, "Supabase service_role key")
        self.assertIn("role=service_role", hit.detail)

    def test_long_jwt(self):
        token = F.jwt({"role": "service_role", "pad": F.rand(3000)})
        self.assertEqual([(h.rule, h.severity, h.secret) for h in scan(token)], [("jwt", "critical", token)])

    def test_garbage_that_looks_like_a_jwt(self):
        self.assertIsNone(jwt_claims("eyJhbGciOi.eyJ!!!notbase64.sig"))


class Credentials(unittest.TestCase):
    def test_database_urls(self):
        pw = F.password()
        hits = scan(f'const db="postgres://app:{pw}@db.prod-cluster.net:5432/app"')
        self.assertEqual([(h.rule, h.severity) for h in hits], [("database-url", "critical")])
        self.assertEqual(hits[0].secret, pw)                                   # the password, not the URL
        self.assertEqual(hits[0].detail, "postgres://app:•••@db.prod-cluster.net")
        self.assertEqual(found(f'"mongodb+srv://u:{pw}@localhost/x"'), [("database-url", "medium")])

    def test_placeholder_credentials(self):
        for url in ("postgres://user:password@localhost/db", "mysql://root:${DB_PASS}@db/x",
                    "redis://:<password>@cache:6379", "https://user:pass@example.com", "postgres://u:****@h/db",
                    "postgres://app:•••@db.prod-cluster.net"):
            with self.subTest(url=url):
                self.assertEqual(found(f'"{url}"'), [])

    def test_url_credentials(self):
        self.assertEqual(found(f'fetch("https://deploy:{F.password()}@ci.corp-tools.net/api")'),
                         [("url-credentials", "high")])


class PrivateKeys(unittest.TestCase):
    def test_pem_with_key_material(self):
        self.assertEqual(found(f'const k="{F.private_key()}"'), [("private-key", "critical")])
        self.assertEqual(found(f'const k="{F.private_key("ENCRYPTED ")}"'), [("private-key", "high")])

    def test_header_without_key_material(self):
        # crypto libraries carry the header as a marker; that is no leak
        self.assertEqual(found('if(t.startsWith("' + F.j("-----BEGIN ", "RSA PRIVATE KEY-----") + '"))'), [])


class Generic(unittest.TestCase):
    def test_hardcoded_secret(self):
        self.assertEqual(found(f'const cfg={{clientSecret:"{F.password()}"}}'), [("hardcoded-secret", "medium")])
        self.assertEqual(found(f'userPassword = "{F.password()}"'), [("hardcoded-secret", "medium")])

    def test_names_and_labels_are_not_secrets(self):
        for text in ('refreshToken:"github.copilot.chat.refreshToken"', 'password:"Password must be 8 chars"',
                     'ACCESS_TOKEN_WITH_AUTH_SCHEME:"AccessTokenWithAuthScheme"', 'secret:"Summer2024!"',
                     'passwordField:"input[type=password]"', 'secretKey:"YOUR_SECRET_KEY_HERE_123"'):
            with self.subTest(text=text):
                self.assertEqual(found(text), [])

    def test_most_severe_wins_on_overlap(self):
        self.assertEqual(found(f'secret_key = "{F.stripe()}"'), [("stripe-secret-key", "critical")])


class Helpers(unittest.TestCase):
    def test_redact(self):
        token = F.stripe()
        shown = redact(token)
        self.assertTrue(shown.startswith(token[:12]) and shown.endswith(token[-4:]))
        self.assertNotIn(token[12:-4], shown)
        self.assertIn(f"({len(token)})", shown)

    def test_looks_fake(self):
        for v in ("sk_live_xxxxxxxxxxxxxxxx", "YOUR_API_KEY", "${SECRET}", "aaaaaaaaaaaa", "abc0123456789"):
            self.assertTrue(looks_fake(v), v)
        self.assertFalse(looks_fake(F.rand(32)))

    def test_random_looking(self):
        self.assertTrue(random_looking(F.password()))
        self.assertFalse(random_looking("github.copilot.chat.refreshToken"))
        self.assertGreater(entropy(F.rand(32)), 4.0)


class Speed(unittest.TestCase):
    def test_large_bundle_is_linear(self):
        # 8 MB of minified-looking code with a key at the very end
        chunk = 'function a(b){return b.map(c=>c.id+"/api/v1/x").join(",")}var d={e:1,f:"https://cdn.example.com"};'
        text = chunk * (8_000_000 // len(chunk)) + f'k="{F.github()}"'
        started = time.perf_counter()
        hits = scan(text)
        self.assertEqual([h.rule for h in hits], ["github-token"])
        self.assertLess(time.perf_counter() - started, 30)


if __name__ == "__main__":
    unittest.main()
