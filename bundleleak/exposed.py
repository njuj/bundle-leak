"""Files a deploy should never serve: environment files, a Git folder, credentials and archives that end
up in the web root by accident (a `public/.env`, an rsync of the whole project, a backup zip).

Each one is recognised by its *content*, not by the status code: most SPA hosts answer every path with
200 and their index.html, so only a body that really is a .env, a Git HEAD or a zip counts."""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Callable

_ENV_LINE = re.compile(r"^\s*(?:export\s+)?[A-Za-z_][A-Za-z0-9_.]*\s*=", re.M)


def _text(body: bytes) -> str | None:
    head = body[:4096].lstrip().lower()
    if not body.strip() or b"\0" in body[:4096] or head.startswith((b"<!doctype", b"<html", b"<?xml", b"{", b"[")):
        return None
    return body[:1 << 20].decode("utf-8", "replace")


def _env(body: bytes) -> bool:
    text = _text(body)
    if text is None:
        return False
    lines = [l for l in text.splitlines() if l.strip() and not l.lstrip().startswith("#")]
    hits = len(_ENV_LINE.findall(text))
    return hits >= 1 and hits >= len(lines) * 0.6


def _git_head(body: bytes) -> bool:
    return re.fullmatch(rb"(?:ref: refs/[\w./-]+|[0-9a-f]{40}|[0-9a-f]{64})\s*", body[:200]) is not None


def _git_config(body: bytes) -> bool:
    text = body[:8192].decode("utf-8", "replace") if b"\0" not in body[:8192] else ""   # starts with "[", so not _text
    return text.lstrip().startswith("[") and "[core]" in text and ("repositoryformatversion" in text or "bare =" in text)


def _npmrc(body: bytes) -> bool:
    text = _text(body) or ""
    return bool(re.search(r"^\s*(?://[^\s=]+:)?_(?:authToken|auth|password)\s*=", text, re.M))


def _htpasswd(body: bytes) -> bool:
    text = _text(body) or ""
    lines = [l for l in text.splitlines() if l.strip()]
    return bool(lines) and all(re.fullmatch(r"[^:\s]+:(?:\$apr1\$|\$2[aby]\$|\{SHA\}|\$5\$|\$6\$)\S+", l) for l in lines[:20])


def _compose(body: bytes) -> bool:
    text = _text(body) or ""
    return bool(re.search(r"^services:\s*$", text, re.M)) and bool(re.search(r"^\s+image:|^\s+build:", text, re.M))


def _zip(body: bytes) -> bool:
    return body[:4] == b"PK\x03\x04"


def _ds_store(body: bytes) -> bool:
    return body[:8] == b"\x00\x00\x00\x01Bud1"


@dataclass(frozen=True)
class Probe:
    path: str
    rule: str
    title: str
    severity: str
    check: Callable[[bytes], bool]
    advice: str
    scan_contents: bool = False      # run the secret detectors over the file


_ROTATE = "Remove it from the web root, rotate every secret it holds (it is public already), and fix the deploy step that copied it."
PROBES = [
    *(Probe(p, "env-file-served", "Environment file served to anyone", "critical", _env, _ROTATE, True)
      for p in (".env", ".env.local", ".env.production", ".env.production.local", ".env.development", ".env.backup")),
    Probe(".git/HEAD", "git-exposed", "Git repository served: source code and history can be downloaded", "high",
          _git_head, "Block /.git/ on the server and stop deploying it; tools such as git-dumper rebuild the whole "
          "repository, history and old secrets included, from these files."),
    Probe(".git/config", "git-exposed", "Git repository served: source code and history can be downloaded", "high",
          _git_config, "Block /.git/ on the server and stop deploying it; the config also names the remote."),
    Probe(".npmrc", "npmrc-served", "npm credentials file served", "critical", _npmrc, _ROTATE, True),
    Probe(".htpasswd", "htpasswd-served", "Password hashes served (.htpasswd)", "high", _htpasswd,
          "Move it outside the web root and change those passwords: the hashes can be cracked offline."),
    Probe("docker-compose.yml", "compose-served", "docker-compose.yml served", "medium", _compose,
          "Keep deployment files out of the web root; they describe your services and often carry credentials.", True),
    *(Probe(p, "archive-served", "Archive of the site served", "high", _zip,
            "Delete it from the web root: archives like this usually hold the source and its config.")
      for p in ("backup.zip", "site.zip", "dist.zip", "build.zip")),
    Probe(".DS_Store", "ds-store-served", "macOS folder index (.DS_Store) served", "low", _ds_store,
          "Delete it and stop deploying it: it lists the names of files in the folder, hidden ones included."),
]


def match(path: str, body: bytes) -> Probe | None:
    """The probe for `path` whose content check this body passes."""
    return next((p for p in PROBES if p.path == path and p.check(body)), None)
