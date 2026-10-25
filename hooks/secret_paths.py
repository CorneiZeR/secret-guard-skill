"""Which paths hold secrets. Shared by secret-guard (the hook) and its tests.

The patterns here are the ones every machine has. Paths particular to one
setup — an inventory's per-server folders, a repository's env directory — go
one regex per line into ~/.config/secret-guard/paths (or $SECRET_GUARD_PATHS),
so they never have to be published with the plugin.
"""

import os
import re

HOME = os.path.expanduser("~")
EXTRA = os.environ.get("SECRET_GUARD_PATHS", os.path.join(HOME, ".config", "secret-guard", "paths"))

# Names that look like env files but carry no secrets by convention.
_ENV_SAFE = re.compile(
    r"(\.example|\.sample|\.template|\.dist|\.defaults)$|(^|/)test\.env$|\.example\.env$"
)

_BUILTIN = (
    r"(^|/)\.env(\.[^/]*)?$",  # .env, .env.local, .env.production
    r"\.env$",  # prod.env, ci/x.prod.env
    r"(^|/)secrets(/|$)",
    r"\.(secret|secrets|token|pem|key|p12|pfx|kdbx|jks|keystore)$",
    r"\.tfstate(\.backup)?$",
    r"(^|/)\.vault[_-]?pass[^/]*$",
    r"(^|/)id_(rsa|dsa|ecdsa|ed25519)[^/]*(?<!\.pub)$",
    r"(^|/)\.ssh/(?!(config|known_hosts[^/]*|[^/]*\.pub|authorized_keys)$)[^/]+$",
    r"(^|/)\.claude\.json$",
    r"(^|/)\.credentials\.json$",
    r"(^|/)\.config/(glab-cli/config\.yml|gh/hosts\.yml)$",
    r"(^|/)\.config/secret-keys(/|$)",  # the fingerprint key of secret-keys
    r"(^|/)\.terraform\.d/credentials\.tfrc\.json$",
    r"(^|/)\.(netrc|pgpass|git-credentials)$",
    r"(^|/)\.aws/credentials$",
    r"(^|/)\.docker/config\.json$",
    r"(^|/)\.kube/config$",
)


def _local():
    try:
        with open(EXTRA) as fh:
            lines = [ln.strip() for ln in fh]
    except OSError:
        return ()
    return tuple(ln for ln in lines if ln and not ln.startswith("#"))


_SECRET = [re.compile(p) for p in _BUILTIN + _local()]


def normalize(path: str) -> str:
    path = path.strip().strip("'\"")
    if path.startswith("~"):
        path = HOME + path[1:]
    return path


def is_secret(path: str) -> bool:
    path = normalize(path)
    if not path or _ENV_SAFE.search(path):
        return False
    return any(p.search(path) for p in _SECRET)
