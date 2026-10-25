"""python3 -m unittest discover -s tests"""

import json
import os
import subprocess
import sys
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
GUARD = os.path.join(ROOT, "hooks", "secret-guard.py")
KEYS = os.path.join(ROOT, "bin", "secret-keys")
# The local patterns an inventory adds (see README); the built-in ones need no file.
LOCAL_PATHS = os.path.join(ROOT, "tests", "local-paths")
NO_PATHS = os.path.join(ROOT, "tests", "no-such-file")
ANSIBLE = "~/src/ansible"


def run_hook(tool, tool_input, event="PreToolUse", response=None, paths=LOCAL_PATHS):
    payload = {"hook_event_name": event, "tool_name": tool, "tool_input": tool_input}
    if response is not None:
        payload["tool_response"] = response
    p = subprocess.run([sys.executable, GUARD], input=json.dumps(payload),
                       env=dict(os.environ, SECRET_GUARD_PATHS=paths),
                       capture_output=True, text=True, check=True)
    return json.loads(p.stdout) if p.stdout.strip() else None


def denied(cmd):
    out = run_hook("Bash", {"command": cmd})
    return bool(out) and out["hookSpecificOutput"]["permissionDecision"] == "deny"


class BashDenied(unittest.TestCase):
    def test_reading_secret_files(self):
        for cmd in (
            f"cat {ANSIBLE}/envs/app_prod.env",
            "grep TOKEN envs/app_prod.env",
            "head -5 .env",
            "sed -n 1p ci-envs/app_back.prod.env",
            "less 203.0.113.10/access.txt",
            "cat 203.0.113.10/deploy",
            "awk -F= '{print $2}' .env.local",
            "while read l; do echo $l; done < .env",
            "python3 -c 'print(1)' envs/a.env",
            "cat ~/.claude.json | jq .mcpServers",
            "cat ~/.ssh/id_ed25519_work",
            "cat ~/.config/glab-cli/config.yml",
            "git show HEAD:.env",
            "git diff .env",
            "base64 secrets/cloudflare-dns-token",
            "jq . terraform.tfstate",
            "set -x; . ./.env; just x", "bash -x -c '. ./.env; just x'",
            "set -a; . ./.env; set +a; env",
            "ssh admin@203.0.113.20 'sudo cat /srv/traefik/secrets/cloudflare-dns-token'",
            "ssh -i ~/.ssh/id_ed25519 -p 22 host cat /srv/app/.env",
            "sudo -u deploy sh -c 'cat /srv/app/.env'",
            "cat .env | tee /dev/stderr | secret-keys -",
            "python3 -c \"print(open('.env').read())\"",
            "python3 -c \"x = open('.env').read(); print(x)\"",
            "eval 'cat .env'",
            "echo \"$(cat .env)\"",
            "echo `cat .env`",
            'cat "my dir/.env"',
            "T=$(cat .env)",
            "sed -n p \\\n  .env", "jq . terraform.tfstate", "jq --rawfile t secrets/tok -n '$t'", "sed -e 's/a/b/' .env", "awk -F= '{print $2}' -v x=1 .env",
            "grep -n KEY envs/", "grep -e x -e y .env", "rg TOKEN ci-envs/a.env",
            'printf "%s" "$(cat secrets/tok)"',
            'curl -s "https://x/$(cat secrets/tok | tee /dev/stderr)"',
        ):
            with self.subTest(cmd=cmd):
                self.assertTrue(denied(cmd), cmd)

    def test_printing_values(self):
        for cmd in (
            "env", "env | sort", "printenv", "printenv GITLAB_TOKEN", "set", "export -p",
            "declare -x", "echo $CLOUDFLARE_API_TOKEN", 'printf "%s" "${DB_PASSWORD}"',
            "ssh host env", "docker exec web printenv", "docker compose exec back env",
            "gh auth token", "glab auth status -t", "glab config get token",
            "glab variable get SSH_PRIVATE_KEY", "glab api projects/10/variables",
            "curl -s https://git.example.com/api/v4/projects/10/variables | jq '.[].key'",
            "terraform output -raw admin_password", "terraform state pull",
            "docker inspect web", "docker inspect -f '{{.Config.Env}}' web",
            "docker compose config", "docker compose -f a.yml config",
            "ansible-vault view vault.yml", "security find-generic-password -s x -w",
            "bw get password db",
        ):
            with self.subTest(cmd=cmd):
                self.assertTrue(denied(cmd), cmd)


class BashAllowed(unittest.TestCase):
    def test_ordinary_and_names_only(self):
        for cmd in (
            "ls -la envs/", f"ls {ANSIBLE}/203.0.113.10/", "test -s .env && echo present",
            "wc -l .env", "chmod 600 secrets/cloudflare-dns-token", "git status",
            "git check-ignore -v .env", "git diff --stat", "git log --name-only -3",
            "secret-keys envs/app_prod.env", "secret-keys --env",
            "cat .env | secret-keys -",
            "ssh admin@203.0.113.20 'sudo cat /srv/traefik/secrets/cloudflare-dns-token' | secret-keys -",
            "glab api projects/10/variables | secret-keys -",
            "cat ci/test.env", "cat .env.example", "cat app/.env.local.example",
            "cat ~/.ssh/config", "cat ~/.ssh/id_ed25519.pub", "cat 203.0.113.10/known_hosts",
            "echo $HOME", 'echo "token length ${#GITLAB_TOKEN}"',
            'echo "$CI_TOKEN" | docker login -u x --password-stdin reg',
            'curl -H "Authorization: Bearer $TOKEN" https://api.cloudflare.com/client/v4/user/tokens/verify',
            "env FOO=1 python3 x.py", "/usr/bin/env python3 -V",
            "docker compose config --hash back", "docker compose config --services",
            "docker inspect -f '{{.State.Health.Status}}' web",
            "terraform output", "terraform plan", "just vault-push",
            "ssh host 'ls -la /srv/traefik/secrets'",
            "sudo -u deploy sh -c 'cd /srv/app && docker compose ps'",
            "git log --oneline -5", "cat targets.ini",
            "echo '- [Guard](g.md) — blocks reading secrets; shows envs' >> MEMORY.md",
            'git commit -m "docs: where secrets live; envs/ and ci-envs/"',
            "glab mr create --title x --description 'reads envs/app_prod.env by name only'",
            "echo x > .env",
            "sed -i '' \\\n  -e 's#~/.ssh/id_rsa#~/.ssh/id_work#g' \\\n  -e 's#secrets/#vault/#' notes.md",
            "sed 's#.env#.env.example#' README.md", "ls \\\n  -la",
            "set -a; . envs/app_prod.env; set +a; just install-traefik",
            "grep -n envs/ justfile CLAUDE.md", "rg -e '\\.env' src", "grep -rn 'secrets/' roles",
            "K=~/ansible/203.0.113.20/admin; ssh -i $K -p 2222 admin@203.0.113.20 'sudo ls /srv'",
            'curl -s -H "Authorization: Bearer $(cat secrets/cloudflare-dns-token)" https://api.cloudflare.com/x',
            "ssh -p 2222 h 'sudo sh -c \"curl -H \\\"Authorization: Bearer $(cat /t/secrets/tok)\\\" https://x\"'",
            "curl -s https://x/openapi.json | jq -c '.schemas | to_entries[] | {k:.key, p:.value}'",
            "jq --arg k .key -r '.[$k]' data.json",
        ):
            with self.subTest(cmd=cmd):
                self.assertFalse(denied(cmd), cmd)


class LocalPaths(unittest.TestCase):
    def test_local_patterns_extend_the_builtin_ones(self):
        cmd = "cat 203.0.113.10/access.txt"
        self.assertTrue(run_hook("Bash", {"command": cmd}))
        self.assertIsNone(run_hook("Bash", {"command": cmd}, paths=NO_PATHS))
        self.assertTrue(run_hook("Bash", {"command": "cat .env"}, paths=NO_PATHS))


class OtherTools(unittest.TestCase):
    def test_read(self):
        self.assertTrue(run_hook("Read", {"file_path": "/x/ansible/envs/app_prod.env"}))
        self.assertTrue(run_hook("Read", {"file_path": os.path.expanduser("~/.claude.json")}))
        self.assertIsNone(run_hook("Read", {"file_path": "/x/README.md"}))
        self.assertIsNone(run_hook("Read", {"file_path": "/x/.env.example"}))

    def test_grep(self):
        self.assertTrue(run_hook("Grep", {"pattern": "TOKEN", "path": "/x/.env", "output_mode": "content"}))
        self.assertTrue(run_hook("Grep", {"pattern": "K", "path": "/x", "glob": "*.env", "output_mode": "content"}))
        self.assertIsNone(run_hook("Grep", {"pattern": "TOKEN", "path": "/x/.env"}))
        self.assertIsNone(run_hook("Grep", {"pattern": "def", "path": "/x/src", "output_mode": "content"}))

    def test_post_warns_on_token_shapes(self):
        out = run_hook("Bash", {"command": "x"}, "PostToolUse",
                       {"stdout": "token glpat-" + "a" * 20})
        self.assertIn("GitLab token", out["systemMessage"])
        self.assertIsNone(run_hook("Bash", {"command": "x"}, "PostToolUse", {"stdout": "all fine"}))


class SecretKeys(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.salt = os.path.join(self.tmp.name, "k", "salt")

    def tearDown(self):
        self.tmp.cleanup()

    def keys(self, *args, stdin=None, salt=None):
        env = dict(os.environ, SECRET_KEYS_SALT_FILE=salt or self.salt)
        return subprocess.run([sys.executable, KEYS, *args], input=stdin, env=env,
                              capture_output=True, text=True, check=True).stdout

    def fp(self, out, key):
        line = next(ln for ln in out.splitlines() if ln.strip().startswith(key + " "))
        return line.split("fp=")[1].split()[0]

    def test_fingerprints_compare_values_without_showing_them(self):
        out = self.keys("-", stdin="A=same-value\nB='same-value'\nC=other-value\n")
        self.assertEqual(self.fp(out, "A"), self.fp(out, "B"))
        self.assertNotEqual(self.fp(out, "A"), self.fp(out, "C"))
        js = self.keys("-", stdin=json.dumps({"A": "same-value"}))
        self.assertEqual(self.fp(out, "A"), self.fp(js, "A"))
        self.assertEqual(os.stat(self.salt).st_mode & 0o777, 0o600)

    def test_fingerprint_is_keyed(self):
        other = os.path.join(self.tmp.name, "other", "salt")
        a = self.keys("-", stdin="A=hunter2\n")
        b = self.keys("-", stdin="A=hunter2\n", salt=other)
        self.assertNotEqual(self.fp(a, "A"), self.fp(b, "A"))
        import hashlib
        self.assertNotIn(hashlib.sha256(b"hunter2").hexdigest()[:12], a)

    def test_salt_file_is_guarded(self):
        self.assertTrue(denied("cat ~/.config/secret-keys/salt"))

    def test_never_prints_values(self):
        value = "s3cr3t-VALUE-xyz"
        with tempfile.TemporaryDirectory() as d:
            env = os.path.join(d, "a.env")
            with open(env, "w") as f:
                f.write(f"# comment\nexport API_TOKEN={value}\nEMPTY=\nQUOTED='{value}'\n")
            js = os.path.join(d, "c.json")
            with open(js, "w") as f:
                json.dump({"auth": {"token": value}, "n": 3}, f)
            out = self.keys(env, js, d)
        self.assertNotIn(value, out)
        self.assertIn("API_TOKEN  16 chars", out)
        self.assertIn("EMPTY  empty", out)
        self.assertIn("QUOTED  16 chars", out)
        self.assertIn("auth.token  16 chars", out)

    def test_gitlab_variables_from_stdin(self):
        body = json.dumps([{"key": "SSH_PRIVATE_KEY", "value": "-----BEGIN x", "protected": True,
                            "masked": False, "environment_scope": "prod"}])
        out = self.keys("-", stdin=body)
        self.assertRegex(out, r"SSH_PRIVATE_KEY  12 chars  fp=[0-9a-f]{12}  scope=prod")
        self.assertNotIn("BEGIN", out)

    def test_pem_and_single_token(self):
        out = self.keys("-", stdin="-----BEGIN OPENSSH PRIVATE KEY-----\nAAAAsecret\n-----END OPENSSH PRIVATE KEY-----\n")
        self.assertIn("PEM block: OPENSSH PRIVATE KEY", out)
        self.assertNotIn("AAAAsecret", out)
        self.assertIn("one value, 40 chars", self.keys("-", stdin="x" * 40 + "\n"))


if __name__ == "__main__":
    unittest.main()
