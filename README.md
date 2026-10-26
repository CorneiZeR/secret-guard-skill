# secret-guard

A Claude Code plugin that keeps secret values out of the session transcript.
Asking an assistant not to print a token works until the one time it does; a
token that reached the transcript has to be rotated. This makes the
mistake impossible instead of unlikely, and gives back a way to work with
secrets that does not need their values.

```
/plugin marketplace add CorneiZeR/claude-plugins
/plugin install secret-guard@corneizer
```

## What it refuses

Before a Bash, Read or Grep call runs:

- **reading a secret file** — `cat`, `grep`, `head`, `sed`, `source`,
  `python -c "open(...)"`, `git show`/`git diff`, also inside `ssh host '…'`,
  `sh -c`, `eval`, `$(…)` and backticks. Listing, moving, hashing, `chmod`,
  `git status` and the like stay allowed;
- **printing a value** — bare `env`, `printenv`, `set`, `export -p`;
  `echo $SOME_TOKEN`; `gh auth token`, `glab auth status -t`;
  `terraform output -raw|-json`, `terraform state pull`; `docker inspect`
  (a container or an image) without `--format` — a manifest, network or
  volume holds no environment and passes — `docker compose config`;
  `ansible-vault view`,
  `security … -w`, `bw get`, `op read`; GitLab's CI/CD variables API;
- **xtrace next to a secret file** — `set -x` or `sh -x` would print every
  value the file loads.

A value handed to another process is not printed and passes:
`curl -H "Authorization: Bearer $TOKEN"`, `echo "$T" | docker login
--password-stdin`, `curl -H "Bearer $(cat token)"`. An interpreter is not
such a process: a value substituted into python or perl code can be printed
by it, and is refused.

A here-document is data for its command, not commands — unless a shell reads
it (`sh <<EOF`). Fed to python or node it is their code: a secret path in it
is still a read, while a backtick or `$(` in it is text, since neither runs a
command there. Perl and ruby run backticks, and keep them.

The refusal tells the assistant what to use instead. If the value itself is
needed, the person runs the command with `!` in the prompt.

After every call, output that matches a well-known token shape (GitLab,
GitHub, Anthropic, OpenAI, AWS, Slack, Stripe, private keys) raises a warning
to the person: it cannot be taken back, so it should be rotated.

## secret-keys: names, lengths, fingerprints

```
$ secret-keys envs/prod.env
== envs/prod.env
  DATABASE_URL       61 chars  fp=4b1e0c9a7f22
  DNS_API_TOKEN      53 chars  fp=9d02e7b51a60
  SMTP_PASSWORD      empty
```

- `secret-keys FILE|DIR …` — dotenv, JSON, YAML, PEM, single-token files;
- `<command> | secret-keys -` — the same for stdin, so a file on a server is
  checked without its value crossing into the session:
  `ssh host 'sudo cat /srv/app/.env' | secret-keys -`. A GitLab
  `/variables` response is shown as key, scope, protected and masked;
- `secret-keys --env` — the current environment.

`fp=` is an HMAC-SHA256 under a key generated once in
`~/.config/secret-keys/salt` (mode 0600, refused to the assistant). Equal values
give equal fingerprints, so "is the server's token the one in the vault?" and
"did the rotation really change it?" are answered without seeing either. A
plain hash would not do: a short password is recovered from its SHA-256 by
brute force.

`secret-keys` lives in `bin/`; the refusals give its full path. To call it by
name, link it onto your PATH: `ln -s "$PWD/bin/secret-keys" ~/.local/bin/`.

## Which paths are secret

Built in: `.env*` and `*.env` (but not `*.example`, `*.sample`, `test.env`),
`secrets/`, `*.token`, `*.pem`, `*.key`, `*.tfstate`, private SSH keys and
`~/.ssh/` (but not `config`, `known_hosts`, `*.pub`), `~/.claude.json`, the
gh/glab/terraform/aws/docker/kube credential files, `.netrc`, `.pgpass`.

Paths particular to one machine go into `~/.config/secret-guard/paths`, one
Python regex per line, so they are never published with the plugin:

```
# an ansible inventory
(^|/)(envs|ci-envs)(/|$)
(^|/)\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/(?!known_hosts$)[^/]+
```

## Limits

It reads the command's text; it is not a sandbox. A determined way of reading a
file it does not recognise will get through, and the warning after the fact
is the backstop. A crash in the guard refuses the call rather than letting it
through. `/hooks` shows and disables it.

## Tests

`python3 -m unittest discover -s tests` — stdlib only.
