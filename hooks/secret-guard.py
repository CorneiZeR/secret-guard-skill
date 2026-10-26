#!/usr/bin/env python3
"""Claude Code hook: keep secret values out of the transcript.

PreToolUse (Bash, Read, Grep): refuses reading a secret file or printing a
secret variable. Names are fine: `secret-keys` shows a file's keys, each
value's length and a keyed fingerprint, never the value.
PostToolUse (Bash, Read, Grep): if a well-known token shape reached the output
anyway, tells the user which one, so it can be rotated.
"""

import json
import os
import re
import shlex
import shutil
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from secret_paths import is_secret  # noqa: E402

KEYS = "secret-keys"  # recognised by name, wherever it is run from
KEYS_RUN = shutil.which(KEYS) or os.path.join(os.path.dirname(HERE), "bin", KEYS)
HINT = (
    f"Names only: `{KEYS_RUN} <file>` lists its keys with each value's length and "
    "fingerprint (fp=, equal values give equal fp); "
    f"`<command> | {KEYS_RUN} -` does the same for JSON or KEY=value on stdin; "
    f"`{KEYS_RUN} --env` lists the environment. If the value itself is needed, "
    "ask the user to run the command with `!`."
)

SECRET_VAR = re.compile(
    r"TOKEN|SECRET|PASSW(OR)?D|PASS$|API_?KEY|PRIVATE_?KEY|_KEY$|^KEY$|CREDENTIAL|"
    r"AUTH|DSN|DATABASE_URL|COOKIE|WEBHOOK",
    re.I,
)
VAR_REF = re.compile(r"\$\{?([A-Za-z_][A-Za-z0-9_]*)")

# Verbs that may name a secret path without showing what is inside it.
SAFE = {
    "ls", "stat", "test", "[", "[[", "wc", "file", "chmod", "chown", "chgrp",
    "mkdir", "touch", "rm", "mv", "cp", "install", "scp", "rsync", "ln",
    "shasum", "sha256sum", "md5", "md5sum", "cmp", "find", "du", "realpath",
    "dirname", "basename", "readlink", "cd", "pushd", "trash", "ssh-keygen",
    "ssh-add", "ssh", "sudo", "git", "echo", "printf", KEYS,
    ".", "source",  # loads values into the environment; xtrace is refused separately
}
XTRACE = re.compile(r"\bset\s+(-[a-z]*[xv][a-z]*\b|-o\s+(xtrace|verbose))|\b(ba|z|da)?sh\s+-[a-z]*[xv]")
# Wrappers whose arguments are another command.
WRAPPERS = {"sudo", "env", "timeout", "nice", "nohup", "command", "exec", "time", "xargs"}
ARG_FLAGS = {
    "sudo": {"-u", "-g", "-C", "-h", "-p", "-U", "-r", "-t", "-D"},
    "env": {"-u", "-C", "-S"},
    "timeout": {"-s", "-k"},
    "nice": {"-n"},
    "xargs": {"-I", "-n", "-P", "-L", "-d", "-E", "-s"},
    "ssh": {"-i", "-p", "-l", "-o", "-F", "-J", "-L", "-R", "-D", "-E", "-b", "-c", "-e",
            "-m", "-O", "-Q", "-S", "-w", "-W", "-B"},
}
PRINTERS = {"echo", "printf", "print", "logger", "tee", "cat"}
GIT_SAFE = {"status", "check-ignore", "ls-files", "add", "rm", "mv", "restore", "stash", "commit"}
# `docker <object> inspect` for objects that hold no environment: a registry's
# manifest list, a network, a volume. `docker inspect`, `container inspect` and
# `image inspect` stay refused — a container's and an image's Env is there.
DOCKER_INSPECT_SAFE = {"manifest", "network", "volume", "buildx"}

COMPOSE_CONFIG_SAFE = {"--hash", "--services", "--volumes", "--images", "-q", "--quiet",
                       "--profiles", "--networks", "--environment"}

LEAK_SHAPES = [
    ("GitLab token", r"\bgl(pat|dt|rt|ptt|ft|cbt|soat|oas)-[A-Za-z0-9_\-]{20,}"),
    ("GitHub token", r"\b(gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{30,})"),
    ("Anthropic key", r"\bsk-ant-[A-Za-z0-9_\-]{20,}"),
    ("OpenAI key", r"\bsk-(proj-)?[A-Za-z0-9]{32,}"),
    ("AWS key", r"\bAKIA[0-9A-Z]{16}\b"),
    ("Slack token", r"\bxox[abpors]-[A-Za-z0-9\-]{10,}"),
    ("private key", r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
    ("Stripe key", r"\b[sr]k_live_[A-Za-z0-9]{20,}"),
]


class Deny(Exception):
    pass


HEREDOC = re.compile(r"<<-?\s*(['\"]?)([A-Za-z_][A-Za-z0-9_]*)\1")


def drop_heredoc_bodies(cmd):
    """A here-document's body is data for its command, not commands — unless a shell reads it."""
    lines, out, i = cmd.split("\n"), [], 0
    while i < len(lines):
        line = lines[i]
        out.append(line)
        i += 1
        match = HEREDOC.search(line)
        if not match:
            continue
        word = match.group(2)
        body = []
        while i < len(lines) and lines[i].strip() != word:
            body.append(lines[i])
            i += 1
        i += 1  # the closing word
        readers = {os.path.basename(w) for w in line[: match.start()].split()}
        if readers & SH_SHELLS:
            out.extend(body)  # `sh <<EOF` runs its body: commands, checked as such
        elif readers & SHELLS:
            # `python3 - <<EOF`: code, kept on its command's line so a secret path
            # in it is still a secret path read by that interpreter. In python
            # and node a backtick or `$(` is text, not a command — a string that
            # merely mentions one is not running it — so neither is read as a
            # substitution there. Perl and ruby run backticks, and keep them.
            text = " ".join(body)
            if readers & NO_SUBST:
                text = text.replace("`", "'").replace("$(", "( ")
            out[-1] = line + " " + shlex.quote(text)
    return "\n".join(out)


def words_of(cmd):
    cmd = drop_heredoc_bodies(cmd.replace("\\\n", " "))  # a continued line is one command, not two
    lex = shlex.shlex(cmd, posix=True, punctuation_chars=";&|<>()`\n")
    lex.whitespace = " \t\r"  # a newline outside quotes separates commands, like `;`
    lex.whitespace_split = True
    lex.commenters = ""
    try:
        return list(lex)
    except ValueError:
        return cmd.split()


def pipelines(tokens):
    """[[stage, ...], ...]: sequences split on ; && || newline, stages on |."""
    seqs, stages, stage = [], [], []
    for t in tokens:
        if t in ("|", "|&"):
            stages.append(stage)
            stage = []
        elif t and set(t) <= set(";&|()`\n"):
            stages.append(stage)
            seqs.append(stages)
            stages, stage = [], []
        else:
            stage.append(t)
    stages.append(stage)
    seqs.append(stages)
    return [[s for s in p if s] for p in seqs if any(p)]


def verb_of(stage):
    """The command a stage runs, past sudo/env/timeout and VAR=value."""
    i, wrapper = 0, ""
    while i < len(stage):
        w = stage[i]
        base = os.path.basename(w)
        if re.match(r"^[A-Za-z_][A-Za-z0-9_]*=", w) or w in ("<", ">", ">>", "2>"):
            i += 1
        elif base in WRAPPERS:
            wrapper = base
            i += 1
            while i < len(stage) and stage[i].startswith("-"):
                i += 2 if stage[i] in ARG_FLAGS.get(base, ()) else 1
            if base == "timeout" and i < len(stage) and re.match(r"^\d", stage[i]):
                i += 1
        else:
            return base, stage[i + 1:]
    return wrapper, []  # a bare `env` or `sudo` with nothing after it


def path_candidates(word):
    word = SUBST.sub("", word)  # a $(...) is checked as a command of its own
    if " " in word or "\n" in word:
        yield word  # prose or a quoted path with spaces: only the whole of it
        return
    for part in re.split(r"[=:,'\"()]", word):
        part = part.lstrip("@<")
        if part:
            yield part


def mentions_secret(stage):
    for w in stage:
        if any(is_secret(p) for p in path_candidates(w)):
            return w
    return None


PATTERN_FLAGS = {  # flags whose argument is a pattern or a program, not a file
    "grep": {"-e", "--regexp"}, "egrep": {"-e"}, "fgrep": {"-e"}, "rg": {"-e", "--regexp"},
    "sed": {"-e", "--expression"}, "awk": {"-v", "-F"}, "gawk": {"-v", "-F"},
    "jq": {"--indent"},
}
# jq's two-argument flags: `--arg name value` names no file, `--rawfile name f` reads f.
JQ_PAIRS = {"--arg": False, "--argjson": False, "--slurpfile": True, "--rawfile": True}


def drop_pattern(verb, stage):
    """A pattern is text, not a file: `grep -n envs/ justfile` reads justfile only."""
    if verb not in PATTERN_FLAGS:
        return stage
    out, i, start = [], 0, stage.index(next(w for w in stage if os.path.basename(w) == verb))
    rest, have_pattern = stage[start + 1:], False
    while i < len(rest):
        w = rest[i]
        if not w:  # `sed -i ''`: the empty backup suffix
            i += 1
            continue
        if verb == "jq" and w in JQ_PAIRS and i + 2 < len(rest):
            if JQ_PAIRS[w]:
                out.append(rest[i + 2])
            i += 3
            continue
        if w in PATTERN_FLAGS[verb] | {"-f", "--file"} and i + 1 < len(rest):
            have_pattern = have_pattern or w in ("-e", "--regexp", "--expression")
            if w in ("-f", "--file"):
                out.append(rest[i + 1])  # a patterns file or a script is read
            i += 2
            continue
        if w.startswith("-e") and len(w) > 2:
            have_pattern = True
        elif not w.startswith("-") and not have_pattern:
            have_pattern = True  # the first operand is the pattern
        else:
            out.append(w)
        i += 1
    return stage[:start + 1] + out


# `-c` runs its argument only after one of these: `jq -c` is compact output.
SH_SHELLS = {"sh", "bash", "zsh", "dash", "ksh", "fish", "su"}
SHELLS = SH_SHELLS | {"python", "python3", "perl", "ruby", "node"}
# Interpreters for which a backtick or `$(...)` in the code is not a command.
NO_SUBST = {"python", "python3", "node"}

SUBST = re.compile(r"\$\(([^()]*)\)|`([^`]*)`")


def skip_flags(verb, args):
    i = 0
    while i < len(args) and args[i].startswith("-"):
        i += 2 if args[i] in ARG_FLAGS.get(verb, ()) else 1
    return args[i:]


def check_env_dump(verb, args, stage, feeds_process):
    flags_only = all(a.startswith("-") for a in args)
    if verb == "env" and flags_only:
        raise Deny("`env` prints every variable with its value")
    if verb == "printenv" and (flags_only or any(SECRET_VAR.search(a) for a in args)):
        raise Deny("`printenv` prints values")
    if verb in ("set", "export", "declare", "typeset") and (
        not args or all(a in ("-p", "-x", "-px", "-xp", "-g") for a in args)
    ):
        raise Deny(f"`{verb}` without arguments prints variables with their values")
    for i, w in enumerate(stage):  # `ssh host env`, `docker exec c printenv`
        if os.path.basename(w) in ("env", "printenv") and all(
            a.startswith("-") for a in stage[i + 1:]
        ) and i > 0:
            raise Deny(f"`{w}` at the end of a remote or container command prints values")
    if verb in PRINTERS and not feeds_process and not {">", ">>"} & set(stage):
        for w in stage:
            for name in VAR_REF.findall(w):
                if SECRET_VAR.search(name) and "${#" + name not in w:
                    raise Deny(f"`{verb}` would print ${name}; `${{#{name}}}` gives its length")


def check_tools(verb, args, piped_to_keys):
    a = " ".join(args)
    if verb in ("gh", "glab") and re.search(r"\bauth\s+(token|status\b.*(-t|--show-token))", a):
        raise Deny(f"`{verb} auth` with a token flag prints the token")
    if verb == "glab" and re.search(r"\bconfig\s+get\s+\S*token", a):
        raise Deny("`glab config get token` prints the token")
    if verb in ("glab", "curl", "http", "xh") and re.search(r"/variables\b|\bvariable\s+(get|list|export)", a):
        if not piped_to_keys:
            raise Deny("CI/CD variables come back with their values; pipe them to `secret-keys -`")
    if verb in ("terraform", "tofu"):
        if re.search(r"\boutput\b.*(-raw|-json)|\bstate\s+pull\b|\bshow\b.*-json|\bconsole\b", a):
            raise Deny(f"`{verb}` would print sensitive values or the whole state")
    if verb == "docker" or verb == "docker-compose":
        sub = next((w for w in args if not w.startswith("-")), "")
        if (re.search(r"\binspect\b", a) and not re.search(r"(-f|--format)[ =]", a)
                and sub not in DOCKER_INSPECT_SAFE):
            raise Deny("`docker inspect` prints the container's environment; use --format")
        if re.search(r"(-f|--format)[ =]\S*Env", a):
            raise Deny("that --format prints the container's environment")
        if re.search(r"\bconfig\b", a) and (verb == "docker-compose" or re.search(r"\bcompose\b", a)):
            if not COMPOSE_CONFIG_SAFE & set(args):
                raise Deny("`docker compose config` prints the interpolated .env; "
                           "use --hash, --services, --volumes or --environment")
    if verb == "ansible-vault" and re.search(r"\bview\b|--output[ =]-", a):
        raise Deny("`ansible-vault` would print the decrypted file")
    if verb == "security" and re.search(r"find-\S+-password\b.*\s-[wg]\b", " " + a):
        raise Deny("`security ... -w` prints the keychain password")
    if verb == "bw" and re.search(r"\b(get|list)\b", a):
        raise Deny("Bitwarden would print the secret")
    if verb == "op" and re.search(r"\bread\b|--reveal", a):
        raise Deny("1Password would print the secret")
    if verb == "git" and re.search(r"\bcredential\s+fill\b", a):
        raise Deny("`git credential fill` prints the stored password")
    if verb == "kubectl" and re.search(r"\bsecrets?\b.*-o", a):
        raise Deny("`kubectl get secret -o` prints the secret")


def check_secret_path(verb, args, word, piped_to_keys):
    if not verb or (verb == "cat" and piped_to_keys):
        return  # `K=path` alone names the file; a $(...) in it is checked on its own
    if verb == "git":
        sub = next((x for x in args if not x.startswith("-")), "")
        if sub in GIT_SAFE or (
            sub in ("diff", "log", "show") and {"--stat", "--name-only", "--name-status", "--quiet"} & set(args)
        ):
            return
        raise Deny(f"`git {sub}` would show the contents of {word}")
    if verb in SAFE:
        return
    raise Deny(f"`{verb or '?'}` would read {word}, which holds secrets")


def analyze(cmd, piped_to_keys=False, depth=0):
    if depth > 4:
        return
    seqs = pipelines(words_of(cmd))
    for si, stages in enumerate(seqs):
        last_seq = si == len(seqs) - 1
        tail_is_keys = len(stages) > 1 and verb_of(stages[-1])[0] == KEYS
        for i, stage in enumerate(stages):
            final = i == len(stages) - 1
            to_keys = (tail_is_keys and i == len(stages) - 2) or (piped_to_keys and final and last_seq)
            verb, args = verb_of(stage)
            nxt = verb_of(stages[i + 1])[0] if not final else ""
            feeds_process = bool(nxt) and nxt not in PRINTERS | {"less", "more", "head", "tail"}
            if verb == "ssh":  # the remote command is the rest of the line
                remote = skip_flags("ssh", args)[1:]
                if remote:
                    analyze(" ".join(remote), to_keys, depth + 1)
            for j, w in enumerate(stage):  # sh -c '...', eval '...', "$(...)"
                prev = os.path.basename(stage[j - 1]) if j else ""
                shell_c = prev == "-c" and any(os.path.basename(x) in SHELLS for x in stage[:j - 1])
                if (shell_c or prev in ("eval", "watch")) and (" " in w or "\n" in w):
                    analyze(w, to_keys, depth + 1)
                for m in SUBST.finditer(w):
                    # `curl -H "Bearer $(cat f)"` hands the value to a process; echo would
                    # show it, and so would python or perl, whose code can print it. A
                    # shell's `-c` is checked as commands of its own, above.
                    interpreter = os.path.basename(verb) in SHELLS - SH_SHELLS
                    hands_off = bool(verb) and verb not in PRINTERS and not interpreter
                    analyze(m.group(1) or m.group(2) or "", hands_off, depth + 1)
            check_env_dump(verb, args, stage, feeds_process)
            check_tools(verb, args, to_keys)
            word = mentions_secret(drop_pattern(verb, stage))
            if word:
                check_secret_path(verb, args, word, to_keys)


def pre(tool, ti):
    if tool == "Read":
        p = ti.get("file_path", "")
        if is_secret(p):
            raise Deny(f"{p} holds secrets")
    elif tool == "Grep":
        if ti.get("output_mode", "files_with_matches") == "content":
            for key in ("path", "glob"):
                v = (ti.get(key) or "").replace("*", "x")
                if v and is_secret(v):
                    raise Deny(f"Grep with content on {ti.get(key)} would print secret values")
    elif tool == "Bash":
        cmd = ti.get("command", "")
        if XTRACE.search(cmd) and any(is_secret(p) for p in re.split(r"[\s'\";|&()=<>`]+", cmd)):
            raise Deny("xtrace (set -x / sh -x) next to a secret file prints every value it loads")
        analyze(cmd)


def post(tool, data):
    out = json.dumps(data.get("tool_response", ""))
    found = [name for name, rx in LEAK_SHAPES if re.search(rx, out)]
    if found:
        print(json.dumps({
            "systemMessage": f"secret-guard: the output of {tool} contains what looks like "
                             f"a {', '.join(found)}. If it is real, rotate it.",
            "hookSpecificOutput": {
                "hookEventName": "PostToolUse",
                "additionalContext": "A secret-shaped value appeared in that output. Do not "
                                     "repeat it, quote it, or write it anywhere; tell the user.",
            },
        }))


def main():
    data = json.load(sys.stdin)
    tool, ti = data.get("tool_name", ""), data.get("tool_input") or {}
    if data.get("hook_event_name") == "PostToolUse":
        post(tool, data)
        return
    try:
        pre(tool, ti)
    except Deny as e:
        reason = f"secret-guard: {e}. {HINT}"
    except Exception as e:  # a guard that crashes must not let the call through
        reason = f"secret-guard failed ({type(e).__name__}: {e}); refusing to be safe. {HINT}"
    else:
        return
    print(json.dumps({"hookSpecificOutput": {
        "hookEventName": "PreToolUse",
        "permissionDecision": "deny",
        "permissionDecisionReason": reason,
    }}))


if __name__ == "__main__":
    main()
