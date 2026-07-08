# CLAUDE.md — SCA Operating Manual

This file is the operating manual for working in this repository. Where it
conflicts with the global `~/.claude/CLAUDE.md`, **this file wins** (notably:
no TDD here, no test scaffolding, module-level globals are accepted style).
Architecture deep-dive lives in `AGENTS.md` — read it before touching the
multiplexer or connection logic. This file tells you how to *work*, not how
the system works.

## 60-second model of the system

`sca` builds this chain and everything in the repo serves it:

```
local agent OR identity file (temp agent)
        │
        ├──> ssh -a -F config_single sca-key "groups"      → security level (0-3)
        ├──> ssh -a -L ~/.ssh/scadev-agent.sock:/home/<user>/yubikey-agent.sock
        │        sca-key "ragent <args>"                   → remote YubiKey agent, forwarded
        └──> sca/agentmux.py merges local + remote sockets → ~/.ssh/scadev-mux.sock
                                                              (what SSH actually uses via IdentityAgent)
```

This is **live production tooling**: the sockets under `~/.ssh/scadev-*` may
belong to a running session of the user, and the repo directory itself is
inside `~/.ssh`. Treat every state-changing command accordingly.

## Source vs. generated — check before every edit

| File | Status | To change it, edit… |
|---|---|---|
| `sca/` package | **source** (primary implementation) | directly |
| `sshagentmux.py` | **source** (standalone twin of `sca/agentmux.py`) | directly, mirror twin |
| `functions.sh` | **source** (legacy bash implementation) | directly, only for user-visible parity |
| `templates/*.j2` | **source** | directly |
| `playbook.yml`, `addhost` | **source** | directly |
| `hosts/*` | **private data**, live-included by `~/.ssh/config` | directly; never commit to this repo |
| `localvars.yml` | **local config**, gitignored | directly; never commit |
| `sca.py`, `sca.sh` | **generated** from `templates/sca.py.j2` / `sca.sh.j2` | the template |
| `config_single`, `config_match`, `config` | **generated** from `templates/config_*.j2` | the template |
| `*.bak`, `.sca-jump-level` | runtime artifacts | never |

Rule of thumb: if a path appears as `dest:` in `playbook.yml` or in
`.gitignore`, it is generated or private — find the template or leave it alone.
Extra twist: `config_single` is **also patched at runtime** by
`sca/config.py:patch_jump_aliases()`, so even reading it tells you less than
reading its template.

## Conventions

Existing (followed in this repo):

- **Python stdlib only.** No pip dependencies at runtime (the venv holds only
  ruff). Floor is Python 3.12 (`NamedTemporaryFile(delete_on_close=…)`).
- **All human output goes to stderr** via `sca/logging_utils.py` (`log_info`,
  `log_error`, `log_success`, `log_warn`, `log_debug`, `log_note`). stdout is
  a machine protocol: `sca -e` output is eval'd by the user's shell.
- **CLI options flow through environment variables** from `cli.py` to
  `__main__.py` (`SSH_MODE`, `SUBSHELL_MODE`, `KEY`, `LEVEL`, `REVERSE`,
  `WAIT`, `SSH_ARGS`, `DEBUG`). Keep that contract; the shell integration in
  `.zshrc`/`.bashrc` reads `SCA_SUBSHELL`, `MUX_SSH_AUTH_SOCK`,
  `SCA_SSH_AUTH_SOCK`, `LOCAL_SSH_AUTH_SOCK`.
- **Help is hand-rendered** in `cli.py:_print_help()` (argparse help is
  disabled) with manual column alignment (`COL = 48`, visible-length math for
  ANSI colors). The bash version has its own `print_help()` in `functions.sh`.
- **Unknown CLI args are SSH args** (`parse_known_args`); `sca -- -p9922 host`
  must always pass through untouched.
- **Host entries** follow the `addhost` pattern:
  `Host <name> <name>_* sca-<name> sca-<name>_*` + `Tag sca-host` +
  `Tag File-<file>`. Suffix aliases (`_my`, `_local`, `_org`, `_mux`,
  `_direct`, `_jump`, `_nojump`, `_proxy`, `_noproxy`) are wildcard rules in
  `config_single.j2` — the suffix itself is the feature.
- **Commits**: short imperative summary, capitalized, no type prefix, no
  trailing period, no Co-Authored-By (matches repo history: "Fix help comment
  color and alignment").
- Python and bash implementations stay in **user-visible parity** (flags,
  help text, messages). Internal refactors do not need porting.

Added (follow these too):

- **Expand paths at every boundary.** Anything handed to `ssh -L`, socket
  syscalls, or path comparison goes through `platform_utils.expand_path()`
  first. Half the bug-fix history of this repo is unexpanded `~`.
- **Name the twin in the commit.** Any behavior change states either that the
  counterpart (`functions.sh`, or `sshagentmux.py` ↔ `sca/agentmux.py`) was
  updated, or why it doesn't apply.
- **Verify config work with `ssh -G`**, never by eyeballing the file. `ssh -G
  <host>` resolves the full include/match chain without connecting.
- **ruff on what you touched**: `.venv/bin/ruff check <changed files>` — no
  new findings.
- **Never write outside the repo** except the scratchpad. `~/.ssh/config` and
  rc files belong to the playbook, not to you.

## Mistakes you will make here — named, with the rule that prevents each

1. **The generated-file trap.** You edit `config_single` or `sca.py` because
   that's where the text is; the next `ansible-playbook` run silently erases
   your work. *Rule: consult the table above before every edit; edit the
   `.j2`, tell the user regeneration is needed.*

2. **The half-ported fix.** You fix the sign-request handling in
   `sca/agentmux.py` and leave `sshagentmux.py` broken (or fix a flag in
   `cli.py` and leave `functions.sh` announcing the old one). They are ~85%
   identical twins. *Rule: after any behavior change, grep the counterpart
   for the same symbol; mirror or state why not.*

3. **The stdout leak.** You add a friendly `print()` in the connection flow;
   `eval $(sca -e --key=local)` now executes your message as shell code.
   *Rule: `logging_utils.log_*` only; bare `print()` to stdout is allowed
   solely in the existing `-e` env-output and `--list`/`--find` display paths.*

4. **The eager playbook run.** You run `ansible-playbook playbook.yml` to
   "apply" a template change; it also rewrites `~/.ssh/config`, `~/.zshrc`,
   `~/.bashrc` and symlinks into `/opt/homebrew/bin`. *Rule: never run the
   playbook unprompted; propose it, offer `--check --diff` first.*

5. **The killer cleanup.** While debugging you run `sca --kill`, `pkill -f
   ragent`, or delete `~/.ssh/scadev-*` sockets — and sever the user's live
   SSH sessions. *Rule: diagnosis is read-only; every kill/delete needs
   explicit user consent in this conversation.*

6. **The magic-marker rename.** You "clean up" `L1-sca-magic-jump`, `STY_*`,
   the `ragent` command word, `/home/<user>/yubikey-agent.sock`, or the
   `sca-host`/`File-*` tags. Each is a wire contract:
   `config.py:patch_jump_aliases()` regex-matches `-sca-magic-jump`; the
   backend still reads `STY_*` (see commit 504c4d9); process cleanup pattern-
   matches `" ragent "`. *Rule: treat these strings as API — grep all
   consumers (`sca/`, `functions.sh`, `templates/`) before touching, and
   escalate first.*

7. **The secrets commit.** `git add -A` sweeps in `hosts/` (customer
   hostnames, IPs, ports), `localvars.yml`, `config*`, `*.bak`. *Rule: stage
   files by explicit path only; before any commit, confirm
   `git status --porcelain` shows nothing from the table's
   private/generated rows; never use `git add -A` or `-f`.*

8. **The dependency import.** You reach for `paramiko`/`click`/`rich`.
   *Rule: stdlib only. If stdlib genuinely can't do it, escalate.*

9. **The pytest scaffold.** The global CLAUDE.md demands TDD; you create
   `tests/`. This repo deliberately removed its test suite (commit c4baf40) —
   it is exercised against live SSH infrastructure. *Rule: no test
   infrastructure unless explicitly requested; use the verification
   checklists below instead.*

10. **The short-flag collision.** You add `-p` or another short option;
    `parse_known_args` now steals it from SSH and `sca -- -p9922 host`
    changes meaning. *Rule: new flags are long-form only; after any CLI
    change, re-check the passthrough examples in README.md.*

11. **The tilde socket.** You pass `~/.ssh/scadev-agent.sock` unexpanded to
    `ssh -L` or compare an expanded path with an unexpanded one and conclude
    "different socket". *Rule: `expand_path()` before use or comparison —
    both sides.*

12. **The helpful refactor.** You globalize immutability, split
    `__main__.py`, or rename the env-var plumbing to "clean architecture".
    The env-var contract is load-bearing (bash twin, shell integration,
    generated shims). *Rule: match existing style; structural refactors only
    on explicit request.*

## Quality bar per deliverable — checkable, not adjectives

**Python change** (done when all boxes tick):
- [ ] `python3 -m py_compile <changed .py files>` exits 0
- [ ] `.venv/bin/ruff check <changed files>` reports no findings introduced by the change
- [ ] Type annotations on every new/changed signature
- [ ] No `print()` to stdout outside the allowed paths (mistake 3)
- [ ] Every path that reaches `ssh`/sockets went through `expand_path()`
- [ ] No imports outside the stdlib
- [ ] From repo root: `python3 -m sca --help` and `python3 -m sca --version` still exit 0
- [ ] Twin statement exists (mirrored, or "n/a because …")

**CLI surface change** (flags, help, messages) — Python checklist plus:
- [ ] `cli.py:_print_help()` updated, columns still aligned (check the `ex()` visible-length arguments)
- [ ] `functions.sh`: `parse_arguments()` + `print_help()` mirrored
- [ ] `README.md` (Command Options + examples) and `AGENTS.md` (Common Commands) updated
- [ ] Passthrough still documented and coherent: `sca --key=remote -- -p9922 root@host hostname`

**Template / config change**:
- [ ] Edit landed in `templates/*.j2` (not in a generated file)
- [ ] All `-sca-magic-jump` markers and `STY_*` lines preserved unless explicitly changing them
- [ ] User informed that `ansible-playbook playbook.yml` must run; `--check --diff` output shown first if run at all
- [ ] After regeneration: `ssh -G sca-key` and one `ssh -G <real host>` show expected `user`/`hostname`/`port`/`identityagent`
- [ ] `grep '^Include' ~/.ssh/config` still shows order: `config_single` → `hosts/*` → `config_match`

**Host entry** (in `hosts/`):
- [ ] Correct group file chosen (customer/org name; default `kunden`)
- [ ] Host line matches pattern `Host <name> <name>_* sca-<name> sca-<name>_*`
- [ ] `Tag sca-host` and `Tag File-<file>` present
- [ ] Style matches neighbors in that file (lowercase `user`/`hostname`/`port`)
- [ ] `ssh -G <name> | grep -E '^(user|hostname|port) '` returns the intended values (no playbook run needed — `hosts/*` is live-included)
- [ ] `python3 -m sca --find <name>` (from repo root) displays the block
- [ ] Not staged in this repo's git

**Commit**:
- [ ] Only when the user asked for a commit
- [ ] Message: imperative, capitalized, no type prefix, no Co-Authored-By
- [ ] `git status --porcelain` shows only intended files; nothing private/generated
- [ ] Behavior changes name their twin (mistake 2)

## Verification commands

Safe, run freely (read-only or self-terminating):
```
python3 -m py_compile …            .venv/bin/ruff check …
python3 -m sca --help | --version  python3 -m sca --list | --find <h>   (repo root)
ssh -G <host>                      git status / diff / log
ls -la ~/.ssh/scadev-*             grep '^Include' ~/.ssh/config
pgrep -fl " ragent " ; pgrep -fl sshagentmux.py
SSH_AUTH_SOCK=<sock> ssh-add -l    (read-only agent probe)
```

Only with explicit consent (state-changing or opens real connections):
`ansible-playbook playbook.yml` (even more so without `--check`), any `sca`
invocation that connects (`sca`, `sca <host>`, `--shell`, `--wait`, `-e` when
no sockets exist yet), `sca --kill`, `pkill`, deleting sockets, `git commit`,
`git push`, `./addhost` (appends to private hosts files).

## When uncertain — exact escalation rules

Proceed without asking when: the action is in the safe list above, or it edits
source files the user's request clearly covers, or it is reversible with
`git checkout` and touches nothing outside the repo.

Ask first (one concrete question, then act) when any of these is true:
1. The next command is in the consent list above.
2. The change touches a contract string: `STY_*`, `-sca-magic-jump`,
   `" ragent "`, `yubikey-agent.sock`, `scadev-agent.sock`/`scadev-mux.sock`
   defaults, tag names, `SCA_*`/`MUX_*`/`ORG_*` env names.
3. You would edit `functions.sh` for something the user only asked about the
   Python version (or vice versa) and the mirror is more than mechanical.
4. You cannot determine whether a file is generated → assume generated, ask
   while pointing at the template you found.
5. The fix seems to require changing behavior on the server side (`ragent`
   arguments, level detection output format) — that code is not in this repo.

Stop and report instead of acting when: a private value (customer host/IP,
key material) would land in a tracked file or commit; a command would kill
processes or delete sockets you did not create this session; you found what
looks like a leaked secret (report it, do not rotate or rewrite history
yourself); tests/verification failed (report the exact output — never commit
on top of a failure).

Default when torn between two designs: the smaller diff that matches the
neighboring code. This repo optimizes for a working SSH chain, not for
architectural purity.
