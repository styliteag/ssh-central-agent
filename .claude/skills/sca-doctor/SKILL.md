---
name: sca-doctor
description: Diagnose a broken SCA connection or agent chain — stale sockets, dead forwarders, missing keys, wrong jump level, double passphrase prompts. Use when sca cannot connect, ssh-add shows no keys, "Cannot determine security level" appears, or sockets misbehave. Read-only diagnosis first; proposes fixes but never kills processes or deletes sockets without explicit consent.
---

# SCA Doctor

Diagnose the SCA agent chain from symptom to fix. **Phase 1 is strictly
read-only.** Every repair command that kills a process, deletes a socket, or
opens a new SSH connection is proposed to the user, never executed silently —
live SSH sessions may depend on these sockets.

## The chain you are debugging

```
[local agent / temp agent]───┐
                             ├──> agentmux ──> ~/.ssh/scadev-mux.sock ──> ssh (IdentityAgent)
[ssh -L forwarder to sca-key]┴──> ~/.ssh/scadev-agent.sock
        (runs remote command "ragent", forwards /home/<user>/yubikey-agent.sock)
```

A working setup shows: both sockets exist, `ssh-add -l` succeeds against both,
one `ssh … ragent …` process and one `sshagentmux.py`/spawned mux process
running.

## Phase 1 — Gather state (read-only, run all)

```bash
env | grep -E 'SSH_AUTH_SOCK|SCA_|MUX_|LOCAL_SSH|ORG_SSH' | sort
ls -la ~/.ssh/scadev-* 2>/dev/null
readlink ~/.ssh/scadev-mux.sock 2>/dev/null          # mux sock is usually a symlink
for S in ~/.ssh/scadev-agent.sock ~/.ssh/scadev-mux.sock "$SSH_AUTH_SOCK"; do
  echo "== $S"; SSH_AUTH_SOCK="$S" ssh-add -l 2>&1
done
pgrep -fl " ragent " ; pgrep -fl "sshagentmux"
cat ~/.ssh/sca/.sca-jump-level 2>/dev/null
grep -n '^Include' ~/.ssh/config
ssh -G sca-key | grep -E '^(user|hostname|port|identityagent|identityfile) '
ssh -G jump 2>/dev/null | grep -E '^(hostname|port) '   # resolves only after alias patching
```

Note: `ssh -G` never connects — always safe. `ssh sca-key groups` DOES
connect — consent required.

## Phase 2 — Match symptom to cause

| Finding | Cause | Fix (propose, don't run) |
|---|---|---|
| Mux socket exists, `ssh-add -l` against it fails | Mux process died; socket/symlink stale | Remove stale mux socket, rerun `sca` (it rebuilds mux from working remote socket) |
| Remote socket works, mux missing/broken | Only the mux layer is down | Rerun `sca` — `use_existing_connection()` rebuilds mux without new SSH connection |
| Neither socket answers, no ` ragent ` process | Forwarder dead (network drop, laptop sleep) | Rerun `sca` for a fresh connection; `sca --wait` for auto-restart monitoring |
| ` ragent ` process runs but remote socket dead | Half-dead forwarder | `kill <pid>` of that specific forwarder (consent!), then rerun `sca` |
| "Cannot determine security level" | `sca-key` unreachable, or no usable local key for the initial hop | Check `ssh -G sca-key` (host/port/IdentityFile), check local agent has a key, check `MY_SSH_KEY`/`my_ssh_key` in `localvars.yml` |
| Passphrase prompted twice | Temp agent not reused for level check + forwarder (regression of commits 4da8/c64d) | Bug in `sca/` — inspect `validate_local_agent`/`determine_security_level` call order; do not shell-work around it |
| `ssh jump` / `sca-jump` does not resolve | `config_single` regenerated but aliases not re-patched yet | Run `sca` once (consent) — `patch_jump_aliases()` triggers when `config_single` is newer than `.sca-jump-level` |
| Wrong/lowered level | `LEVEL` env var, `-l` flag, or stale `.sca-jump-level` | Show current values; level can only be lowered, never raised, by `-l` |
| Socket path printed with literal `~` | Path-expansion bug at some boundary | Find the callsite missing `expand_path()`; this is a known bug class |
| `ssh-add -l` → "error fetching identities" on local socket | Local agent gone (reboot, agent restart) | User restarts agent or lets `sca` build a temp agent from the identity file |
| Keys listed but auth still fails on target host | Wrong agent selected for that alias suffix | `ssh -G <host> \| grep identityagent` — compare against the `_local`/`_remote`/`_mux`/`_org` suffix rules in `config_single` |
| Duplicate SCA_SUBSHELL blocks / weird prompt | `blockinfile` markers duplicated in `.zshrc`/`.bashrc` | Show the duplicate block; let the user delete one |

## Phase 3 — Report

Deliver: (1) one-line verdict of which chain link is broken, (2) the evidence
lines that prove it, (3) the exact repair commands for the user to approve.
If everything checks out but the user still sees failures, propose
`DEBUG=1 sca -d …` (consent — it connects) and reading the mux log output
(`SSH: Found … key`, `SSH: Sign: …` lines identify which agent served which
key).

## Hard rules

- Never run `sca --kill` or broad `pkill` yourself — they kill ALL SCA
  processes of the user, including healthy sessions.
- Never delete `~/.ssh/scadev-*` without consent.
- Never "test" by opening real connections without consent.
- If the diagnosis points at server-side behavior (`ragent`, level groups
  output), stop and report — that code is not in this repo.
