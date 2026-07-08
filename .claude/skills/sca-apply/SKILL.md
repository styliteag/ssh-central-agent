---
name: sca-apply
description: Safely apply SCA configuration changes — SSH config templates, localvars.yml, host entries — with regeneration and verification. Use when editing templates/*.j2, adding or changing hosts, changing localvars, or when the user says "apply config", "regenerate", "run the playbook", "add host".
---

# SCA Apply — config change pipeline

Every config change here falls into exactly one class. Classify first; the
classes have different blast radii.

## Step 0 — Classify the change

| Class | Files | Needs playbook? | Blast radius |
|---|---|---|---|
| **A: Host entry** | `hosts/*` | **No** — live-included by `~/.ssh/config` | One host |
| **B: SSH config** | `templates/config_single.j2`, `templates/config_match.j2`, `localvars.yml` | Yes | Every SSH connection of the user |
| **C: Entrypoints** | `templates/sca.py.j2`, `templates/sca.sh.j2`, `playbook.yml` | Yes | `sca` command itself + `/opt/homebrew/bin` symlinks + rc-files |

Never edit `config_single`, `config_match`, `config`, `sca.py`, `sca.sh`
directly — they are generated and will be overwritten.

## Class A: Host entry (no playbook needed)

1. Pick the right file in `hosts/` (customer/group; `kunden` is the default
   catch-all). New entries go via `./addhost [file] name [ip] [port] [user]`
   or manually in this exact shape:

   ```
   #
   # Autoadded <file> <name> <ip> <port> <user>
   Host <name> <name>_* sca-<name> sca-<name>_*
       user <user>
       hostname <ip-or-fqdn>
       port <port>
       Tag sca-host
       Tag File-<file>
       #ProxyJump none
   ```

   The `<name>_*` wildcard is what makes the `_my`/`_local`/`_mux`/`_direct`
   suffix aliases work — never drop it.

2. Verify immediately (live include, no regeneration):
   ```bash
   ssh -G <name> | grep -E '^(user|hostname|port|identityagent) '
   python3 -m sca --find <name>        # from repo root
   ```
3. Special needs go on the host, mirroring existing examples: legacy crypto
   (`HostKeyAlgorithms +ssh-rsa`, see `hosts/stylite` ns01), direct routing
   (`#ProxyJump none` uncommented / `Tag NoJump`).
4. `hosts/` is a private repo/directory — commits there follow its own flow,
   never this repo's.

## Class B/C: Template or localvars change (playbook required)

1. **Edit the template**, preserving contract strings: every
   `L<n>-sca-magic-jump` alias, `SendEnv STY_*`, `SetEnv STY_LOCALUSER`,
   `Tag sca-jmp`/`sca-key` lines. `patch_jump_aliases()` in `sca/config.py`
   regex-targets `-sca-magic-jump` — if it's gone, level aliasing silently
   dies.
2. **Snapshot** current generated files to the scratchpad:
   ```bash
   cp config_single config_match sca.py sca.sh "$SCRATCHPAD/" 2>/dev/null
   ```
3. **Dry-run first** and show the diff to the user:
   ```bash
   ansible-playbook playbook.yml --check --diff
   ```
4. **Real run only with explicit consent** — say what it touches beyond the
   repo: `~/.ssh/config` (Include lines), `~/.zshrc`, `~/.bashrc`
   (blockinfile), `<bindir>/sca` symlinks.
5. **Post-verify** (all read-only):
   ```bash
   diff "$SCRATCHPAD/config_single" config_single      # change is what you expected, nothing more
   grep -n '^Include' ~/.ssh/config                    # order: config_single → hosts/* → config_match
   ssh -G sca-key  | grep -E '^(user|hostname|port|identityfile) '
   ssh -G <sample-host> | grep -E '^(user|hostname|port|identityagent|proxycommand) '
   grep -c 'sca-magic-jump' config_single              # markers survived
   ```
6. **Warn about the alias gap**: right after regeneration, `config_single`
   has bare `L<n>-sca-magic-jump` lines — the `jump`/`sca-jump` aliases are
   only re-added the next time `sca` runs (mtime of `config_single` >
   `.sca-jump-level` triggers the patch). Tell the user `ssh jump` won't
   resolve until then.
7. For Class C additionally: `python3 -m sca --help` and `./sca.sh --help`
   still work; the `sca` symlink in bindir still points into this repo.

## Rollback

- Generated files: restore from the scratchpad snapshot (or `*.bak`, which
  `patch_jump_aliases` maintains) — then fix the template, because the next
  playbook run reapplies the mistake.
- `~/.ssh/config` / rc-files: the playbook edits are line/block-based; show
  the user the exact lines before removing anything there manually.

## Hard rules

- Playbook never runs without consent; `--check --diff` always runs before
  the real thing.
- Template edit without post-regeneration verification is not "done" — it's
  "staged". Say so in your report.
- Nothing from `hosts/`, `localvars.yml`, or generated files gets committed
  to this repo.
