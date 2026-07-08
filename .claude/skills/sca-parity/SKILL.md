---
name: sca-parity
description: Check and mirror changes across SCA's parallel implementations — the Python package (sca/), the legacy bash version (functions.sh), the twin multiplexers (sshagentmux.py vs sca/agentmux.py), and the four help/doc surfaces. Use after any behavior change, before commits, or when the user says "sync ports", "check parity", "mirror to bash".
---

# SCA Parity — keep the twins honest

This repo maintains parallel implementations on purpose. Drift between them
is the single most expensive bug class here. There are **three parity axes**:

## Axis 1: Python package ↔ legacy bash

`sca/` is **authoritative**. `functions.sh` gets mirrored only for
**user-visible** behavior: flags, help text, connection semantics, log
messages users act on. Internal refactors are NOT ported.

Function mapping (Python ↔ bash, names in `functions.sh`):

| `sca/` | `functions.sh` |
|---|---|
| `cli.cli_main` | `parse_arguments` |
| `cli._print_help` | `print_help` |
| `cli.list_hosts` / `find_host` / `add_host` | `list` / `find` / `add` |
| `cli.kill_all` | `kill_all_sca_processes` (+ caller) |
| `__main__.main` | `sca_main` |
| `__main__.execute_command_or_shell` | `execute_command_or_shell` |
| `__main__.setup_new_connection` | `setup_new_connection` |
| `__main__.use_existing_connection` | `use_existing_connection` |
| `__main__.cleanup_handler` | `cleanup` |
| `connection.determine_security_level` | `determine_security_level` |
| `connection.start_remote_agent` | `start_remote_agent` |
| `connection.check_existing_connections` | `check_existing_connections` |
| `connection.validate_local_agent` | `validate_local_agent` |
| `agent.find_identity_file` / `setup_temp_agent` / `cleanup_temp_agent` / `build_ssh_cmd` | same names |
| `config.patch_jump_aliases` | `patch_jump_aliases` |
| `multiplexer.setup_python_multiplexer` | `setup_python_multiplexer` |
| `socket_utils.verify_socket_working` / `wait_for_socket` | same names |
| `process.kill_if_exists` / `kill_processes` / `check_ssh_agent_running` | same names |
| `logging_utils.log_*` | `log_*` |

One-sided on purpose (do NOT create counterparts):
- bash only: Rust-mux support (`check_rust_mux_*`, `setup_rust_*`,
  `filter_rust_mux_errors`), `do_cmd`
- Python only: `platform_utils` (Windows/named-pipe support), `cli` argparse
  plumbing via env vars

## Axis 2: standalone ↔ embedded multiplexer

`sshagentmux.py` (standalone, used by the bash version and externally) and
`sca/agentmux.py` (embedded module used by the Python version) are ~85%
identical. Intentional differences, everything else is drift:

- standalone has: `argparse` CLI, `multiprocessing` self-daemonizing wrapper,
  `time`/`shutil` imports, `__main__` entry
- embedded has: `run_agentmux(ready_pipe, parent_pid, primary, alternate,
  log_level)` entry called by `sca/multiplexer.py`

Drift check:

```bash
diff <(sed 's/[[:space:]]*$//' sshagentmux.py) <(sed 's/[[:space:]]*$//' sca/agentmux.py) | wc -l
```

Baseline is ~176 lines. A protocol/behavior fix (identity map, sign-request
routing, key parsing, socket handling) that appears in only one file is a
bug: port it to the other, keeping each file's wrapper intact.

## Axis 3: help & docs surfaces

Any CLI flag/behavior change must land on all four surfaces:

1. `sca/cli.py:_print_help()` — mind the manual alignment: `ex(vis_len, …)`
   takes the VISIBLE length (without ANSI codes); comments align at column 48
2. `functions.sh:print_help()` (+ `parse_arguments` for the flag itself)
3. `README.md` — "Command Options" and the examples
4. `AGENTS.md` — "Common Commands"

## Procedure

1. Determine what changed:
   ```bash
   git diff --name-only HEAD            # or the range in question
   git diff HEAD -- sca/ sshagentmux.py functions.sh
   ```
2. For each changed function, look up the counterpart in the tables above and
   read it (bash: `grep -n '^<name>() {' functions.sh`).
3. Classify each delta: **mirror required** (user-visible / protocol),
   **intentionally one-sided** (tables above), or **internal** (no port).
4. Report a drift table before touching anything:

   | Change | Counterpart | Status | Action |
   |---|---|---|---|
   | `--shell` flag added in `cli.py` | `parse_arguments` | missing | mirror |
   | globals refactor in `__main__` | `sca_main` | internal | none |

5. Mirror only after the user confirms — bash edits in a 1900-line
   `functions.sh` deserve a look before they land. Match bash idioms already
   in the file (`log_info`, `${var}` braces, shellcheck directives at top).
6. Verify: `bash -n functions.sh` (syntax), `./sca.sh --help` (if safe:
   help exits before connecting), plus the Python checks from CLAUDE.md.
7. Commit messages name the parity outcome: "… (mirrored in functions.sh)"
   or "… (Python only, bash n/a)".

## When to run this skill

- After completing any feature/fix in `sca/` or `functions.sh`
- After touching either multiplexer file
- Before any commit that changes behavior
- On request: "check parity" → run steps 1–4 only and report the drift table
