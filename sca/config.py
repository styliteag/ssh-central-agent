"""
Configuration management and SSH config patching.
"""
import re
from pathlib import Path

from .logging_utils import log_info, log_debug


def patch_jump_aliases(
    playbook_dir: str,
    ssh_config_file: str,
    my_level: int
) -> None:
    """
    Patch SSH config: add jump aliases (sca-jump, jump, etc.) to the Host line
    for this user's level.

    Args:
        playbook_dir: Directory containing SSH config files
        ssh_config_file: Name of SSH config file
        my_level: User's security level
    """
    status_file = Path(playbook_dir) / ".sca-jump-level"
    config_path = Path(playbook_dir) / ssh_config_file
    config_single_path = Path(playbook_dir) / f"{ssh_config_file}_single"

    log_info(f"Patching jump aliases (sca-jump, jump, etc.) for level {my_level} in SSH config")

    # Check if we need to patch
    need_patch = False

    if not status_file.exists():
        need_patch = True
        log_debug("Patch: no status file, will patch")
    else:
        # Check stored level
        try:
            with open(status_file, 'r') as f:
                for line in f:
                    if line.startswith("LEVEL="):
                        stored_level = int(line.split("=", 1)[1].strip())
                        if stored_level != my_level:
                            need_patch = True
                            log_info(f"Patch: level changed ({stored_level} -> {my_level}), will patch")
                        break
        except Exception:
            need_patch = True

        # Check if config files are newer than status
        if not need_patch:
            if config_path.exists() and config_path.stat().st_mtime > status_file.stat().st_mtime:
                need_patch = True
                log_info(f"Patch: {ssh_config_file} newer than status (e.g. Ansible), will patch")
            elif config_single_path.exists() and config_single_path.stat().st_mtime > status_file.stat().st_mtime:
                need_patch = True
                log_info(f"Patch: {ssh_config_file}_single newer than status (e.g. Ansible), will patch")

    if not need_patch:
        log_debug(f"Patch: level {my_level} already applied, skip")
        return

    # Patch the files
    for config_file in [config_path, config_single_path]:
        if not config_file.exists():
            log_debug(f"  Skip (not a file): {config_file}")
            continue

        log_info(f"  Patching: {config_file}")

        try:
            # Read file
            with open(config_file, 'r') as f:
                content = f.read()

            # Create backup
            backup_path = config_file.with_suffix(config_file.suffix + ".bak")
            with open(backup_path, 'w') as f:
                f.write(content)

            # Apply patches
            # 1. Strip any existing aliases after -sca-magic-jump
            content = re.sub(
                r'(-sca-magic-jump)(.*)$',
                r'\1',
                content,
                flags=re.MULTILINE
            )

            # 2. Append aliases to L$MY_LEVEL-sca-magic-jump
            pattern = f"(L{my_level}-sca-magic-jump)"
            replacement = r'\1 jump jump_local jump_my sca-jump sca-jump_org sca-jump_local sca-jump_my sca-jump_mux'
            content = re.sub(pattern, replacement, content)

            # Write back
            with open(config_file, 'w') as f:
                f.write(content)

        except Exception as e:
            log_debug(f"Error patching {config_file}: {e}")

    # Update status file
    try:
        with open(status_file, 'w') as f:
            f.write(f"LEVEL={my_level}\n")
        status_file.touch()
    except Exception as e:
        log_debug(f"Error writing status file: {e}")
