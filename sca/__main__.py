"""
Main entry point for SCA - SSH Central Agent.
"""
import os
import resource
import signal
import subprocess
import sys
import time
from pathlib import Path
from typing import Optional, Dict, Any

try:
    from . import cli
except ImportError:
    cli = None
from .agent import (
    find_identity_file, setup_temp_agent, cleanup_temp_agent,
    get_key_fingerprint, check_key_in_agent
)
from .connection import (
    determine_security_level, start_remote_agent,
    check_existing_connections, validate_local_agent
)
from .multiplexer import setup_python_multiplexer
from .socket_utils import verify_socket_working, resolve_socket_path
from .process import kill_if_exists
from .config import patch_jump_aliases
from .logging_utils import (
    log_info, log_error, log_success, log_warn, log_debug,
    color_value, color_reset
)
from .platform_utils import expand_path


# Constants
MAX_LEVEL = 99
CHECK_SECONDS = 30

# Global state
sca_exiting = False
ssh_pid: Optional[int] = None
mux_pid: Optional[int] = None
tail_log_pid: Optional[int] = None
temp_agent_pid: Optional[int] = None
temp_agent_sock: Optional[str] = None
# Track which processes were started by this instance (for cleanup)
_started_ssh_pid: Optional[int] = None
_started_mux_pid: Optional[int] = None


def _select_socket_for_key(
    key: str,
    expanded_mux_sock: str,
    expanded_ssh_auth_sock: str,
    org_ssh_auth_sock: Optional[str]
) -> str:
    """Select the appropriate socket based on --key option.

    Args:
        key: Key selection mode ("local", "remote", "mux", or default)
        expanded_mux_sock: Expanded path to mux socket
        expanded_ssh_auth_sock: Expanded path to remote agent socket
        org_ssh_auth_sock: Original local agent socket

    Returns:
        Path to selected socket

    Raises:
        SystemExit: If socket selection fails or socket is not working
    """
    if key == "mux":
        return expanded_mux_sock
    elif key == "local":
        if not org_ssh_auth_sock:
            log_error("No local agent available (--key=local requires a local SSH agent)")
            sys.exit(1)

        local_sock = org_ssh_auth_sock
        expanded_remote = expanded_ssh_auth_sock
        expanded_mux = expanded_mux_sock
        expanded_local = str(expand_path(local_sock)) if local_sock else ""

        if expanded_local == expanded_remote or expanded_local == expanded_mux:
            local_sock = os.environ.get("ORG_SSH_AUTH_SOCK") or os.environ.get("SSH_AUTH_SOCK", "")
            if local_sock:
                expanded_local = str(expand_path(local_sock))
                if expanded_local == expanded_remote or expanded_local == expanded_mux:
                    log_error("Cannot determine local agent socket (it appears to be a SCA socket)")
                    sys.exit(1)

        ssh_socket = str(expand_path(local_sock))
        if not verify_socket_working(ssh_socket):
            log_error(f"Local agent socket is not working: {ssh_socket}")
            sys.exit(1)
        return ssh_socket
    elif key == "remote":
        remote_sock = os.environ.get("SCA_SSH_AUTH_SOCK")
        if not remote_sock:
            remote_sock = expanded_ssh_auth_sock

        expanded_remote_param = str(expand_path(remote_sock))
        if expanded_remote_param == expanded_mux_sock:
            remote_sock = str(Path.home() / ".ssh" / "scadev-agent.sock")

        ssh_socket = str(expand_path(remote_sock))
        if not verify_socket_working(ssh_socket):
            log_error(f"Remote agent socket is not working: {ssh_socket}")
            sys.exit(1)
        return ssh_socket
    else:
        # Default: try mux first, fallback to remote
        if verify_socket_working(expanded_mux_sock):
            return expanded_mux_sock
        elif verify_socket_working(expanded_ssh_auth_sock):
            return expanded_ssh_auth_sock
        else:
            return expanded_mux_sock  # Will fail below with better error


def _list_keys_in_agent(agent_socket: str, key_mode: str) -> None:
    """List keys available in the specified agent socket.

    Args:
        agent_socket: Path to the agent socket
        key_mode: Key selection mode (for display purposes)
    """
    log_info(f"Available keys in selected agent ({key_mode if key_mode else 'default'}) at {agent_socket}:")
    try:
        clean_env = {k: v for k, v in os.environ.items() if k != "SSH_AUTH_SOCK"}
        clean_env["SSH_AUTH_SOCK"] = agent_socket
        result = subprocess.run(
            ["ssh-add", "-l"],
            env=clean_env,
            capture_output=True,
            text=True,
            timeout=5
        )
        if result.returncode == 0 and result.stdout.strip():
            from .logging_utils import Colors, _colorize, _should_use_colors
            for line in result.stdout.splitlines():
                if _should_use_colors():
                    colored_line = _colorize(line, Colors.CYAN)
                    print(f"  {colored_line}", file=sys.stderr, flush=True)
                else:
                    log_info(f"  {line}")
        else:
            log_warn("  No keys found in selected agent")
            if result.stderr:
                log_debug(f"  ssh-add error: {result.stderr}")
    except Exception as e:
        log_debug(f"Error listing keys: {e}")


def _build_ssh_command(
    playbook_dir: str,
    ssh_config_file: str,
    expanded_socket: str,
    ssh_args: Optional[str] = None
) -> list[str]:
    """Build SSH command with proper configuration.

    Args:
        playbook_dir: Directory containing SSH config
        ssh_config_file: Name of SSH config file
        expanded_socket: Expanded path to agent socket
        ssh_args: Additional SSH arguments

    Returns:
        List of SSH command arguments
    """
    config_path = Path(playbook_dir) / ssh_config_file
    ssh_cmd = ["ssh", "-F", str(config_path)]

    # Override IdentityAgent to use the working socket
    if " " in expanded_socket:
        ssh_cmd.extend(["-o", f"IdentityAgent='{expanded_socket}'"])
    else:
        ssh_cmd.extend(["-o", f"IdentityAgent={expanded_socket}"])

    if os.environ.get("DEBUG") == "1":
        ssh_cmd.append("-v")

    if ssh_args:
        import shlex
        ssh_cmd.extend(shlex.split(ssh_args))

    return ssh_cmd


def _create_symlink_if_needed(omux_socket: str, mux_ssh_auth_sock: str) -> None:
    """Create symlink from mux_ssh_auth_sock to omux_socket if needed.

    Args:
        omux_socket: Path to the actual multiplexer socket
        mux_ssh_auth_sock: Path where the symlink should be created
    """
    omux_expanded = expand_path(omux_socket)
    target_expanded = expand_path(mux_ssh_auth_sock)
    if omux_expanded != target_expanded:
        try:
            target_path = Path(target_expanded)
            if target_path.is_symlink():
                current_target = target_path.readlink()
                if str(current_target) == omux_socket:
                    log_debug(f"Symlink already exists and is correct: {target_expanded} -> {omux_socket}")
                else:
                    target_path.unlink()
                    target_path.symlink_to(omux_socket)
                    log_debug(f"Updated symlink: {target_expanded} -> {omux_socket}")
            elif target_path.exists():
                target_path.unlink()
                target_path.symlink_to(omux_socket)
                log_debug(f"Replaced file with symlink: {target_expanded} -> {omux_socket}")
            else:
                target_path.parent.mkdir(parents=True, exist_ok=True)
                target_path.symlink_to(omux_socket)
                log_debug(f"Created symlink: {target_expanded} -> {omux_socket}")
        except OSError as e:
            log_debug(f"Could not create symlink: {e}")


def _execute_ssh_connection(
    ssh_cmd: list[str],
    expanded_socket: str,
    temp_agent_pid: Optional[int],
    temp_agent_sock: Optional[str]
) -> None:
    """Execute SSH connection with proper environment setup.

    Args:
        ssh_cmd: SSH command arguments
        expanded_socket: Path to agent socket
        temp_agent_pid: Temporary agent PID (for cleanup)
        temp_agent_sock: Temporary agent socket (for cleanup)
    """
    # Verify socket exists and is accessible
    socket_path = Path(expanded_socket)
    if not socket_path.exists():
        log_error(f"Socket does not exist: {expanded_socket}")
        sys.exit(1)

    if not verify_socket_working(expanded_socket):
        log_error(f"Socket is not working: {expanded_socket}")
        sys.exit(1)

    log_info(f"Connecting via SSH config (SSH_AUTH_SOCK={expanded_socket}): ssh {' '.join(ssh_cmd[3:])}")

    env = os.environ.copy()
    env["SSH_AUTH_SOCK"] = expanded_socket

    if os.environ.get("DEBUG") == "1":
        log_debug(f"Environment SSH_AUTH_SOCK={env.get('SSH_AUTH_SOCK')}")

    sys.stderr.flush()
    sys.stdout.flush()

    # Close file descriptors that might interfere
    try:
        maxfd = resource.getrlimit(resource.RLIMIT_NOFILE)[1]
        if maxfd == resource.RLIM_INFINITY:
            maxfd = 1024
        for fd in range(3, maxfd):
            try:
                os.close(fd)
            except OSError:
                pass
    except Exception:
        pass

    # Execute SSH
    try:
        os.execvpe(ssh_cmd[0], ssh_cmd, env)
        exit_code = 1
    except FileNotFoundError:
        log_error(f"SSH command not found: {ssh_cmd[0]}")
        exit_code = 1
    except Exception as e:
        log_error(f"SSH command failed: {e}")
        exit_code = 1

    # Clean up temporary agent after SSH connection
    if temp_agent_pid:
        log_info("Cleaning up temporary SSH agent after SSH connection")
        cleanup_temp_agent(temp_agent_pid, temp_agent_sock or "")

    sys.exit(exit_code)


def cleanup_handler(signum=None, frame=None):
    """Handle cleanup on exit."""
    global sca_exiting, tail_log_pid, temp_agent_pid, _started_ssh_pid, _started_mux_pid
    sca_exiting = True

    if temp_agent_pid:
        log_info(f"Cleaning up temporary SSH agent (PID {temp_agent_pid})")
        cleanup_temp_agent(temp_agent_pid, temp_agent_sock or "")

    # Only kill processes we started (not ones from other instances)
    if _started_ssh_pid:
        log_info(f"Killing SSH agent forwarder (TCP port forwarding) (PID {_started_ssh_pid})")
        kill_if_exists(_started_ssh_pid, "SSH agent forwarder")

    if _started_mux_pid:
        log_info(f"Killing SSH agent multiplexer (PID {_started_mux_pid})")
        kill_if_exists(_started_mux_pid, "SSH agent multiplexer")

    if tail_log_pid:
        log_info(f"Killing log tail process (PID {tail_log_pid})")
        kill_if_exists(tail_log_pid, "log tail")


def execute_command_or_shell(
    playbook_dir: str,
    ssh_config_file: str,
    ssh_auth_sock: str,
    mux_ssh_auth_sock: str,
    org_ssh_auth_sock: str,
    ssh_args: Optional[str] = None
) -> None:
    """Execute command or start shell based on mode."""
    global temp_agent_pid, temp_agent_sock

    shell_mode = os.environ.get("SHELL_MODE") == "1"
    ssh_mode = os.environ.get("SSH_MODE") == "1"
    wait_mode = os.environ.get("WAIT") == "1"
    key = os.environ.get("KEY", "mux")

    if shell_mode:
        # Shell Mode: Output environment variables in ssh-agent format
        print(f"SSH_AUTH_SOCK={ssh_auth_sock}; export SSH_AUTH_SOCK;")
        agent_pid = mux_pid or ssh_pid
        if agent_pid:
            print(f"SSH_AGENT_PID={agent_pid}; export SSH_AGENT_PID;")
            print(f"echo Agent pid {agent_pid};")
        sys.exit(0)

    elif ssh_mode:
        # SSH Mode: Direct SSH connection
        expanded_mux_sock = str(expand_path(mux_ssh_auth_sock))
        expanded_ssh_auth_sock = str(expand_path(ssh_auth_sock))

        # Select socket based on --key option
        ssh_socket = _select_socket_for_key(key, expanded_mux_sock, expanded_ssh_auth_sock, org_ssh_auth_sock)

        # Log which agent is being used
        if key == "mux":
            log_info("Using multiplexed agent (--key=mux)")
        elif key == "local":
            log_info(f"Using local agent (--key=local): {ssh_socket}")
        elif key == "remote":
            log_info(f"Using remote agent (--key=remote): {ssh_socket}")
        else:
            if ssh_socket == expanded_mux_sock:
                log_info("Using multiplexed agent (default)")
            else:
                log_info(f"Using remote agent (fallback): {ssh_socket}")

        # Resolve symlink if needed
        if key in ("local", "remote"):
            resolved_socket = ssh_socket
        else:
            resolved_socket = resolve_socket_path(ssh_socket)
            if not verify_socket_working(resolved_socket):
                if ssh_socket == expanded_mux_sock and verify_socket_working(expanded_ssh_auth_sock):
                    resolved_socket = resolve_socket_path(expanded_ssh_auth_sock)
                    ssh_socket = expanded_ssh_auth_sock
                    log_info(f"Multiplexer socket not available, using remote agent: {resolved_socket}")
                else:
                    log_error(f"Socket is not working: {resolved_socket}")
                    sys.exit(1)

        # Show available keys
        agent_socket = str(expand_path(resolved_socket))
        _list_keys_in_agent(agent_socket, key)

        # Debug output
        if os.environ.get("DEBUG") == "1":
            log_debug("Socket details:")
            log_debug(f"  Selected socket: {ssh_socket}")
            if Path(ssh_socket).is_symlink():
                log_debug(f"  Type: symlink -> {resolved_socket}")
            else:
                log_debug("  Type: regular socket")

        # Build and execute SSH command
        expanded_socket = str(expand_path(resolved_socket))
        ssh_cmd = _build_ssh_command(playbook_dir, ssh_config_file, expanded_socket, ssh_args)
        _execute_ssh_connection(ssh_cmd, expanded_socket, temp_agent_pid, temp_agent_sock)

    elif wait_mode:
        # Wait Mode: Monitor connection and restart if needed
        log_info(f"WAIT in a Loop and check every {CHECK_SECONDS} if the Connection is dead")

        # Expand socket paths before checking
        expanded_mux_sock = str(expand_path(mux_ssh_auth_sock))
        expanded_sca_sock = str(expand_path(ssh_auth_sock))

        # Give sockets a moment to stabilize before first check
        time.sleep(2)

        while True:
            if sca_exiting:
                log_info("Exiting...")
                break

            # Check the appropriate socket (prefer mux, fallback to remote agent)
            socket_to_check = expanded_mux_sock
            if not verify_socket_working(expanded_mux_sock):
                socket_to_check = expanded_sca_sock

            if not verify_socket_working(socket_to_check):
                if sca_exiting:
                    log_info("Exiting due to intentional termination")
                    break
                log_error("Cannot connect to agent!")
                log_info("Restarting...")
                # Restart by re-running main
                os.environ.pop("SCA_SUBSHELL", None)
                os.environ["SSH_AUTH_SOCK"] = org_ssh_auth_sock
                # Re-import and call main
                main()
                sys.exit(255)
            else:
                print(".", end="", file=sys.stderr, flush=True)

            time.sleep(CHECK_SECONDS)

    else:
        # Default: Start Interactive Subshell
        log_info("Starting Subshell")
        shell = os.environ.get("SHELL", "/bin/sh")
        os.execv(shell, [shell])


def setup_new_connection(
    playbook_dir: str,
    ssh_config_file: str,
    sca_ssh_auth_sock: str,
    mux_ssh_auth_sock: str,
    rusername: str,
    org_ssh_auth_sock: str,
    temp_agent_sock_param: Optional[str],
    temp_agent_pid_param: Optional[int],
    use_identity_file: bool,
    identity_file: Optional[str],
    reverse: bool,
    level: Optional[int]
) -> Dict[str, Any]:
    """Setup a new connection."""
    global ssh_pid, mux_pid, temp_agent_sock, temp_agent_pid, _started_ssh_pid, _started_mux_pid

    # Use parameter values, update globals
    temp_agent_sock = temp_agent_sock_param
    temp_agent_pid = temp_agent_pid_param

    log_info("No working agent found: Starting new connection")

    # Remove old sockets (expand paths first)
    for sock in [sca_ssh_auth_sock, mux_ssh_auth_sock]:
        sock_path = Path(expand_path(sock))
        if sock_path.exists():
            try:
                log_debug(f"Removing old socket: {sock_path}")
                sock_path.unlink()
            except OSError as e:
                log_debug(f"Error removing socket {sock_path}: {e}")

    # Determine security level
    try:
        my_level = determine_security_level(
            playbook_dir, ssh_config_file,
            mux_ssh_auth_sock=mux_ssh_auth_sock,
            temp_agent_sock=temp_agent_sock,
            use_identity_file=use_identity_file,
            identity_file=identity_file
        )
    except Exception as e:
        log_error(f"Failed to determine security level: {e}")
        sys.exit(1)

    log_info(f"You are a Level {my_level} user")

    # Handle level override
    if level is not None and level != MAX_LEVEL and level < my_level:
        log_warn(f"LOWER level to {level}")
        my_level = level
    elif level is None:
        log_error("Cannot find your level (Maybe something is not working). Stopping")
        sys.exit(1)

    # Start remote agent
    try:
        ssh_pid = start_remote_agent(
            my_level,
            playbook_dir,
            ssh_config_file,
            sca_ssh_auth_sock,
            rusername,
            temp_agent_sock=temp_agent_sock,
            use_identity_file=use_identity_file,
            identity_file=identity_file,
            max_level=MAX_LEVEL
        )
        _started_ssh_pid = ssh_pid  # Track that we started this process
    except Exception as e:
        log_error(f"Failed to start remote agent: {e}")
        sys.exit(1)

    # Patch SSH config
    patch_jump_aliases(playbook_dir, ssh_config_file, my_level)

    log_success(f"Successfully started a remote agent at {sca_ssh_auth_sock}")

    # Determine local agent socket for multiplexing
    local_agent_sock = None
    if temp_agent_sock and verify_socket_working(temp_agent_sock):
        local_agent_sock = temp_agent_sock
        log_info("Will multiplex temporary agent (local key) with remote agent")
    elif org_ssh_auth_sock and verify_socket_working(org_ssh_auth_sock):
        local_agent_sock = org_ssh_auth_sock
        log_info("Will multiplex local agent with remote agent")
    else:
        log_info("No local agent, will use remote agent only")

    # Setup multiplexer
    omux_socket = None
    omux_pid = None
    skip_symlink = False

    # Expand socket path before checking
    expanded_sca_sock = str(expand_path(sca_ssh_auth_sock))

    if verify_socket_working(expanded_sca_sock):
        log_info("Muxing the agents to one")

        # Use local agent or dummy path
        org_sock_for_mux = local_agent_sock if local_agent_sock else "/dev/null"

        try:
            mux_result = setup_python_multiplexer(
                playbook_dir,
                expanded_sca_sock,
                org_sock_for_mux,
                reverse=reverse
            )
            omux_socket = mux_result["socket"]
            omux_pid = mux_result["pid"]
            skip_symlink = False
        except Exception as e:
            log_error(f"Failed to setup Python multiplexer: {e}")
            sys.exit(1)

        mux_pid = omux_pid
        _started_mux_pid = omux_pid  # Track that we started this process

        # Create symlink if needed
        if not skip_symlink:
            _create_symlink_if_needed(omux_socket, mux_ssh_auth_sock)

        os.environ["ORG_MUX_SSH_AUTH_SOCK"] = omux_socket
        # Use expanded path for environment variable
        expanded_mux_sock = str(expand_path(mux_ssh_auth_sock))
        os.environ["SSH_AUTH_SOCK"] = expanded_mux_sock

        log_info(f"Verifying with: 'SSH_AUTH_SOCK={expanded_mux_sock} ssh-add -l'")
        log_success("You can now use this key (even not in this SUBSHELL, thanks to .ssh/config magic)")
        try:
            result = subprocess.run(
                ["ssh-add", "-l"],
                env={"SSH_AUTH_SOCK": expanded_mux_sock, **os.environ},
                capture_output=True,
                text=True,
                timeout=5
            )
            for line in result.stdout.splitlines():
                log_info(f"{color_value()}{line}{color_reset()}")
        except Exception:
            pass
    else:
        log_error(f"Remote agent socket not available: {expanded_sca_sock}")
        log_debug(f"Socket exists: {Path(expanded_sca_sock).exists()}")
        sys.exit(1)

    return {
        "my_level": my_level,
        "ssh_pid": ssh_pid,
        "mux_pid": mux_pid,
        "started_ssh_pid": _started_ssh_pid,
        "started_mux_pid": _started_mux_pid,
        "ssh_auth_sock": mux_ssh_auth_sock
    }


def use_existing_connection(
    playbook_dir: str,
    ssh_config_file: str,
    sca_ssh_auth_sock: str,
    mux_ssh_auth_sock: str,
    org_ssh_auth_sock: str,
    rusername: str,
    reverse: bool,
    level: Optional[int]
) -> Dict[str, Any]:
    """Use an existing connection."""
    global temp_agent_pid, temp_agent_sock, ssh_pid, mux_pid, _started_ssh_pid, _started_mux_pid

    # Check if we need a temporary agent
    has_local_agent = False
    if org_ssh_auth_sock and verify_socket_working(org_ssh_auth_sock):
        has_local_agent = True
    elif os.environ.get("SSH_AUTH_SOCK") and verify_socket_working(os.environ["SSH_AUTH_SOCK"]):
        current_sock = os.environ["SSH_AUTH_SOCK"]
        if current_sock != sca_ssh_auth_sock and current_sock != mux_ssh_auth_sock:
            has_local_agent = True

    if not has_local_agent:
        # Check if mux socket has local key
        id_file = find_identity_file()
        needs_local_key = True
        if id_file and verify_socket_working(mux_ssh_auth_sock):
            id_fingerprint = get_key_fingerprint(id_file)
            if id_fingerprint and check_key_in_agent(mux_ssh_auth_sock, id_fingerprint):
                needs_local_key = False
                log_info("Mux socket already has local key, no need to create temporary agent")

        if needs_local_key and id_file:
            log_info("Creating temporary SSH agent for local key (needed for connection)...")
            try:
                temp_sock, temp_pid = setup_temp_agent(id_file)
                temp_agent_sock = temp_sock
                temp_agent_pid = temp_pid
                log_info("Temporary SSH agent created")
            except Exception as e:
                log_warn(f"Failed to create temporary agent: {e}")

    # Determine level
    try:
        my_level = determine_security_level(
            playbook_dir, ssh_config_file,
            mux_ssh_auth_sock=mux_ssh_auth_sock,
            temp_agent_sock=temp_agent_sock,
            use_identity_file=bool(temp_agent_sock),
            identity_file=str(find_identity_file()) if find_identity_file() else None
        )
    except Exception as e:
        log_error(f"Failed to determine security level: {e}")
        sys.exit(1)

    # Patch SSH config
    patch_jump_aliases(playbook_dir, ssh_config_file, my_level)

    # Handle level override
    if level is not None and level != MAX_LEVEL and level < my_level:
        log_warn(f"LOWER level to {level}")
        my_level = level

    # Setup multiplexer if needed
    # We need mux if we have both a local agent (temp or regular) and remote agent
    local_agent_sock = None
    if temp_agent_sock and verify_socket_working(temp_agent_sock):
        local_agent_sock = temp_agent_sock
    elif has_local_agent:
        # Use the existing local agent
        if org_ssh_auth_sock and verify_socket_working(org_ssh_auth_sock):
            local_agent_sock = org_ssh_auth_sock
        elif os.environ.get("SSH_AUTH_SOCK") and verify_socket_working(os.environ["SSH_AUTH_SOCK"]):
            current_sock = os.environ["SSH_AUTH_SOCK"]
            if current_sock != sca_ssh_auth_sock and current_sock != mux_ssh_auth_sock:
                local_agent_sock = current_sock

    # Expand socket paths before checking
    expanded_sca_sock = str(expand_path(sca_ssh_auth_sock))
    expanded_mux_sock_check = str(expand_path(mux_ssh_auth_sock))

    # Check if mux socket is already working - if so, reuse it directly
    if verify_socket_working(expanded_mux_sock_check):
        log_info("Reusing existing SSH agent multiplexer (no new process started)")
        needs_mux_setup = False
    elif local_agent_sock and verify_socket_working(expanded_sca_sock):
        # Only create new mux if we have both local and remote agents, and mux doesn't exist/work
        needs_mux_setup = True
    else:
        needs_mux_setup = False

    if needs_mux_setup:
        log_info("Setting up multiplexer for local agent + remote agent")
        org_sock_for_mux = local_agent_sock

        try:
            mux_result = setup_python_multiplexer(
                playbook_dir,
                expanded_sca_sock,
                org_sock_for_mux,
                reverse=reverse
            )
            omux_socket = mux_result["socket"]
            omux_pid = mux_result["pid"]
            skip_symlink = False
        except Exception as e:
            log_error(f"Failed to setup Python multiplexer: {e}")
            return {
                "my_level": my_level,
                "ssh_pid": None,
                "mux_pid": None,
                "started_ssh_pid": None,
                "started_mux_pid": None,
                "ssh_auth_sock": sca_ssh_auth_sock
            }

        mux_pid = omux_pid
        _started_mux_pid = omux_pid  # Track that we started this process

        if not skip_symlink:
            _create_symlink_if_needed(omux_socket, mux_ssh_auth_sock)

        os.environ["ORG_MUX_SSH_AUTH_SOCK"] = omux_socket
        # Use expanded path for environment variable
        expanded_mux_sock = str(expand_path(mux_ssh_auth_sock))
        os.environ["SSH_AUTH_SOCK"] = expanded_mux_sock

    # Use the multiplexed socket if available, otherwise use remote agent
    # Expand paths before checking
    expanded_mux_sock = str(expand_path(mux_ssh_auth_sock))
    expanded_sca_sock = str(expand_path(sca_ssh_auth_sock))

    if verify_socket_working(expanded_mux_sock):
        log_info(f"Using existing multiplexed SSH agent (SSH_AUTH_SOCK={expanded_mux_sock})")
        final_sock = expanded_mux_sock
    elif verify_socket_working(expanded_sca_sock):
        log_info(f"Using existing remote SSH agent (SSH_AUTH_SOCK={expanded_sca_sock})")
        final_sock = expanded_sca_sock
        os.environ["MUX_SSH_AUTH_SOCK"] = expanded_sca_sock
    else:
        log_error("No working agent socket found")
        log_debug(f"Mux socket: {expanded_mux_sock} (exists: {Path(expanded_mux_sock).exists()})")
        log_debug(f"Remote socket: {expanded_sca_sock} (exists: {Path(expanded_sca_sock).exists()})")
        sys.exit(1)

    os.environ["SSH_AUTH_SOCK"] = final_sock

    # Show available keys
    log_info(f"Verifying with: 'SSH_AUTH_SOCK={final_sock} ssh-add -l'")
    try:
        result = subprocess.run(
            ["ssh-add", "-l"],
            env={"SSH_AUTH_SOCK": final_sock, **os.environ},
            capture_output=True,
            text=True,
            timeout=5
        )
        for line in result.stdout.splitlines():
            log_info(f"{color_value()}{line}{color_reset()}")
    except Exception:
        pass

    # Return None for PIDs since we didn't start them (they're from existing connection)
    return {
        "my_level": my_level,
        "ssh_pid": None,  # We didn't start this, it's from existing connection
        "mux_pid": None if not needs_mux_setup else mux_pid,  # Only set if we created it
        "started_ssh_pid": None,  # We didn't start SSH agent
        "started_mux_pid": _started_mux_pid if needs_mux_setup else None,  # Only if we created mux
        "ssh_auth_sock": final_sock
    }


def main():
    """Main entry point."""
    global sca_exiting, ssh_pid, mux_pid, temp_agent_pid, temp_agent_sock, _started_ssh_pid, _started_mux_pid

    # Set up signal handlers
    signal.signal(signal.SIGINT, cleanup_handler)
    signal.signal(signal.SIGTERM, cleanup_handler)

    # Get configuration from environment (set by Ansible-generated script)
    # Resolve playbook_dir to absolute path - if not set, use directory containing this module
    playbook_dir_env = os.environ.get("PLAYBOOK_DIR", "")
    if playbook_dir_env:
        playbook_dir = str(Path(playbook_dir_env).resolve())
    else:
        # Default to directory containing sca package (where sshagentmux.py should be)
        # Try to find it relative to the sca package location
        sca_package_dir = Path(__file__).parent.parent.resolve()
        if (sca_package_dir / "sshagentmux.py").exists():
            playbook_dir = str(sca_package_dir)
        else:
            # Fallback to current directory
            playbook_dir = str(Path.cwd().resolve())

    ssh_config_file = os.environ.get("SSH_CONFIG_FILE", "config")
    sca_ssh_auth_sock = os.environ.get("SCA_SSH_AUTH_SOCK", str(Path.home() / ".ssh" / "scadev-agent.sock"))
    mux_ssh_auth_sock = os.environ.get("MUX_SSH_AUTH_SOCK", str(Path.home() / ".ssh" / "scadev-mux.sock"))
    rusername = os.environ.get("RUSERNAME", "")
    org_ssh_auth_sock = os.environ.get("ORG_SSH_AUTH_SOCK", os.environ.get("SSH_AUTH_SOCK", ""))

    # If RUSERNAME is not set, try to read from localvars.yml
    if not rusername:
        localvars_path = Path(playbook_dir) / "localvars.yml"
        if localvars_path.exists():
            try:
                with open(localvars_path, 'r') as f:
                    for line in f:
                        if line.strip().startswith("remote_username:"):
                            rusername = line.split(":", 1)[1].strip()
                            break
            except Exception:
                pass

    # Validate rusername
    if not rusername:
        from .logging_utils import log_error
        log_error("RUSERNAME not set. Set it in environment or localvars.yml")
        log_error("Example: export RUSERNAME=wb")
        sys.exit(1)

    # Parse CLI arguments using argparse
    if cli and hasattr(cli, 'cli_main'):
        try:
            result = cli.cli_main()
            # cli_main() returns None to continue, or raises SystemExit if handled
            # If it returns, we continue to main logic
        except SystemExit:
            # CLI handled the command (--list, --find, --add, --kill, --help)
            return

    # Get options from environment (set by CLI)
    reverse = os.environ.get("REVERSE") == "1"
    level_str = os.environ.get("LEVEL")
    level = int(level_str) if level_str else MAX_LEVEL
    ssh_args = os.environ.get("SSH_ARGS", "")

    # Check for existing connections
    conn_status = check_existing_connections(sca_ssh_auth_sock, mux_ssh_auth_sock)
    my_socks_working = conn_status["working"]

    # Validate local agent
    try:
        agent_info = validate_local_agent(org_ssh_auth_sock)
        temp_agent_sock = agent_info.get("temp_agent_sock")
        temp_agent_pid = agent_info.get("temp_agent_pid")
        use_identity_file = agent_info.get("use_identity_file", False)
        identity_file = agent_info.get("identity_file")
    except RuntimeError as e:
        log_error(str(e))
        sys.exit(1)

    # Setup connection
    if not my_socks_working:
        result = setup_new_connection(
            playbook_dir, ssh_config_file,
            sca_ssh_auth_sock, mux_ssh_auth_sock,
            rusername, org_ssh_auth_sock,
            agent_info.get("temp_agent_sock"),
            agent_info.get("temp_agent_pid"),
            use_identity_file, identity_file,
            reverse, level
        )
    else:
        result = use_existing_connection(
            playbook_dir, ssh_config_file,
            sca_ssh_auth_sock, mux_ssh_auth_sock,
            org_ssh_auth_sock, rusername,
            reverse, level
        )

    my_level = result["my_level"]
    ssh_pid = result.get("ssh_pid")
    mux_pid = result.get("mux_pid")
    final_ssh_auth_sock = result["ssh_auth_sock"]

    # Update ownership tracking from result (only if we started the processes)
    started_ssh = result.get("started_ssh_pid")
    started_mux = result.get("started_mux_pid")
    if started_ssh is not None:
        _started_ssh_pid = started_ssh
    if started_mux is not None:
        _started_mux_pid = started_mux

    # Set environment variables
    os.environ["SCA_SSH_AUTH_SOCK"] = sca_ssh_auth_sock
    os.environ["MUX_SSH_AUTH_SOCK"] = mux_ssh_auth_sock
    os.environ["SCA_SUBSHELL"] = "SCA-KEY"
    os.environ["SCA_USER"] = rusername
    os.environ["SCA_JUMPHOST"] = f"sca-jump-level{my_level}"
    os.environ["SCA_LEVEL"] = str(my_level)

    logname = os.environ.get("LOGNAME", os.environ.get("USER", ""))
    log_success(f"Hello {rusername}({logname}) you are level {my_level} and using sca-jump-level{my_level}")

    # Execute command or start shell
    execute_command_or_shell(
        playbook_dir, ssh_config_file,
        final_ssh_auth_sock, mux_ssh_auth_sock,
        org_ssh_auth_sock, ssh_args
    )


if __name__ == "__main__":
    main()
