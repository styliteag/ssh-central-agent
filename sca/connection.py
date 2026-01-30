"""
Connection management: determining security level, starting remote agents, etc.
"""
import os
import re
import socket
import subprocess
import tempfile
import time
from pathlib import Path
from typing import Dict, Optional, Any

from .agent import (
    find_identity_file, setup_temp_agent, build_ssh_cmd, get_key_fingerprint, check_key_in_agent, get_agent_key_count
)
from .socket_utils import verify_socket_working, check_agent_socket
from .process import (
    verify_remote_agent_working,
    kill_all_sca_processes, process_exists
)
from .logging_utils import log_info, log_error, log_success, log_warn, log_debug
from .platform_utils import get_home_dir, expand_path


# Constants
SSH_RETRY_MAX = 10
SSH_RETRY_DELAY = 1
SSH_INITIAL_DELAY = 0.1


def determine_security_level(
    playbook_dir: str,
    ssh_config_file: str,
    mux_ssh_auth_sock: Optional[str] = None,
    temp_agent_sock: Optional[str] = None,
    use_identity_file: bool = False,
    identity_file: Optional[str] = None
) -> int:
    """
    Determine user security level by connecting to sca-key server.

    Args:
        playbook_dir: Directory containing SSH config
        ssh_config_file: Name of SSH config file
        mux_ssh_auth_sock: Mux socket path (if available)
        temp_agent_sock: Temporary agent socket (if using temp agent)
        use_identity_file: Whether to use identity file directly
        identity_file: Path to identity file

    Returns:
        Security level (0-3)

    Raises:
        RuntimeError: If security level cannot be determined
    """
    # If we have a mux socket with the local key, use it directly
    # Otherwise, use build_ssh_cmd which will use temp agent or identity file
    ssh_cmd_list = None

    if mux_ssh_auth_sock and verify_socket_working(mux_ssh_auth_sock):
        # Check if mux socket has the local key (needed for sca-key connection)
        id_file = find_identity_file()
        if id_file:
            id_fingerprint = get_key_fingerprint(id_file)
            if id_fingerprint:
                if check_key_in_agent(mux_ssh_auth_sock, id_fingerprint):
                    # Mux socket has the local key, use it
                    config_path = Path(playbook_dir) / ssh_config_file
                    ssh_cmd_list = [
                        "ssh", "-a", "-F", str(config_path),
                        "-o", f"IdentityAgent={mux_ssh_auth_sock}"
                    ]
                    log_debug(f"Determining security level with mux socket: {' '.join(ssh_cmd_list)}")

    if not ssh_cmd_list:
        # Use build_ssh_cmd which will use temp agent or identity file
        ssh_cmd_list = build_ssh_cmd(
            playbook_dir, ssh_config_file,
            temp_agent_sock=temp_agent_sock,
            use_identity_file=use_identity_file,
            identity_file=identity_file
        )
        log_debug(f"Determining security level with: {' '.join(ssh_cmd_list)}")

    # Execute SSH command to get security level
    ssh_cmd_list.extend([
        "-o", "SetEnv SCA_NOLEVEL=1",
        "sca-key", "groups"
    ])

    try:
        result = subprocess.run(
            ssh_cmd_list,
            capture_output=True,
            text=True,
            timeout=30
        )

        if result.returncode != 0:
            log_error(f"SSH connection failed with exit code {result.returncode}")
            log_error(f"SSH output: {result.stderr}")
            raise RuntimeError(f"SSH connection failed: {result.stderr}")

        ssh_output = result.stdout + result.stderr

        # Parse output for level-* groups
        # Format: level-0, level-1, etc.
        level_pattern = r'level-(\d+)'
        matches = re.findall(level_pattern, ssh_output)

        if not matches:
            log_error("Could not determine your security level. Check your SSH connection.")
            if ssh_output:
                log_error(f"SSH command output: {ssh_output}")
            raise RuntimeError("Could not determine security level")

        # Get the highest level
        levels = [int(m) for m in matches]
        my_level = max(levels)

        return my_level

    except subprocess.TimeoutExpired:
        log_error("SSH connection timed out")
        raise RuntimeError("SSH connection timed out")
    except Exception as e:
        log_error(f"Error determining security level: {e}")
        raise


def start_remote_agent(
    level: int,
    playbook_dir: str,
    ssh_config_file: str,
    sca_ssh_auth_sock: str,
    rusername: str,
    temp_agent_sock: Optional[str] = None,
    use_identity_file: bool = False,
    identity_file: Optional[str] = None,
    max_level: int = 99
) -> int:
    """
    Start remote SSH agent forwarder.

    Args:
        level: Security level
        playbook_dir: Directory containing SSH config
        ssh_config_file: Name of SSH config file
        sca_ssh_auth_sock: Path where remote agent socket will be created
        rusername: Remote username
        temp_agent_sock: Temporary agent socket (if using temp agent)
        use_identity_file: Whether to use identity file directly
        identity_file: Path to identity file
        max_level: Maximum security level

    Returns:
        Process ID of SSH forwarder

    Raises:
        RuntimeError: If agent cannot be started
    """
    ssh_cmd_list = build_ssh_cmd(
        playbook_dir, ssh_config_file,
        temp_agent_sock=temp_agent_sock,
        use_identity_file=use_identity_file,
        identity_file=identity_file
    )

    log_info(f"Starting SSH agent forwarder (level {level})...")

    # Expand socket path (SSH -L requires absolute path, doesn't expand ~)
    expanded_socket = str(expand_path(sca_ssh_auth_sock))
    log_debug(f"Expanded socket path: {sca_ssh_auth_sock} -> {expanded_socket}")

    # Remove stale socket file if it exists (SSH -L will fail if socket exists and is not in use)
    socket_path = Path(expanded_socket)
    if socket_path.exists():
        try:
            # Check if socket is actually working (has a process attached)
            if verify_socket_working(expanded_socket):
                # Socket is working - this shouldn't happen if check_existing_connections worked
                # But if it does, we should not try to create a new one
                log_warn(f"Socket already exists and is working: {expanded_socket}")
                log_warn("This indicates a race condition - socket was created between checks")
                # This is a race condition - socket exists but we're trying to create it
                # Best to remove it and start fresh
                log_warn("Socket exists but we're starting new connection - removing stale socket")
                socket_path.unlink()
            else:
                # Stale socket - remove it so SSH can create a new one
                log_debug(f"Removing stale socket before starting: {expanded_socket}")
                socket_path.unlink()
        except OSError as e:
            log_debug(f"Error checking socket: {e}, attempting to remove anyway")
            try:
                if socket_path.is_socket():
                    socket_path.unlink()
            except Exception:
                pass

    # Validate rusername
    if not rusername:
        log_error("Remote username (rusername) is required but not set")
        raise RuntimeError("Remote username is required")

    # Build the SSH command with port forwarding
    # Note: We don't use -tt here because this is a background process that doesn't need a TTY
    # Using -tt would try to allocate a TTY which can interfere with the interactive SSH session
    remote_socket = f"/home/{rusername}/yubikey-agent.sock"
    ssh_cmd_list.extend([
        "-a",  # Disable agent forwarding (we're forwarding the socket via -L instead)
        "-L", f"{expanded_socket}:{remote_socket}",
        "-o", f"SetEnv STY_LEVEL={level} SCA_LEVEL={level}",
        "sca-key", "ragent",
        f"{os.environ.get('LOGNAME', '')},{os.environ.get('USER', '')},{rusername},{level},{max_level},{socket.gethostname()},{get_home_dir()}"
    ])

    # Set environment variables
    env = os.environ.copy()
    env["SCA_LOCALUSER"] = os.environ.get("LOGNAME", "")
    env["SCA_REMOTEUSER"] = rusername
    env["SCA_IP"] = socket.gethostname()

    # Start SSH process in background
    # Capture stderr to a temporary file for debugging
    ssh_stderr_file = tempfile.NamedTemporaryFile(mode='w', suffix='.log', delete=False, delete_on_close=False)
    ssh_stderr_file.close()

    try:
        log_debug(f"SSH command: {' '.join(ssh_cmd_list)}")
        # Fully detach from terminal: new session, no stdin/stdout/stderr attached
        process = subprocess.Popen(
            ssh_cmd_list,
            stdin=subprocess.DEVNULL,  # Detach stdin from terminal
            stdout=subprocess.DEVNULL,  # Detach stdout from terminal
            stderr=open(ssh_stderr_file.name, 'w'),  # Log to file only
            env=env,
            start_new_session=True  # Create new session (fully detached)
        )
        ssh_pid = process.pid
        log_success(f"Started SSH agent forwarder (TCP port forwarding) as PID {ssh_pid}")
    except Exception as e:
        log_error(f"Failed to start SSH agent forwarder: {e}")
        raise RuntimeError(f"Failed to start SSH agent forwarder: {e}")

    # Wait for connection to establish
    time.sleep(SSH_INITIAL_DELAY)

    iterations = 0
    while iterations < SSH_RETRY_MAX:
        iterations += 1

        # Check if SSH process is still running
        if not process_exists(ssh_pid):
            log_error(f"SSH process (PID {ssh_pid}) died unexpectedly")
            raise RuntimeError("SSH process died unexpectedly")

        # Check if socket exists and is working (use expanded path)
        if verify_socket_working(expanded_socket):
            return ssh_pid

        log_info(f"Trying to connect to agent ({iterations}/{SSH_RETRY_MAX})")
        time.sleep(SSH_RETRY_DELAY)

    log_error(f"Cannot connect to agent after {SSH_RETRY_MAX} attempts")

    # Check if SSH process is still running
    if process_exists(ssh_pid):
        log_error(f"SSH process (PID {ssh_pid}) is still running but socket is not working")
        log_debug(f"Socket path: {expanded_socket}")
        log_debug(f"Socket exists: {Path(expanded_socket).exists()}")

        # Read SSH stderr for debugging
        try:
            with open(ssh_stderr_file.name, 'r') as f:
                ssh_errors = f.read().strip()
                if ssh_errors:
                    # Clean up SSH stderr - remove carriage returns and normalize whitespace
                    cleaned_errors = '\n'.join(
                        line.strip() for line in ssh_errors.splitlines()
                        if line.strip() and not line.strip().startswith('\r')
                    )
                    # Remove duplicate consecutive lines
                    lines = cleaned_errors.split('\n')
                    unique_lines = []
                    prev_line = None
                    for line in lines:
                        if line != prev_line:
                            unique_lines.append(line)
                        prev_line = line
                    if unique_lines:
                        log_debug("SSH stderr output:\n" + '\n'.join(unique_lines))
        except Exception:
            pass

        from .process import kill_if_exists
        log_info(f"Killing failed SSH agent forwarder (TCP port forwarding) (PID {ssh_pid})")
        kill_if_exists(ssh_pid, "SSH agent forwarder")

    raise RuntimeError("Failed to connect to remote agent")


def check_existing_connections(
    sca_ssh_auth_sock: str,
    mux_ssh_auth_sock: str
) -> Dict[str, bool]:
    """
    Check existing connections and clean up stale ones.

    Args:
        sca_ssh_auth_sock: Path to remote agent socket
        mux_ssh_auth_sock: Path to mux socket

    Returns:
        Dictionary with keys: 'sca_sock', 'mux_sock', 'working'
    """
    from .socket_utils import verify_socket_working

    sca_sock = False
    mux_sock = False
    working = True

    # Expand paths before checking
    expanded_sca_sock = str(expand_path(sca_ssh_auth_sock))
    expanded_mux_sock = str(expand_path(mux_ssh_auth_sock))

    # Check mux socket first - if it's working, we can use it directly
    # The socket being functional is proof enough that the agent is working
    if verify_socket_working(expanded_mux_sock):
        mux_sock = True
        log_info("Found working mux socket, will reuse existing connection")

    # Check remote socket if mux is not available
    # For remote socket, we also verify the SSH process is running
    if not mux_sock:
        if verify_remote_agent_working(sca_ssh_auth_sock):
            sca_sock = True
            log_info("Found working remote agent socket, will reuse existing connection")

    # Only kill processes if NEITHER socket is working
    if not sca_sock and not mux_sock:
        log_info("Cleaning up stale connections")
        kill_all_sca_processes()
        log_info("Removing stale socket files")
        # Expand paths before checking/removing
        sca_sock_path = Path(expanded_sca_sock)
        mux_sock_path = Path(expanded_mux_sock)

        try:
            if sca_sock_path.exists():
                log_debug(f"Removing stale socket: {sca_sock_path}")
                sca_sock_path.unlink()
        except OSError as e:
            log_debug(f"Error removing socket {sca_sock_path}: {e}")
        try:
            if mux_sock_path.exists():
                log_debug(f"Removing stale socket: {mux_sock_path}")
                mux_sock_path.unlink()
        except OSError as e:
            log_debug(f"Error removing socket {mux_sock_path}: {e}")
        working = False
    elif not mux_sock and sca_sock:
        # Remote socket is working but mux is not - check if mux socket exists but is stale
        mux_socket_path = Path(expanded_mux_sock)
        if mux_socket_path.exists():
            # Mux socket exists but not working - clean it up (we'll use remote socket)
            log_info("Mux socket exists but not working, removing stale mux socket")
            from .process import kill_processes, PROC_PYTHON_MUX
            kill_processes(PROC_PYTHON_MUX, "SSH agent multiplexer")
            try:
                if mux_socket_path.exists():
                    mux_socket_path.unlink()
            except OSError:
                pass
            # We can still use the remote socket, so working = True

    return {
        "sca_sock": sca_sock,
        "mux_sock": mux_sock,
        "working": working
    }


def validate_local_agent(
    ssh_auth_sock: Optional[str] = None
) -> Dict[str, Any]:
    """
    Validate local SSH agent or identity file.

    Args:
        ssh_auth_sock: Current SSH_AUTH_SOCK value

    Returns:
        Dictionary with keys: 'local_sock', 'use_identity_file', 'identity_file',
                              'temp_agent_sock', 'temp_agent_pid'

    Raises:
        RuntimeError: If no agent or identity file found
    """
    local_sock = False
    use_identity_file = False
    identity_file = None
    temp_agent_sock = None
    temp_agent_pid = None

    # Check if local SSH agent is working
    if ssh_auth_sock and check_agent_socket(ssh_auth_sock):
        local_sock = True

    if not local_sock:
        # No agent found, check for identity files
        log_info("No local SSH agent found, checking for identity files...")
        id_file = find_identity_file()
        if id_file:
            use_identity_file = True
            identity_file = str(id_file)
            log_success(f"Found identity file: {identity_file}")
            # Create temporary agent to avoid multiple passphrase prompts
            try:
                temp_sock, temp_pid = setup_temp_agent(id_file)
                temp_agent_sock = temp_sock
                temp_agent_pid = temp_pid
                local_sock = True  # We now have a temporary agent
                log_info("Using temporary SSH agent for initial connections")
            except Exception as e:
                log_error("Failed to set up temporary SSH agent")
                raise RuntimeError(f"Failed to set up temporary SSH agent: {e}")
        else:
            log_error("No local SSH agent or identity file found.")
            log_error('Either start an agent with "eval $(ssh-agent)" and add your keys,')
            log_error("or ensure you have an identity file at ~/.ssh/id_ed25519, ~/.ssh/id_rsa, etc.")
            raise RuntimeError("No local SSH agent or identity file found")
    else:
        # Agent exists, check if it has keys loaded
        key_count = get_agent_key_count(ssh_auth_sock)
        if key_count == 0:
            log_warn("Your local agent has no keys loaded")
            log_info("Checking for identity files as fallback...")
            id_file = find_identity_file()
            if id_file:
                use_identity_file = True
                identity_file = str(id_file)
                log_success(f"Found identity file: {identity_file} (will use instead of empty agent)")
                # Create temporary agent to avoid multiple passphrase prompts
                try:
                    temp_sock, temp_pid = setup_temp_agent(id_file)
                    temp_agent_sock = temp_sock
                    temp_agent_pid = temp_pid
                    local_sock = True  # We now have a temporary agent
                    log_info("Using temporary SSH agent for initial connections")
                except Exception as e:
                    log_error("Failed to set up temporary SSH agent")
                    raise RuntimeError(f"Failed to set up temporary SSH agent: {e}")
            else:
                log_error("You have no key in your local agent and no identity file found!")
                raise RuntimeError("No keys in agent and no identity file found")
        else:
            log_success(f"You have {key_count} keys in your local agent")

    return {
        "local_sock": local_sock,
        "use_identity_file": use_identity_file,
        "identity_file": identity_file,
        "temp_agent_sock": temp_agent_sock,
        "temp_agent_pid": temp_agent_pid
    }
