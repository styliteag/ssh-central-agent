"""
SSH agent operations: finding identity files, setting up temporary agents, etc.
"""
import os
import subprocess
import time
from pathlib import Path
from typing import Optional, Tuple, List

from .platform_utils import get_ssh_dir, expand_path
from .logging_utils import log_info, log_error, log_success, log_debug
from .process import kill_if_exists


def find_identity_file() -> Optional[Path]:
    """
    Find identity file in common locations.
    
    Returns:
        Path to identity file if found, None otherwise
    """
    # First, check if MY_SSH_KEY is set (from localvars.yml via playbook)
    my_ssh_key = os.environ.get("MY_SSH_KEY")
    if my_ssh_key and my_ssh_key != "~/.ssh/id_unused":
        key_file = expand_path(my_ssh_key)
        if key_file.exists() and key_file.is_file() and os.access(key_file, os.R_OK):
            return key_file
    
    # Fall back to standard identity file locations
    ssh_dir = get_ssh_dir()
    for key_name in ["id_ed25519", "id_rsa", "id_ecdsa"]:
        key_file = ssh_dir / key_name
        if key_file.exists() and key_file.is_file() and os.access(key_file, os.R_OK):
            return key_file
    
    return None


def setup_temp_agent(identity_file: Path) -> Tuple[str, int]:
    """
    Setup temporary SSH agent for identity file.
    
    Args:
        identity_file: Path to the identity file
        
    Returns:
        Tuple of (socket_path, pid)
        
    Raises:
        RuntimeError: If agent setup fails
    """
    if not identity_file or not identity_file.exists():
        raise RuntimeError(f"Invalid identity file: {identity_file}")
    
    log_info("Creating temporary SSH agent for identity file...")
    
    # Start ssh-agent and capture output
    try:
        result = subprocess.run(
            ["ssh-agent", "-s"],
            capture_output=True,
            text=True,
            check=True,
            timeout=10
        )
        agent_output = result.stdout
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired, FileNotFoundError) as e:
        log_error("Failed to start temporary SSH agent")
        raise RuntimeError(f"Failed to start ssh-agent: {e}")
    
    # Parse output to extract socket and PID
    # Format: SSH_AUTH_SOCK=/tmp/ssh-XXXXXX/agent.12345; export SSH_AUTH_SOCK;
    #         SSH_AGENT_PID=12345; export SSH_AGENT_PID;
    temp_socket = None
    temp_pid = None
    
    for line in agent_output.splitlines():
        if "SSH_AUTH_SOCK" in line:
            # Extract socket path
            parts = line.split("=", 1)
            if len(parts) == 2:
                socket_part = parts[1].split(";")[0].strip()
                temp_socket = socket_part.strip("'\"")
        elif "SSH_AGENT_PID" in line:
            # Extract PID
            parts = line.split("=", 1)
            if len(parts) == 2:
                pid_part = parts[1].split(";")[0].strip()
                temp_pid = int(pid_part)
    
    if not temp_socket or not temp_pid:
        log_error("Failed to parse ssh-agent output")
        log_debug(f"ssh-agent output: {agent_output}")
        raise RuntimeError("Failed to parse ssh-agent output")
    
    # Set environment variables
    os.environ["SSH_AUTH_SOCK"] = temp_socket
    os.environ["SSH_AGENT_PID"] = str(temp_pid)
    
    # Add the identity file to the agent (this will prompt for passphrase once)
    log_info("Adding identity file to temporary agent (you will be prompted for passphrase once)...")
    try:
        result = subprocess.run(
            ["ssh-add", str(identity_file)],
            check=True,
            timeout=60  # Allow time for passphrase entry
        )
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as e:
        log_error("Failed to add identity file to temporary agent")
        cleanup_temp_agent(temp_pid, temp_socket)
        raise RuntimeError(f"Failed to add identity to agent: {e}")
    
    log_success(f"Temporary SSH agent created (PID: {temp_pid}, Socket: {temp_socket})")
    
    if os.environ.get("DEBUG") == "1":
        log_debug("Temporary agent details:")
        log_debug(f"  PID: {temp_pid}")
        log_debug(f"  Socket: {temp_socket}")
        log_debug("  Keys in temporary agent:")
        try:
            result = subprocess.run(
                ["ssh-add", "-l"],
                env={"SSH_AUTH_SOCK": temp_socket, **os.environ},
                capture_output=True,
                text=True,
                timeout=5
            )
            for line in result.stdout.splitlines():
                log_debug(f"    {line}")
        except Exception as e:
            log_debug(f"    Error listing keys: {e}")
    
    return temp_socket, temp_pid


def cleanup_temp_agent(pid: int, socket_path: str) -> None:
    """
    Cleanup temporary SSH agent.
    
    Args:
        pid: Process ID of the agent
        socket_path: Path to the agent socket
    """
    if pid:
        kill_if_exists(pid, "temporary SSH agent")
        # Wait a bit for clean shutdown
        time.sleep(0.5)
        # Force kill if still running
        try:
            if pid:
                kill_if_exists(pid, "temporary SSH agent")
        except Exception:
            pass
    
    if socket_path:
        socket_file = Path(socket_path)
        if socket_file.exists():
            log_info(f"Removing temporary SSH agent socket: {socket_path}")
            try:
                socket_file.unlink()
            except OSError as e:
                log_debug(f"Error removing socket {socket_path}: {e}")


def build_ssh_cmd(
    playbook_dir: str,
    ssh_config_file: str,
    temp_agent_sock: Optional[str] = None,
    use_identity_file: bool = False,
    identity_file: Optional[str] = None
) -> List[str]:
    """
    Build SSH command with optional identity file.
    
    Args:
        playbook_dir: Directory containing SSH config
        ssh_config_file: Name of SSH config file
        temp_agent_sock: Temporary agent socket path (if using temp agent)
        use_identity_file: Whether to use identity file directly
        identity_file: Path to identity file (if using directly)
        
    Returns:
        List of command arguments for subprocess
    """
    config_path = Path(playbook_dir) / ssh_config_file
    cmd = ["ssh", "-a", "-F", str(config_path)]
    
    # If we have a temporary agent, use it instead of -i to avoid multiple passphrase prompts
    if temp_agent_sock:
        cmd.extend(["-o", f"IdentityAgent={temp_agent_sock}"])
    elif use_identity_file and identity_file:
        cmd.extend(["-i", identity_file])
    
    return cmd


def get_agent_key_count(socket_path: str) -> int:
    """
    Get the number of keys in an SSH agent.
    
    Args:
        socket_path: Path to the agent socket
        
    Returns:
        Number of keys (0 if error or no keys)
    """
    try:
        result = subprocess.run(
            ["ssh-add", "-l"],
            env={"SSH_AUTH_SOCK": socket_path, **os.environ},
            capture_output=True,
            text=True,
            timeout=5
        )
        if result.returncode == 0:
            # Count non-empty lines (each key is one line)
            lines = [line for line in result.stdout.splitlines() if line.strip()]
            return len(lines)
    except Exception as e:
        log_debug(f"Error getting key count: {e}")
    
    return 0


def get_key_fingerprint(identity_file: Path) -> Optional[str]:
    """
    Get fingerprint of an identity file.
    
    Args:
        identity_file: Path to the identity file
        
    Returns:
        Fingerprint string if successful, None otherwise
    """
    try:
        result = subprocess.run(
            ["ssh-keygen", "-lf", str(identity_file)],
            capture_output=True,
            text=True,
            timeout=5
        )
        if result.returncode == 0:
            # Output format: "2048 SHA256:... comment (RSA)"
            # Extract the fingerprint (second field)
            parts = result.stdout.split()
            if len(parts) >= 2:
                return parts[1]
    except Exception as e:
        log_debug(f"Error getting fingerprint: {e}")
    
    return None


def check_key_in_agent(socket_path: str, fingerprint: str) -> bool:
    """
    Check if a key with given fingerprint is in the agent.
    
    Args:
        socket_path: Path to the agent socket
        fingerprint: Key fingerprint to check for
        
    Returns:
        True if key is found in agent
    """
    try:
        result = subprocess.run(
            ["ssh-add", "-l"],
            env={"SSH_AUTH_SOCK": socket_path, **os.environ},
            capture_output=True,
            text=True,
            timeout=5
        )
        if result.returncode == 0:
            return fingerprint in result.stdout
    except Exception as e:
        log_debug(f"Error checking key in agent: {e}")
    
    return False
