"""
Multiplexer setup: Python (sshagentmux.py) implementation.
"""
import os
import re
import shutil
import subprocess
import tempfile
import threading
from pathlib import Path
from typing import Dict, Optional, Tuple

from .platform_utils import get_home_dir, is_macos, is_windows
from .logging_utils import (
    log_info, log_error, log_success, log_warn, log_debug, log_note,
    color_file_header, color_reset
)
from .socket_utils import wait_for_socket, verify_socket_working
from .process import kill_if_exists, process_exists


def setup_python_multiplexer(
    playbook_dir: str,
    sca_ssh_auth_sock: str,
    org_ssh_auth_sock: str,
    reverse: bool = False
) -> Dict[str, str]:
    """
    Setup Python multiplexer (sshagentmux.py).
    
    Args:
        playbook_dir: Directory containing sshagentmux.py
        sca_ssh_auth_sock: Remote agent socket
        org_ssh_auth_sock: Local/temporary agent socket
        reverse: Whether to reverse agent order
        
    Returns:
        Dictionary with 'socket' and 'pid' keys
    """
    log_info("Starting Python multiplexer (sshagentmux.py)...")
    
    sshagentmux_path = Path(playbook_dir) / "sshagentmux.py"
    if not sshagentmux_path.exists():
        raise RuntimeError(f"sshagentmux.py not found at {sshagentmux_path}")
    
    # The Python multiplexer uses SSH_AUTH_SOCK as the primary agent and --socket as the alternate
    # We set SSH_AUTH_SOCK to the remote agent, and pass the local/temporary agent as --socket
    env = os.environ.copy()
    
    if reverse:
        log_info("Reversing the order of the agents")
        env["SSH_AUTH_SOCK"] = sca_ssh_auth_sock
        primary_sock = sca_ssh_auth_sock
        alternate_sock = org_ssh_auth_sock
    else:
        # Set SSH_AUTH_SOCK to remote agent (primary)
        env["SSH_AUTH_SOCK"] = sca_ssh_auth_sock
        primary_sock = sca_ssh_auth_sock
        alternate_sock = org_ssh_auth_sock
    
    # Run sshagentmux.py and capture its output (which sets environment variables)
    cmd = [
        str(sshagentmux_path),
        "--socket", alternate_sock,
        "--envname", "OMUX_"
    ]
    
    try:
        result = subprocess.run(
            cmd,
            env=env,
            capture_output=True,
            text=True,
            timeout=10
        )
        
        if result.returncode != 0:
            log_error(f"sshagentmux.py failed: {result.stderr}")
            raise RuntimeError(f"sshagentmux.py failed: {result.stderr}")
        
        # Parse output to extract environment variables
        # Format: export OMUX_SSH_AUTH_SOCK=...; export OMUX_SSH_AGENT_PID=...;
        output = result.stdout
        omux_socket = None
        omux_pid = None
        
        for line in output.splitlines():
            if "OMUX_SSH_AUTH_SOCK" in line:
                match = re.search(r'OMUX_SSH_AUTH_SOCK=([^;]+)', line)
                if match:
                    omux_socket = match.group(1).strip().strip("'\"")
            elif "OMUX_SSH_AGENT_PID" in line:
                match = re.search(r'OMUX_SSH_AGENT_PID=([^;]+)', line)
                if match:
                    omux_pid = int(match.group(1).strip())
        
        if not omux_socket:
            log_error("Failed to get multiplexer socket from sshagentmux.py")
            raise RuntimeError("Failed to get multiplexer socket")
        
        log_info(f"Python multiplexer started (PID: {omux_pid})")
        
        return {
            "socket": omux_socket,
            "pid": omux_pid
        }
        
    except subprocess.TimeoutExpired:
        log_error("sshagentmux.py timed out")
        raise RuntimeError("sshagentmux.py timed out")
    except Exception as e:
        log_error(f"Error starting Python multiplexer: {e}")
        raise


