"""
Multiplexer setup: Python (sshagentmux.py) implementation.
"""
import logging
import multiprocessing
import os
import shutil
import time
from pathlib import Path
from typing import Dict, Optional, Tuple

from . import agentmux
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
    log_info("Starting Python multiplexer (embedded agentmux)...")
    
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
    
    # Expand socket paths to absolute paths (sshagentmux.py needs absolute paths)
    from .platform_utils import expand_path
    from .socket_utils import verify_socket_working
    expanded_primary = str(expand_path(primary_sock))
    expanded_alternate = str(expand_path(alternate_sock))
    
    # Validate sockets before calling sshagentmux.py
    if not verify_socket_working(expanded_primary):
        raise RuntimeError(f"Primary socket is not working: {expanded_primary}")
    
    if not verify_socket_working(expanded_alternate):
        log_warn(f"Alternate socket is not working: {expanded_alternate}")
        log_warn("sshagentmux.py may fail or hang. Continuing anyway...")
    
    # Update environment with expanded paths
    env["SSH_AUTH_SOCK"] = expanded_primary
    
    # Start the handler in a forked process (embedded module)
    log_debug(f"Primary socket: {expanded_primary}")
    log_debug(f"Alternate socket: {expanded_alternate}")
    
    # Configure sshagentmux logging in child process
    log_level = logging.DEBUG if os.environ.get("DEBUG") == "1" else logging.INFO
    
    # Start the handler in a child process and wait for the socket path
    ready_pipein, ready_pipeout = multiprocessing.Pipe()
    parent_pid = os.getpid()
    
    mux_process = multiprocessing.Process(
        target=agentmux.run_agentmux,
        args=(ready_pipeout, parent_pid, expanded_primary, expanded_alternate, log_level),
        daemon=True
    )
    mux_process.start()
    ready_pipeout.close()
    
    timeout_seconds = 5
    if not ready_pipein.poll(timeout_seconds):
        mux_process.terminate()
        raise RuntimeError("Multiplexer did not report socket path in time")
    
    omux_socket = ready_pipein.recv()
    ready_pipein.close()
    
    if not omux_socket:
        mux_process.terminate()
        raise RuntimeError("Failed to get multiplexer socket")
    
    # Wait for socket to be ready
    if not wait_for_socket(omux_socket, max_iterations=10, delay=0.1):
        mux_process.terminate()
        raise RuntimeError(f"Multiplexer socket not ready: {omux_socket}")
    
    omux_pid = mux_process.pid
    os.environ["OMUX_SSH_AUTH_SOCK"] = omux_socket
    os.environ["OMUX_SSH_AGENT_PID"] = str(omux_pid or "")
    
    log_info(f"Python multiplexer started (PID: {omux_pid})")
    
    return {
        "socket": omux_socket,
        "pid": omux_pid
    }


