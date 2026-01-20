"""
Cross-platform process management utilities (standard library only).
"""
import os
import signal
import subprocess

from .logging_utils import log_info, log_debug
from .platform_utils import is_windows

# Process name constants
PROC_SSH_RAGENT = " ragent "
PROC_PYTHON_MUX = "sshagentmux.py"


def kill_if_exists(pid: int, name: str) -> None:
    """
    Kill a process if it exists and is running.
    
    Args:
        pid: Process ID
        name: Process name (for logging)
    """
    if not pid:
        return
    
    try:
        # Use os.kill (standard library)
        os.kill(pid, signal.SIGTERM)
        log_info(f"Killing {name} (PID {pid})")
    except ProcessLookupError:
        pass
    except PermissionError:
        log_debug(f"Permission denied when trying to kill PID {pid}")
    except Exception as e:
        log_debug(f"Error killing process {pid}: {e}")


def kill_processes(pattern: str, name: str) -> None:
    """
    Kill processes matching a pattern in their command line.
    
    Args:
        pattern: Pattern to match in process command line
        name: Process name (for logging)
    """
    killed_any = False
    
    # Use pkill if available (Unix only)
    if not is_windows():
        try:
            result = subprocess.run(
                ["pkill", "-f", pattern],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL
            )
            if result.returncode == 0:
                log_info(f"Killed {name} processes")
                killed_any = True
        except FileNotFoundError:
            log_debug("pkill not available, cannot kill processes by pattern")
    
    if not killed_any:
        log_debug(f"No processes found matching pattern: {pattern}")


def kill_process_by_name(process_name: str) -> None:
    """
    Kill processes by exact name.
    
    Args:
        process_name: Exact process name to kill
    """
    killed_any = False
    
    # Use pkill -x if available (Unix only)
    if not is_windows():
        try:
            result = subprocess.run(
                ["pkill", "-x", process_name],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL
            )
            if result.returncode == 0:
                log_info(f"Killed {process_name} processes")
                killed_any = True
        except FileNotFoundError:
            log_debug("pkill not available, cannot kill processes by name")
    
    if not killed_any:
        log_debug(f"No processes found with name: {process_name}")


def kill_all_sca_processes() -> None:
    """Kill all SCA-related processes."""
    kill_processes(PROC_SSH_RAGENT, "SSH agent forwarder")
    kill_processes(PROC_PYTHON_MUX, "Python multiplexer")


def check_ssh_agent_running() -> bool:
    """
    Check if SSH process with ragent is still running.
    
    Returns:
        True if SSH agent forwarder is running
    """
    # Use pgrep if available (Unix only)
    if not is_windows():
        try:
            result = subprocess.run(
                ["pgrep", "-f", PROC_SSH_RAGENT],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL
            )
            return result.returncode == 0
        except FileNotFoundError:
            log_debug("pgrep not available, cannot check SSH agent")
            return False
    else:
        # On Windows, we can't easily check without external tools
        log_debug("Cannot check SSH agent running status on Windows")
        return False


def verify_remote_agent_working(socket_path: str) -> bool:
    """
    Verify socket exists, is working, and SSH process is running.
    
    Args:
        socket_path: Path to the socket
        
    Returns:
        True if socket is working and SSH process is running
    """
    from .socket_utils import verify_socket_working
    
    return verify_socket_working(socket_path) and check_ssh_agent_running()


def process_exists(pid: int) -> bool:
    """
    Check if a process with the given PID exists.
    
    Args:
        pid: Process ID
        
    Returns:
        True if process exists
    """
    if not pid:
        return False
    
    try:
        # Use os.kill with signal 0 (doesn't kill, just checks)
        os.kill(pid, 0)
        return True
    except (ProcessLookupError, OSError):
        return False
