"""
Socket utilities for SSH agent communication with cross-platform support.
Supports both Unix sockets (Linux/macOS) and Windows named pipes.
"""
import os
import stat
import subprocess
import time
from pathlib import Path

from .platform_utils import is_windows, is_named_pipe
from .logging_utils import log_debug


def check_agent_socket(socket_path: str) -> bool:
    """
    Check if an SSH agent socket is working by attempting to list keys.

    Args:
        socket_path: Path to the socket (Unix socket file or Windows named pipe)

    Returns:
        True if socket is working, False otherwise
    """
    if not socket_path:
        return False

    # On Windows, named pipes are handled differently
    if is_windows() and is_named_pipe(socket_path):
        return _check_named_pipe(socket_path)

    # For Unix sockets, check if file exists and is a socket
    socket_file = Path(socket_path)
    if not socket_file.exists():
        log_debug(f"Socket file does not exist: {socket_path}")
        return False

    # Check if it's a socket file (Unix)
    if is_windows():
        # On Windows, we can't use stat.S_ISSOCK, so try to connect
        return _check_unix_socket_windows(socket_path)
    else:
        try:
            mode = socket_file.stat().st_mode
            if not stat.S_ISSOCK(mode):
                log_debug(f"Path exists but is not a socket: {socket_path}")
                return False
        except OSError as e:
            log_debug(f"Error checking socket: {e}")
            return False

    # Try to use ssh-add to verify the socket works
    return _test_socket_with_ssh_add(socket_path)


def _check_named_pipe(pipe_path: str) -> bool:
    """Check if a Windows named pipe is accessible."""
    try:
        # Try to connect to the named pipe
        # Windows named pipes use \\.\pipe\name format
        if not pipe_path.startswith("\\\\.\\pipe\\"):
            # Try to normalize the path
            if pipe_path.startswith("//./pipe/"):
                pipe_path = pipe_path.replace("//./pipe/", "\\\\.\\pipe\\")
            else:
                pipe_path = f"\\\\.\\pipe\\{pipe_path}"

        # Try to connect (this is a simplified check)
        # Full implementation would use Windows API or try ssh-add
        return _test_socket_with_ssh_add(pipe_path)
    except Exception as e:
        log_debug(f"Error checking named pipe {pipe_path}: {e}")
        return False


def _check_unix_socket_windows(socket_path: str) -> bool:
    """Check Unix socket on Windows (WSL or Git Bash scenario)."""
    # On Windows, if we're in WSL or using a Unix-like environment,
    # we might still have Unix sockets
    socket_file = Path(socket_path)
    if socket_file.exists():
        return _test_socket_with_ssh_add(socket_path)
    return False


def _test_socket_with_ssh_add(socket_path: str) -> bool:
    """Test socket by running ssh-add -l."""
    env = os.environ.copy()
    env["SSH_AUTH_SOCK"] = socket_path

    try:
        result = subprocess.run(
            ["ssh-add", "-l"],
            env=env,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=5
        )
        return result.returncode == 0
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        return False


def verify_socket_working(socket_path: str) -> bool:
    """
    Verify socket exists and is working (combined check).

    Args:
        socket_path: Path to the socket

    Returns:
        True if socket exists and is working
    """
    if not socket_path:
        return False

    # Check existence first
    if is_windows() and is_named_pipe(socket_path):
        # Named pipes don't have file existence, just try to connect
        return check_agent_socket(socket_path)

    socket_file = Path(socket_path)
    if not socket_file.exists():
        return False

    # Check if it's working
    return check_agent_socket(socket_path)


def wait_for_socket(
    socket_path: str,
    max_iterations: int = 10,
    delay: float = 0.1
) -> bool:
    """
    Wait for socket to be created.

    Args:
        socket_path: Path to the socket
        max_iterations: Maximum number of iterations to wait
        delay: Delay between checks in seconds

    Returns:
        True if socket was created, False otherwise
    """
    iterations = 0

    while iterations < max_iterations:
        if verify_socket_working(socket_path):
            return True

        time.sleep(delay)
        iterations += 1

    return False


def resolve_socket_path(socket_path: str) -> str:
    """
    Resolve socket path, following symlinks if necessary.

    Args:
        socket_path: Path to the socket (may be a symlink)

    Returns:
        Resolved path
    """
    if is_windows() and is_named_pipe(socket_path):
        # Named pipes don't have symlinks
        return socket_path

    path = Path(socket_path)

    # Check if it's a symlink
    if path.is_symlink():
        try:
            resolved = path.resolve()
            log_debug(f"Socket {socket_path} is a symlink pointing to: {resolved}")
            return str(resolved)
        except (OSError, RuntimeError) as e:
            log_debug(f"Error resolving symlink {socket_path}: {e}")
            return socket_path

    return socket_path
