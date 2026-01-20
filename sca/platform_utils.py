"""
Platform detection and utilities for cross-platform support.
"""
import os
import sys
from pathlib import Path
from typing import Optional


def is_windows() -> bool:
    """Check if running on Windows."""
    return sys.platform == "win32"


def is_macos() -> bool:
    """Check if running on macOS."""
    return sys.platform == "darwin"


def is_linux() -> bool:
    """Check if running on Linux."""
    return sys.platform.startswith("linux")


def expand_path(path: str) -> Path:
    """Expand ~ and environment variables in path, return Path object."""
    expanded = os.path.expanduser(os.path.expandvars(path))
    return Path(expanded)


def get_home_dir() -> Path:
    """Get user home directory as Path."""
    return Path.home()


def get_ssh_dir() -> Path:
    """Get .ssh directory path."""
    return get_home_dir() / ".ssh"


def is_named_pipe(path: str) -> bool:
    """Check if path is a Windows named pipe."""
    if not is_windows():
        return False
    return path.startswith("\\\\.\\pipe\\") or path.startswith("\\\\")


def is_unix_socket(path: str) -> bool:
    """Check if path is a Unix socket (file-based)."""
    if is_windows():
        return False
    path_obj = Path(path)
    return path_obj.exists() and (path_obj.is_socket() if hasattr(path_obj, 'is_socket') else False)


def get_socket_type(path: str) -> str:
    """Determine socket type: 'unix', 'named_pipe', or 'unknown'."""
    if is_named_pipe(path):
        return "named_pipe"
    elif is_unix_socket(path):
        return "unix"
    else:
        # Try to detect by checking if it exists as a file
        path_obj = Path(path)
        if path_obj.exists():
            # On Unix, check if it's a socket file
            if not is_windows() and path_obj.is_socket():
                return "unix"
        return "unknown"
