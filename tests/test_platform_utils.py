"""Tests for platform utilities."""
import pytest
from sca.platform_utils import (
    is_windows, is_macos, is_linux,
    expand_path, get_home_dir, get_ssh_dir,
    is_named_pipe, is_unix_socket, get_socket_type
)


def test_platform_detection():
    """Test platform detection functions."""
    # At least one should be True
    assert is_windows() or is_macos() or is_linux()
    
    # They should be mutually exclusive
    platforms = [is_windows(), is_macos(), is_linux()]
    assert sum(platforms) == 1


def test_expand_path():
    """Test path expansion."""
    home = get_home_dir()
    expanded = expand_path("~/test")
    assert str(expanded).startswith(str(home))
    
    # Test with environment variable
    import os
    os.environ["TEST_VAR"] = "/tmp"
    expanded = expand_path("$TEST_VAR/test")
    assert "/tmp/test" in str(expanded)


def test_get_ssh_dir():
    """Test SSH directory path."""
    ssh_dir = get_ssh_dir()
    assert ssh_dir.name == ".ssh"
    assert ssh_dir.parent == get_home_dir()


def test_socket_type_detection():
    """Test socket type detection."""
    if is_windows():
        # Test Windows named pipe
        assert is_named_pipe("\\\\.\\pipe\\test")
        assert get_socket_type("\\\\.\\pipe\\test") == "named_pipe"
    else:
        # Test Unix socket (if we had a real socket file)
        assert not is_named_pipe("/tmp/test.sock")
        # get_socket_type will return "unknown" for non-existent files
        assert get_socket_type("/tmp/nonexistent.sock") == "unknown"
