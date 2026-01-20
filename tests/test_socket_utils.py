"""Tests for socket utilities."""
from sca.socket_utils import (
    check_agent_socket, verify_socket_working,
    wait_for_socket, resolve_socket_path
)
from sca.platform_utils import is_windows


def test_resolve_socket_path():
    """Test socket path resolution."""
    # Non-existent path should return as-is
    result = resolve_socket_path("/tmp/nonexistent.sock")
    assert result == "/tmp/nonexistent.sock"
    
    # Windows named pipe should return as-is
    if is_windows():
        result = resolve_socket_path("\\\\.\\pipe\\test")
        assert result == "\\\\.\\pipe\\test"


def test_check_agent_socket_nonexistent():
    """Test checking non-existent socket."""
    result = check_agent_socket("/tmp/nonexistent_agent.sock")
    assert result is False


def test_verify_socket_working_nonexistent():
    """Test verifying non-existent socket."""
    result = verify_socket_working("/tmp/nonexistent_agent.sock")
    assert result is False


def test_wait_for_socket_timeout():
    """Test waiting for socket with timeout."""
    result = wait_for_socket("/tmp/nonexistent_agent.sock", max_iterations=2, delay=0.01)
    assert result is False
