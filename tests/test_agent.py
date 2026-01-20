"""Tests for agent operations."""
from pathlib import Path
from sca.agent import find_identity_file, get_key_fingerprint


def test_find_identity_file():
    """Test finding identity file."""
    # This will return None if no identity files exist, which is OK for testing
    result = find_identity_file()
    # Result should be None or a Path object
    assert result is None or isinstance(result, Path)


def test_get_key_fingerprint_nonexistent():
    """Test getting fingerprint of non-existent key."""
    result = get_key_fingerprint(Path("/tmp/nonexistent_key"))
    assert result is None
