"""Tests for logging utilities."""
import os
from sca.logging_utils import (
    log_error, log_warn, log_info, log_success,
    log_debug, log_note, _should_use_colors
)


def test_logging_functions():
    """Test that logging functions don't crash."""
    # These should not raise exceptions
    log_error("Test error")
    log_warn("Test warning")
    log_info("Test info")
    log_success("Test success")
    log_note("Test note")
    
    # Debug should only log if DEBUG=1
    original_debug = os.environ.get("DEBUG")
    os.environ["DEBUG"] = "1"
    log_debug("Test debug")
    if original_debug:
        os.environ["DEBUG"] = original_debug
    else:
        os.environ.pop("DEBUG", None)


def test_color_detection():
    """Test color detection."""
    # Should return a boolean
    result = _should_use_colors()
    assert isinstance(result, bool)
