"""
Colored logging utilities using ANSI codes (standard library only).
"""
import os
import sys


# ANSI color codes
class Colors:
    RESET = "\033[0m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    RED = "\033[31m"
    GREEN = "\033[32m"
    YELLOW = "\033[33m"
    BLUE = "\033[34m"
    MAGENTA = "\033[35m"
    CYAN = "\033[36m"
    GRAY = "\033[90m"
    WHITE = "\033[37m"


def _should_use_colors() -> bool:
    """Determine if colors should be used."""
    # Skip if explicitly disabled
    if os.environ.get("NO_COLOR"):
        return False
    
    # Skip if TERM is "dumb"
    term = os.environ.get("TERM", "")
    if term == "dumb":
        return False
    
    # Use colors if:
    # - stderr is a TTY (interactive terminal), OR
    # - FORCE_COLOR is explicitly set
    if os.environ.get("FORCE_COLOR") == "1":
        return True
    
    # Check if stderr is a TTY
    return sys.stderr.isatty()


def _colorize(text: str, color: str, bold: bool = False) -> str:
    """Apply color to text if colors are enabled."""
    if not _should_use_colors():
        return text
    
    # Use ANSI codes directly
    bold_code = Colors.BOLD if bold else ""
    reset = Colors.RESET
    return f"{bold_code}{color}{text}{reset}"


def log_error(message: str) -> None:
    """Log an error message in red."""
    colored = _colorize("ERROR:", Colors.RED, bold=True)
    msg = _colorize(message, Colors.RED)
    print(f"{colored} {msg}", file=sys.stderr, flush=True)


def log_warn(message: str) -> None:
    """Log a warning message in yellow."""
    colored = _colorize("WARNING:", Colors.YELLOW, bold=True)
    msg = _colorize(message, Colors.YELLOW)
    print(f"{colored} {msg}", file=sys.stderr, flush=True)


def log_info(message: str) -> None:
    """Log an info message in blue."""
    colored = _colorize("INFO:", Colors.BLUE, bold=True)
    msg = _colorize(message, Colors.BLUE)
    # Remove any carriage returns and ensure clean output
    clean_msg = msg.replace('\r', '').rstrip()
    print(f"{colored} {clean_msg}", file=sys.stderr, flush=True)


def log_success(message: str) -> None:
    """Log a success message in green."""
    checkmark = _colorize("✓", Colors.GREEN, bold=True)
    msg = _colorize(message, Colors.GREEN)
    clean_msg = msg.replace('\r', '').rstrip()
    print(f"{checkmark} {clean_msg}", file=sys.stderr, flush=True)


def log_debug(message: str) -> None:
    """Log a debug message in magenta (only if DEBUG=1)."""
    if os.environ.get("DEBUG") != "1":
        return
    colored = _colorize("DEBUG:", Colors.MAGENTA, bold=True)
    msg = _colorize(message, Colors.MAGENTA)
    clean_msg = msg.replace('\r', '').rstrip()
    print(f"{colored} {clean_msg}", file=sys.stderr, flush=True)


def log_note(message: str) -> None:
    """Log a note message in cyan."""
    colored = _colorize("NOTE:", Colors.CYAN, bold=True)
    msg = _colorize(message, Colors.CYAN)
    clean_msg = msg.replace('\r', '').rstrip()
    print(f"{colored} {clean_msg}", file=sys.stderr, flush=True)


# Color helpers for syntax highlighting
def color_host() -> str:
    """Return color code for host names (blue, bold)."""
    if not _should_use_colors():
        return ""
    return f"{Colors.BOLD}{Colors.BLUE}"


def color_directive() -> str:
    """Return color code for directives (cyan)."""
    if not _should_use_colors():
        return ""
    return Colors.CYAN


def color_value() -> str:
    """Return color code for values (yellow)."""
    if not _should_use_colors():
        return ""
    return Colors.YELLOW


def color_comment() -> str:
    """Return color code for comments (gray/dim)."""
    if not _should_use_colors():
        return ""
    return f"{Colors.DIM}{Colors.GRAY}"


def color_file_header() -> str:
    """Return color code for file headers (magenta, dim)."""
    if not _should_use_colors():
        return ""
    return f"{Colors.DIM}{Colors.MAGENTA}"


def color_reset() -> str:
    """Return reset color code."""
    if not _should_use_colors():
        return ""
    return Colors.RESET


def highlight_line(line: str) -> str:
    """Syntax highlight a line of SSH config."""
    import re
    
    # Host or Match directive (bold blue for keyword, yellow for values)
    host_match = re.match(r'^(\s*)(Host|Match)\s+(.+)$', line, re.IGNORECASE)
    if host_match:
        indent = host_match.group(1)
        keyword = host_match.group(2)
        values = host_match.group(3)
        return f"{indent}{color_host()}{keyword}{color_reset()} {color_value()}{values}{color_reset()}"
    
    # Comment lines (gray/dim)
    if re.match(r'^\s*#', line):
        return f"{color_comment()}{line}{color_reset()}"
    
    # Directives with values (cyan directive, yellow value)
    directive_match = re.match(r'^(\s+)([A-Za-z][A-Za-z0-9]*)\s+(.+)$', line)
    if directive_match:
        indent = directive_match.group(1)
        directive = directive_match.group(2)
        value = directive_match.group(3)
        return f"{indent}{color_directive()}{directive}{color_reset()} {color_value()}{value}{color_reset()}"
    
    # Default: just return the line
    return line
