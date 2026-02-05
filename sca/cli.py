"""
CLI interface using argparse (standard library).
"""
import argparse
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Optional

from .logging_utils import (
    log_error, log_info, log_success, highlight_line, color_file_header, color_reset,
    Colors, _should_use_colors
)
from .process import kill_all_sca_processes


def list_hosts(playbook_dir: str) -> None:
    """List all configured hosts."""
    hosts_dir = Path(playbook_dir) / "hosts"
    if not hosts_dir.exists():
        log_error(f"Hosts directory not found: {hosts_dir}")
        return

    print("## Listing Hosts", file=sys.stderr)
    for host_file in sorted(hosts_dir.glob("*")):
        if host_file.is_file():
            with open(host_file, 'r') as f:
                print(f.read())


def find_host_block_start(lines: list, line_num: int) -> Optional[int]:
    """Find the start line of a Host block containing the given line number."""
    start_line = line_num
    while start_line >= 0:
        if start_line >= len(lines):
            start_line -= 1
            continue
        line_content = lines[start_line]
        # Check if this line starts with "Host " or "Match " (with space)
        if re.match(r'^\s*(Host|Match)\s+', line_content, re.IGNORECASE):
            return start_line
        start_line -= 1
    return None


def extract_host_block(file_path: Path, start_line: int) -> Optional[tuple]:
    """Extract a Host block starting at the given line number.

    Returns:
        Tuple of (block_content, end_line) or None if not found
    """
    try:
        with open(file_path, 'r') as f:
            lines = f.readlines()

        if start_line >= len(lines):
            return None

        # Verify it's actually a Host or Match line
        host_line = lines[start_line]
        if not re.match(r'^\s*(Host|Match)\s+', host_line, re.IGNORECASE):
            return None

        # Find the end of this Host block (next Host or Match line, or end of file)
        end_line = len(lines)
        for next_line in range(start_line + 1, len(lines)):
            line_content = lines[next_line]
            if re.match(r'^\s*(Host|Match)\s+', line_content, re.IGNORECASE):
                end_line = next_line
                break

        # Extract the block (keep newlines for proper formatting)
        block_lines = lines[start_line:end_line]
        block_content = ''.join(block_lines).rstrip()

        return (block_content, end_line - 1)  # end_line is 0-based, but we want inclusive
    except Exception:
        return None


def process_matching_lines(file_path: Path, hostname: str) -> bool:
    """Search for hostname in file and extract matching Host blocks."""
    try:
        with open(file_path, 'r') as f:
            lines = f.readlines()

        # Find matching line numbers (ignore comment lines)
        matching_line_nums = []
        hostname_lower = hostname.lower()
        for i, line in enumerate(lines):
            # Skip comment lines (standalone comments starting with #)
            if re.match(r'^\s*#', line):
                continue
            if hostname_lower in line.lower():
                matching_line_nums.append(i)

        if not matching_line_nums:
            return False

        # Find unique Host block start lines
        unique_starts = set()
        for line_num in matching_line_nums:
            start_line = find_host_block_start(lines, line_num)
            if start_line is not None:
                unique_starts.add(start_line)

        if not unique_starts:
            return False

        # Extract and display each Host block
        for start_line in sorted(unique_starts):
            result = extract_host_block(file_path, start_line)
            if result:
                block_content, end_line = result

                # Print file header with line numbers (1-based for display)
                print(f"{color_file_header()}--- {file_path} (lines {start_line + 1}-{end_line + 1}) ---{color_reset()}", file=sys.stderr)

                # Print block with syntax highlighting
                # Filter: skip empty lines and standalone (non-indented) comment lines
                # The shell version processes line by line, skipping empty lines and standalone comments
                block_lines = block_content.split('\n')
                for line in block_lines:
                    # Skip empty lines
                    if not line.strip():
                        continue
                    # Skip standalone comment lines (lines that start with # after stripping)
                    # This matches the shell version: [[ "$line" == \#* ]] && continue
                    stripped = line.strip()
                    if stripped.startswith('#'):
                        continue
                    # Print the line with highlighting
                    print(highlight_line(line))
                print()  # Empty line between blocks

        return True
    except Exception as e:
        log_error(f"Error processing file {file_path}: {e}")
        return False


def find_host(playbook_dir: str, hostname: str) -> None:
    """Find and display information about a specific host."""
    config_file = Path(playbook_dir) / "config"
    hosts_dir = Path(playbook_dir) / "hosts"
    found_any = False

    print(f"Searching for host: {hostname}", file=sys.stderr)

    # Search in config file
    if config_file.exists():
        if process_matching_lines(config_file, hostname):
            found_any = True

    # Search in hosts/* files
    if hosts_dir.exists():
        for host_file in sorted(hosts_dir.glob("*")):
            if host_file.is_file():
                if process_matching_lines(host_file, hostname):
                    found_any = True

    if not found_any:
        print(f"No host found matching: {hostname}", file=sys.stderr)
        sys.exit(1)


def add_host(playbook_dir: str, hostname: str) -> None:
    """Add a new host to the configuration."""
    addhost_script = Path(playbook_dir) / "addhost"
    if not addhost_script.exists():
        log_error(f"addhost script not found: {addhost_script}")
        sys.exit(1)

    try:
        subprocess.run([str(addhost_script), hostname], check=True)
    except subprocess.CalledProcessError as e:
        log_error(f"Failed to add host: {e}")
        sys.exit(1)


def kill_all() -> None:
    """Kill all agents and remote connections."""
    sca_ssh_auth_sock = os.environ.get("SCA_SSH_AUTH_SOCK", "")
    mux_ssh_auth_sock = os.environ.get("MUX_SSH_AUTH_SOCK", "")

    log_info("Killing all agents and remote connections...")
    kill_all_sca_processes()
    log_info("Removing socket files")

    for sock in [sca_ssh_auth_sock, mux_ssh_auth_sock]:
        if sock:
            sock_path = Path(sock)
            if sock_path.exists():
                try:
                    sock_path.unlink()
                except OSError:
                    pass

    log_success("All agents and connections killed")
    sys.exit(0)


def _print_help() -> None:
    """Print colorful help message with examples."""
    use_colors = _should_use_colors()
    R = Colors.RESET if use_colors else ""
    B = Colors.BOLD if use_colors else ""
    C = Colors.CYAN if use_colors else ""
    G = Colors.GREEN if use_colors else ""
    Y = Colors.YELLOW if use_colors else ""
    CM = Colors.GRAY if use_colors else ""  # comment color (gray, no dim)

    sca = os.environ.get("SCA_SCRIPT", "sca")
    sca = Path(sca).name

    # Build example lines with aligned comments at column 48
    COL = 48
    def ex(cmd_vis_len: int, cmd_colored: str, comment: str) -> str:
        pad = " " * max(2, COL - 2 - cmd_vis_len)
        return f"  {cmd_colored}{pad}{CM}# {comment}{R}"

    n = len(sca)  # visible length of script name

    lines = [
        f"{B}{G}SCA - SSH Central Agent{R} - Cross-platform SSH agent multiplexing system",
        "",
        f"{B}Usage:{R}  {sca} [OPTIONS] [user@]hostname [ssh-args ...]",
        f"        {sca} -s [OPTIONS]",
        "",
        f"{B}Options:{R}",
        f"  {C}-h{R}, {C}--help{R}              Show this help message and exit",
        f"  {C}-v{R}, {C}--version{R}           Show version information and exit",
        f"  {C}-d{R}, {C}--debug{R}             Enable debug mode (verbose output)",
        f"  {C}-r{R}, {C}--reverse{R}           Reverse the order of agents when multiplexing",
        f"  {C}-w{R}, {C}--wait{R}              Run in background and monitor connection",
        f"  {C}-e{R}, {C}--env{R}               Output environment variables in shell format",
        f"  {C}-l{R}, {C}--level{R} {Y}LEVEL{R}       Set security level (0-3, default: auto-detect)",
        f"  {C}--key{R} {Y}{{local,remote,mux}}{R}",
        f"                          Specify which key to use",
        f"                            {Y}local{R}:  Use local SSH agent only",
        f"                            {Y}remote{R}: Use remote SSH agent only (default)",
        f"                            {Y}mux{R}:    Use multiplexed agent (local + remote)",
        f"  {C}-s{R}, {C}--shell{R}             Open a subshell with the MUX agent environment set",
        f"  {C}--list{R}                List all configured hosts",
        f"  {C}--find{R} {Y}HOSTNAME{R}       Find and display information about a specific host",
        f"  {C}--add{R} {Y}HOSTNAME{R}        Add a new host to the configuration",
        f"  {C}--kill{R}                Kill all agents and remote connections",
        f"  {C}--{R}                    End of options; remaining args passed to ssh",
        "",
        f"{B}Examples:{R}",
        f"  {CM}# Direct SSH connection (default){R}",
        ex(n + 1 + 9,          f"{sca} {Y}user@host{R}",                                         "Connect using remote agent"),
        ex(n + 12 + 1 + 9,     f"{sca} {C}--key=local{R} {Y}user@host{R}",                       "Connect using local agent"),
        ex(n + 10 + 1 + 9,     f"{sca} {C}--key=mux{R} {Y}user@host{R}",                         "Connect using multiplexed agent"),
        ex(n + 13 + 1 + 19,    f"{sca} {C}--key=remote{R} {C}--{R} {Y}-p9922 root@host{R}",      "SSH options after --"),
        "",
        f"  {CM}# Subshell mode{R}",
        ex(n + 3,              f"{sca} {C}-s{R}",                                                 "Open subshell with MUX agent env"),
        ex(n + 8 + 1 + 11,     f"{sca} {C}--shell{R} {C}--key=local{R}",                          "Subshell with local agent only"),
        "",
        f"  {CM}# Environment & management{R}",
        ex(6 + n + 16,         f"eval `{sca} {C}-e{R} {C}--key=local{R}`",                        "Set SSH_AUTH_SOCK in current shell"),
        ex(n + 7,              f"{sca} {C}--list{R}",                                             "List all configured hosts"),
        ex(n + 7 + 1 + 8,      f"{sca} {C}--find{R} {Y}myserver{R}",                              "Find host 'myserver'"),
        ex(n + 7,              f"{sca} {C}--wait{R}",                                             "Background monitoring mode"),
        ex(n + 7,              f"{sca} {C}--kill{R}",                                             "Clean up all agents"),
    ]
    print("\n".join(lines), file=sys.stderr)


def cli_main() -> Optional[None]:
    """
    Parse CLI arguments using argparse.

    Returns:
        None if command was handled (should exit), or None to continue to main logic
    """
    parser = argparse.ArgumentParser(
        description="SCA - SSH Central Agent - Cross-platform SSH agent multiplexing system",
        allow_abbrev=False,
        add_help=False  # We'll handle -h/--help manually
    )

    parser.add_argument("-h", "--help", action="store_true", help="Show this help message and exit")
    parser.add_argument("-v", "--version", action="store_true", help="Show version information and exit")
    parser.add_argument("-d", "--debug", action="store_true", help="Enable debug mode (verbose output)")
    parser.add_argument("-r", "--reverse", action="store_true", help="Reverse the order of agents when multiplexing")
    parser.add_argument("-w", "--wait", action="store_true", help="Run in background and monitor connection, restart if needed")
    parser.add_argument("-e", "--env", dest="shell_mode", action="store_true", help="Output environment variables in shell format")
    parser.add_argument("-l", "--level", type=int, help="Set security level (0-3, default: auto-detect)")
    parser.add_argument("--key", choices=["local", "remote", "mux"], help="Specify which key to use")
    parser.add_argument("--list", dest="list_hosts_flag", action="store_true", help="List all configured hosts")
    parser.add_argument("--find", dest="find_hostname", type=str, help="Find and display information about a specific host")
    parser.add_argument("--add", dest="add_hostname", type=str, help="Add a new host to the configuration")
    parser.add_argument("-s", "--shell", dest="subshell_mode", action="store_true", help="Open a subshell with the MUX agent environment set")
    parser.add_argument("--kill", dest="kill_flag", action="store_true", help="Kill all agents and remote connections")

    # Parse known args, leaving unknown args for SSH
    args, ssh_args = parser.parse_known_args()

    # Handle --version
    if args.version:
        from .platform_utils import expand_path

        python_exe = sys.executable
        # Try to get the real path (resolve symlinks)
        try:
            resolved = shutil.which(python_exe) or python_exe
            if resolved:
                python_exe = resolved
        except Exception:
            pass

        # Get socket paths (use defaults if not in environment)
        sca_ssh_auth_sock = os.environ.get("SCA_SSH_AUTH_SOCK", str(Path.home() / ".ssh" / "scadev-agent.sock"))
        mux_ssh_auth_sock = os.environ.get("MUX_SSH_AUTH_SOCK", str(Path.home() / ".ssh" / "scadev-mux.sock"))
        org_ssh_auth_sock = os.environ.get("ORG_SSH_AUTH_SOCK", os.environ.get("SSH_AUTH_SOCK", ""))

        # Expand paths
        sca_sock = str(expand_path(sca_ssh_auth_sock))
        mux_sock = str(expand_path(mux_ssh_auth_sock))
        local_sock = str(expand_path(org_ssh_auth_sock)) if org_ssh_auth_sock else "(not set)"

        print("SCA - SSH Central Agent (Python version)", file=sys.stderr)
        print(f"Python interpreter: {python_exe}", file=sys.stderr)
        print(f"Python version: {sys.version.split()[0]}", file=sys.stderr)
        print(f"Remote agent socket: {sca_sock}", file=sys.stderr)
        print(f"Multiplexer socket: {mux_sock}", file=sys.stderr)
        print(f"Local agent socket: {local_sock}", file=sys.stderr)
        sys.exit(0)

    # Handle --help or no arguments (no options and no SSH args)
    if args.help or (len(sys.argv) == 1 and not ssh_args):
        _print_help()
        sys.exit(0)

    # Set DEBUG environment variable
    if args.debug:
        os.environ["DEBUG"] = "1"

    # Handle --kill
    if args.kill_flag:
        kill_all()

    # Handle --list
    if args.list_hosts_flag:
        playbook_dir = os.environ.get("PLAYBOOK_DIR", ".")
        list_hosts(playbook_dir)
        sys.exit(0)

    # Handle --find
    if args.find_hostname:
        playbook_dir = os.environ.get("PLAYBOOK_DIR", ".")
        find_host(playbook_dir, args.find_hostname)
        sys.exit(0)

    # Handle --add
    if args.add_hostname:
        playbook_dir = os.environ.get("PLAYBOOK_DIR", ".")
        add_host(playbook_dir, args.add_hostname)
        sys.exit(0)

    # Store options in environment for main logic to use
    if args.reverse:
        os.environ["REVERSE"] = "1"
    if args.wait:
        os.environ["WAIT"] = "1"
    if args.shell_mode:
        os.environ["SHELL_MODE"] = "1"
    if args.level is not None:
        os.environ["LEVEL"] = str(args.level)
    if args.key:
        os.environ["KEY"] = args.key
    # Always use Python multiplexer
    os.environ["MUX_TYPE"] = "python"
    if args.subshell_mode:
        os.environ["SUBSHELL_MODE"] = "1"
    elif ssh_args:
        os.environ["SSH_MODE"] = "1"
        os.environ["SSH_ARGS"] = " ".join(ssh_args)

    # Return None to continue to main logic
    return None
