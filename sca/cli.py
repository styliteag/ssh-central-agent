"""
CLI interface using argparse (standard library).
"""
import argparse
import os
import sys
from pathlib import Path
from typing import Optional, List

from .logging_utils import log_error, log_info, log_success
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


def find_host(playbook_dir: str, hostname: str) -> None:
    """Find and display information about a specific host."""
    # This is a simplified version - full implementation would use the host search logic
    # from functions.sh (extract_host_block, process_matching_lines, etc.)
    config_file = Path(playbook_dir) / "config"
    hosts_dir = Path(playbook_dir) / "hosts"
    found_any = False
    
    print(f"Searching for host: {hostname}", file=sys.stderr)
    
    # Search in config file
    if config_file.exists():
        # Simplified search - just grep for the hostname
        try:
            with open(config_file, 'r') as f:
                content = f.read()
                if hostname.lower() in content.lower():
                    print(content)
                    found_any = True
        except Exception as e:
            log_error(f"Error reading config file: {e}")
    
    # Search in hosts/* files
    if hosts_dir.exists():
        for host_file in hosts_dir.glob("*"):
            if host_file.is_file():
                try:
                    with open(host_file, 'r') as f:
                        content = f.read()
                        if hostname.lower() in content.lower():
                            print(content)
                            found_any = True
                except Exception:
                    pass
    
    if not found_any:
        print(f"No host found matching: {hostname}", file=sys.stderr)
        sys.exit(1)


def add_host(playbook_dir: str, hostname: str) -> None:
    """Add a new host to the configuration."""
    addhost_script = Path(playbook_dir) / "addhost"
    if not addhost_script.exists():
        log_error(f"addhost script not found: {addhost_script}")
        sys.exit(1)
    
    import subprocess
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
    parser.add_argument("-d", "--debug", action="store_true", help="Enable debug mode (verbose output)")
    parser.add_argument("-r", "--reverse", action="store_true", help="Reverse the order of agents when multiplexing")
    parser.add_argument("-w", "--wait", action="store_true", help="Run in background and monitor connection, restart if needed")
    parser.add_argument("-e", "--env", dest="shell_mode", action="store_true", help="Output environment variables in shell format")
    parser.add_argument("-l", "--level", type=int, help="Set security level (0-3, default: auto-detect)")
    parser.add_argument("--key", choices=["local", "remote", "mux"], help="Specify which key to use")
    parser.add_argument("--list", dest="list_hosts_flag", action="store_true", help="List all configured hosts")
    parser.add_argument("--find", dest="find_hostname", type=str, help="Find and display information about a specific host")
    parser.add_argument("--add", dest="add_hostname", type=str, help="Add a new host to the configuration")
    parser.add_argument("-s", "--ssh", dest="ssh_mode", action="store_true", help="Connect directly via ssh")
    parser.add_argument("--connect", dest="connect_mode", action="store_true", help="Alias for --ssh")
    parser.add_argument("--kill", dest="kill_flag", action="store_true", help="Kill all agents and remote connections")
    
    # Parse known args, leaving unknown args for SSH
    args, ssh_args = parser.parse_known_args()
    
    # Handle --help
    if args.help:
        parser.print_help(file=sys.stderr)
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
    if args.ssh_mode or args.connect_mode or ssh_args:
        os.environ["SSH_MODE"] = "1"
        if ssh_args:
            os.environ["SSH_ARGS"] = " ".join(ssh_args)
    
    # Return None to continue to main logic
    return None
