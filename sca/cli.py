"""
CLI interface using click library.
"""
import os
import sys
from pathlib import Path
from typing import Optional, List

try:
    import click
except ImportError:
    click = None

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


if click:
    @click.command(context_settings={"ignore_unknown_options": True, "allow_extra_args": True})
    @click.option("-h", "--help", "show_help", is_flag=True, help="Show this help message and exit")
    @click.option("-d", "--debug", is_flag=True, help="Enable debug mode (verbose output)")
    @click.option("-r", "--reverse", is_flag=True, help="Reverse the order of agents when multiplexing")
    @click.option("-w", "--wait", is_flag=True, help="Run in background and monitor connection, restart if needed")
    @click.option("-e", "--env", "shell_mode", is_flag=True, help="Output environment variables in shell format")
    @click.option("-l", "--level", type=int, help="Set security level (0-3, default: auto-detect)")
    @click.option("--key", type=click.Choice(["local", "remote", "mux"]), help="Specify which key to use")
    # Multiplexer type removed - only Python multiplexer is supported
    @click.option("--list", "list_hosts_flag", is_flag=True, help="List all configured hosts")
    @click.option("--find", "find_hostname", type=str, help="Find and display information about a specific host")
    @click.option("--add", "add_hostname", type=str, help="Add a new host to the configuration")
    @click.option("-s", "--ssh", "ssh_mode", is_flag=True, help="Connect directly via ssh")
    @click.option("--connect", "connect_mode", is_flag=True, help="Alias for --ssh")
    @click.option("--kill", "kill_flag", is_flag=True, help="Kill all agents and remote connections")
    @click.argument("ssh_args", nargs=-1)
    def cli_main(
        show_help,
        debug,
        reverse,
        wait,
        shell_mode,
        level,
        key,
        list_hosts_flag,
        find_hostname,
        add_hostname,
        ssh_mode,
        connect_mode,
        kill_flag,
        ssh_args
    ):
        """SCA - SSH Central Agent - Cross-platform SSH agent multiplexing system."""
        # Handle --help
        if show_help:
            click.echo(click.get_current_context().get_help(), err=True)
            sys.exit(0)
        
        # Set DEBUG environment variable
        if debug:
            os.environ["DEBUG"] = "1"
        
        # Handle --kill
        if kill_flag:
            kill_all()
        
        # Handle --list
        if list_hosts_flag:
            playbook_dir = os.environ.get("PLAYBOOK_DIR", ".")
            list_hosts(playbook_dir)
            sys.exit(0)
        
        # Handle --find
        if find_hostname:
            playbook_dir = os.environ.get("PLAYBOOK_DIR", ".")
            find_host(playbook_dir, find_hostname)
            sys.exit(0)
        
        # Handle --add
        if add_hostname:
            playbook_dir = os.environ.get("PLAYBOOK_DIR", ".")
            add_host(playbook_dir, add_hostname)
            sys.exit(0)
        
        # Store options in environment for main logic to use
        if reverse:
            os.environ["REVERSE"] = "1"
        if wait:
            os.environ["WAIT"] = "1"
        if shell_mode:
            os.environ["SHELL_MODE"] = "1"
        if level is not None:
            os.environ["LEVEL"] = str(level)
        if key:
            os.environ["KEY"] = key
        # Always use Python multiplexer
        os.environ["MUX_TYPE"] = "python"
        if ssh_mode or connect_mode or ssh_args:
            os.environ["SSH_MODE"] = "1"
            if ssh_args:
                os.environ["SSH_ARGS"] = " ".join(ssh_args)
        
        # Return None to continue to main logic
        return None

else:
    # Fallback if click is not available
    def cli_main(*args, **kwargs):
        log_error("click library is required but not installed")
        log_info("Install it with: pip install click")
        sys.exit(1)
