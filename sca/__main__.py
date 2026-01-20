"""
Main entry point for SCA - SSH Central Agent.
"""
import os
import signal
import subprocess
import sys
import time
from pathlib import Path
from typing import Optional, Dict, Any

try:
    from . import cli
except ImportError:
    cli = None
from .agent import (
    find_identity_file, setup_temp_agent, cleanup_temp_agent,
    build_ssh_cmd, get_agent_key_count, get_key_fingerprint, check_key_in_agent
)
from .connection import (
    determine_security_level, start_remote_agent,
    check_existing_connections, validate_local_agent
)
from .multiplexer import setup_python_multiplexer
from .socket_utils import verify_socket_working, resolve_socket_path
from .process import kill_if_exists, verify_remote_agent_working
from .config import patch_jump_aliases
from .logging_utils import (
    log_info, log_error, log_success, log_warn, log_debug
)
from .platform_utils import expand_path, get_home_dir


# Constants
MAX_LEVEL = 99
CHECK_SECONDS = 30

# Global state
sca_exiting = False
ssh_pid: Optional[int] = None
mux_pid: Optional[int] = None
tail_log_pid: Optional[int] = None
temp_agent_pid: Optional[int] = None
temp_agent_sock: Optional[str] = None


def cleanup_handler(signum=None, frame=None):
    """Handle cleanup on exit."""
    global sca_exiting, ssh_pid, mux_pid, tail_log_pid, temp_agent_pid
    sca_exiting = True
    
    if temp_agent_pid:
        cleanup_temp_agent(temp_agent_pid, temp_agent_sock or "")
    
    if ssh_pid:
        kill_if_exists(ssh_pid, "SSH")
    
    if mux_pid:
        kill_if_exists(mux_pid, "MUX")
    
    if tail_log_pid:
        kill_if_exists(tail_log_pid, "log tail")


def execute_command_or_shell(
    playbook_dir: str,
    ssh_config_file: str,
    ssh_auth_sock: str,
    mux_ssh_auth_sock: str,
    org_ssh_auth_sock: str,
    ssh_args: Optional[str] = None
) -> None:
    """Execute command or start shell based on mode."""
    global temp_agent_pid, temp_agent_sock
    
    shell_mode = os.environ.get("SHELL_MODE") == "1"
    ssh_mode = os.environ.get("SSH_MODE") == "1"
    wait_mode = os.environ.get("WAIT") == "1"
    key = os.environ.get("KEY", "mux")
    
    if shell_mode:
        # Shell Mode: Output environment variables in ssh-agent format
        print(f"SSH_AUTH_SOCK={ssh_auth_sock}; export SSH_AUTH_SOCK;")
        agent_pid = mux_pid or ssh_pid
        if agent_pid:
            print(f"SSH_AGENT_PID={agent_pid}; export SSH_AGENT_PID;")
            print(f"echo Agent pid {agent_pid};")
        sys.exit(0)
    
    elif ssh_mode:
        # SSH Mode: Direct SSH connection
        # Expand paths before checking (needed for fallback logic)
        from .platform_utils import expand_path
        expanded_mux_sock = str(expand_path(mux_ssh_auth_sock))
        expanded_ssh_auth_sock = str(expand_path(ssh_auth_sock))
        
        # Select socket based on --key option
        if key == "mux":
            ssh_socket = expanded_mux_sock
        elif key == "local":
            ssh_socket = org_ssh_auth_sock
        else:
            # Default to mux, but fall back to remote agent if mux doesn't work
            if verify_socket_working(expanded_mux_sock):
                ssh_socket = expanded_mux_sock
            elif verify_socket_working(expanded_ssh_auth_sock):
                ssh_socket = expanded_ssh_auth_sock
            else:
                ssh_socket = expanded_mux_sock  # Will fail below with better error
        
        # Resolve symlink if needed
        resolved_socket = resolve_socket_path(ssh_socket)
        
        # Verify socket
        if not verify_socket_working(resolved_socket):
            # Try fallback to remote agent if mux failed
            if ssh_socket == expanded_mux_sock and verify_socket_working(expanded_ssh_auth_sock):
                resolved_socket = resolve_socket_path(expanded_ssh_auth_sock)
                ssh_socket = expanded_ssh_auth_sock
                log_info(f"Multiplexer socket not available, using remote agent: {resolved_socket}")
            else:
                log_error(f"Socket is not working: {resolved_socket}")
                sys.exit(1)
        
        # Debug output
        if os.environ.get("DEBUG") == "1":
            log_debug("Socket details:")
            log_debug(f"  Selected socket: {ssh_socket}")
            if Path(ssh_socket).is_symlink():
                log_debug(f"  Type: symlink -> {resolved_socket}")
            else:
                log_debug("  Type: regular socket")
            log_debug("  Available keys:")
            try:
                result = subprocess.run(
                    ["ssh-add", "-l"],
                    env={"SSH_AUTH_SOCK": resolved_socket, **os.environ},
                    capture_output=True,
                    text=True,
                    timeout=5
                )
                for line in result.stdout.splitlines():
                    log_debug(f"    {line}")
            except Exception:
                pass
        
        # Expand socket path to absolute path for SSH
        from .platform_utils import expand_path
        expanded_socket = str(expand_path(resolved_socket))
        
        # Build SSH command
        config_path = Path(playbook_dir) / ssh_config_file
        ssh_cmd = ["ssh", "-F", str(config_path)]
        
        # Override IdentityAgent to use the working socket
        # The config may specify a mux socket that doesn't exist, so we override it
        ssh_cmd.extend(["-o", f"IdentityAgent={expanded_socket}"])
        
        if os.environ.get("DEBUG") == "1":
            ssh_cmd.append("-v")
        
        # Add SSH arguments
        if ssh_args:
            import shlex
            ssh_cmd.extend(shlex.split(ssh_args))
        
        # Verify socket exists and is accessible before passing to SSH
        socket_path = Path(expanded_socket)
        if not socket_path.exists():
            log_error(f"Socket does not exist: {expanded_socket}")
            sys.exit(1)
        
        if not verify_socket_working(expanded_socket):
            log_error(f"Socket is not working: {expanded_socket}")
            sys.exit(1)
        
        log_info(f"Connecting via SSH config (SSH_AUTH_SOCK={expanded_socket}): ssh {' '.join(ssh_cmd[3:])}")
        
        # Execute SSH with SSH_AUTH_SOCK set in environment
        # Make sure to use a clean environment copy and explicitly set the socket
        env = os.environ.copy()
        env["SSH_AUTH_SOCK"] = expanded_socket
        
        # Debug: Only log the environment variable, don't test the agent (blocking)
        if os.environ.get("DEBUG") == "1":
            log_debug(f"Environment SSH_AUTH_SOCK={env.get('SSH_AUTH_SOCK')}")
        
        # Flush all output before handing control to SSH
        # This ensures no buffered output interferes with SSH's terminal control
        sys.stderr.flush()
        sys.stdout.flush()
        
        # Close any file descriptors that might interfere (except stdin/stdout/stderr)
        # This ensures SSH gets a clean terminal
        try:
            import resource
            maxfd = resource.getrlimit(resource.RLIMIT_NOFILE)[1]
            if maxfd == resource.RLIM_INFINITY:
                maxfd = 1024
            for fd in range(3, maxfd):
                try:
                    os.close(fd)
                except OSError:
                    pass
        except Exception:
            pass  # Ignore errors closing file descriptors
        
        # Use os.execvpe to completely replace this process with SSH
        # This gives SSH full terminal control without any Python wrapper interference
        try:
            os.execvpe(ssh_cmd[0], ssh_cmd, env)
            # execvpe never returns on success, so this should never be reached
            exit_code = 1
        except FileNotFoundError:
            log_error(f"SSH command not found: {ssh_cmd[0]}")
            exit_code = 1
        except Exception as e:
            log_error(f"SSH command failed: {e}")
            exit_code = 1
        
        # Clean up temporary agent after SSH connection
        if temp_agent_pid:
            log_info("Cleaning up temporary SSH agent after SSH connection")
            cleanup_temp_agent(temp_agent_pid, temp_agent_sock or "")
        
        sys.exit(exit_code)
    
    elif wait_mode:
        # Wait Mode: Monitor connection and restart if needed
        log_info(f"WAIT in a Loop and check every {CHECK_SECONDS} if the Connection is dead")
        while True:
            if sca_exiting:
                log_info("Exiting...")
                break
            
            # Check the appropriate socket
            socket_to_check = mux_ssh_auth_sock
            if not verify_socket_working(mux_ssh_auth_sock) or mux_ssh_auth_sock == os.environ.get("SCA_SSH_AUTH_SOCK", ""):
                socket_to_check = os.environ.get("SCA_SSH_AUTH_SOCK", "")
            
            if not verify_socket_working(socket_to_check):
                if sca_exiting:
                    log_info("Exiting due to intentional termination")
                    break
                log_error("Cannot connect to agent!")
                log_info("Restarting...")
                # Restart by re-running main
                os.environ.pop("SCA_SUBSHELL", None)
                os.environ["SSH_AUTH_SOCK"] = org_ssh_auth_sock
                # Re-import and call main
                main()
                sys.exit(255)
            else:
                print(".", end="", file=sys.stderr, flush=True)
            
            time.sleep(CHECK_SECONDS)
    
    else:
        # Default: Start Interactive Subshell
        log_info("Starting Subshell")
        shell = os.environ.get("SHELL", "/bin/sh")
        os.execv(shell, [shell])


def setup_new_connection(
    playbook_dir: str,
    ssh_config_file: str,
    sca_ssh_auth_sock: str,
    mux_ssh_auth_sock: str,
    rusername: str,
    org_ssh_auth_sock: str,
    temp_agent_sock_param: Optional[str],
    temp_agent_pid_param: Optional[int],
    use_identity_file: bool,
    identity_file: Optional[str],
    reverse: bool,
    level: Optional[int]
) -> Dict[str, Any]:
    """Setup a new connection."""
    global ssh_pid, mux_pid, temp_agent_sock, temp_agent_pid
    
    # Use parameter values, update globals
    temp_agent_sock = temp_agent_sock_param
    temp_agent_pid = temp_agent_pid_param
    
    log_info("No working agent found: Starting new connection")
    
    # Remove old sockets (expand paths first)
    from .platform_utils import expand_path
    for sock in [sca_ssh_auth_sock, mux_ssh_auth_sock]:
        sock_path = Path(expand_path(sock))
        if sock_path.exists():
            try:
                log_debug(f"Removing old socket: {sock_path}")
                sock_path.unlink()
            except OSError as e:
                log_debug(f"Error removing socket {sock_path}: {e}")
    
    # Determine security level
    try:
        my_level = determine_security_level(
            playbook_dir, ssh_config_file,
            mux_ssh_auth_sock=mux_ssh_auth_sock,
            temp_agent_sock=temp_agent_sock,
            use_identity_file=use_identity_file,
            identity_file=identity_file
        )
    except Exception as e:
        log_error(f"Failed to determine security level: {e}")
        sys.exit(1)
    
    log_info(f"You are a Level {my_level} user")
    
    # Handle level override
    if level is not None and level != MAX_LEVEL and level < my_level:
        log_warn(f"LOWER level to {level}")
        my_level = level
    elif level is None:
        log_error("Cannot find your level (Maybe something is not working). Stopping")
        sys.exit(1)
    
    # Start remote agent
    try:
        ssh_pid = start_remote_agent(
            my_level,
            playbook_dir,
            ssh_config_file,
            sca_ssh_auth_sock,
            rusername,
            temp_agent_sock=temp_agent_sock,
            use_identity_file=use_identity_file,
            identity_file=identity_file,
            max_level=MAX_LEVEL
        )
    except Exception as e:
        log_error(f"Failed to start remote agent: {e}")
        sys.exit(1)
    
    # Patch SSH config
    patch_jump_aliases(playbook_dir, ssh_config_file, my_level)
    
    log_success(f"Successfully started a remote agent at {sca_ssh_auth_sock}")
    
    # Determine local agent socket for multiplexing
    local_agent_sock = None
    if temp_agent_sock and verify_socket_working(temp_agent_sock):
        local_agent_sock = temp_agent_sock
        log_info("Will multiplex temporary agent (local key) with remote agent")
    elif org_ssh_auth_sock and verify_socket_working(org_ssh_auth_sock):
        local_agent_sock = org_ssh_auth_sock
        log_info("Will multiplex local agent with remote agent")
    else:
        log_info("No local agent, will use remote agent only")
    
    # Setup multiplexer
    omux_socket = None
    omux_pid = None
    skip_symlink = False
    
    # Expand socket path before checking
    from .platform_utils import expand_path
    expanded_sca_sock = str(expand_path(sca_ssh_auth_sock))
    
    if verify_socket_working(expanded_sca_sock):
        log_info("Muxing the agents to one")
        
        # Use local agent or dummy path
        org_sock_for_mux = local_agent_sock if local_agent_sock else "/dev/null"
        
        try:
            mux_result = setup_python_multiplexer(
                playbook_dir,
                expanded_sca_sock,
                org_sock_for_mux,
                reverse=reverse
            )
            omux_socket = mux_result["socket"]
            omux_pid = mux_result["pid"]
            skip_symlink = False
        except Exception as e:
            log_error(f"Failed to setup Python multiplexer: {e}")
            sys.exit(1)
        
        mux_pid = omux_pid
        
        # Create symlink if needed
        if not skip_symlink:
            omux_expanded = expand_path(omux_socket)
            target_expanded = expand_path(mux_ssh_auth_sock)
            if omux_expanded != target_expanded:
                try:
                    target_path = Path(target_expanded)
                    # Check if symlink already exists and points to the right target
                    if target_path.is_symlink():
                        current_target = target_path.readlink()
                        if str(current_target) == omux_socket:
                            log_debug(f"Symlink already exists and is correct: {target_expanded} -> {omux_socket}")
                        else:
                            target_path.unlink()
                            target_path.symlink_to(omux_socket)
                            log_debug(f"Updated symlink: {target_expanded} -> {omux_socket}")
                    elif target_path.exists():
                        # Regular file exists, remove it
                        target_path.unlink()
                        target_path.symlink_to(omux_socket)
                        log_debug(f"Replaced file with symlink: {target_expanded} -> {omux_socket}")
                    else:
                        # Ensure parent directory exists
                        target_path.parent.mkdir(parents=True, exist_ok=True)
                        target_path.symlink_to(omux_socket)
                        log_debug(f"Created symlink: {target_expanded} -> {omux_socket}")
                except OSError as e:
                    log_debug(f"Could not create symlink: {e}")
        
        os.environ["ORG_MUX_SSH_AUTH_SOCK"] = omux_socket
        # Use expanded path for environment variable
        expanded_mux_sock = str(expand_path(mux_ssh_auth_sock))
        os.environ["SSH_AUTH_SOCK"] = expanded_mux_sock
        
        log_info(f"Verifying with: 'SSH_AUTH_SOCK={expanded_mux_sock} ssh-add -l'")
        log_success("You can now use this key (even not in this SUBSHELL, thanks to .ssh/config magic)")
        try:
            result = subprocess.run(
                ["ssh-add", "-l"],
                env={"SSH_AUTH_SOCK": expanded_mux_sock, **os.environ},
                capture_output=True,
                text=True,
                timeout=5
            )
            for line in result.stdout.splitlines():
                log_info(line)
        except Exception:
            pass
    else:
        log_error(f"Remote agent socket not available: {expanded_sca_sock}")
        log_debug(f"Socket exists: {Path(expanded_sca_sock).exists()}")
        sys.exit(1)
    
    return {
        "my_level": my_level,
        "ssh_pid": ssh_pid,
        "mux_pid": mux_pid,
        "ssh_auth_sock": mux_ssh_auth_sock
    }


def use_existing_connection(
    playbook_dir: str,
    ssh_config_file: str,
    sca_ssh_auth_sock: str,
    mux_ssh_auth_sock: str,
    org_ssh_auth_sock: str,
    rusername: str,
    reverse: bool,
    level: Optional[int]
) -> Dict[str, Any]:
    """Use an existing connection."""
    global temp_agent_pid, temp_agent_sock, ssh_pid, mux_pid
    
    # Check if we need a temporary agent
    has_local_agent = False
    if org_ssh_auth_sock and verify_socket_working(org_ssh_auth_sock):
        has_local_agent = True
    elif os.environ.get("SSH_AUTH_SOCK") and verify_socket_working(os.environ["SSH_AUTH_SOCK"]):
        current_sock = os.environ["SSH_AUTH_SOCK"]
        if current_sock != sca_ssh_auth_sock and current_sock != mux_ssh_auth_sock:
            has_local_agent = True
    
    if not has_local_agent:
        # Check if mux socket has local key
        id_file = find_identity_file()
        needs_local_key = True
        if id_file and verify_socket_working(mux_ssh_auth_sock):
            id_fingerprint = get_key_fingerprint(id_file)
            if id_fingerprint and check_key_in_agent(mux_ssh_auth_sock, id_fingerprint):
                needs_local_key = False
                log_info("Mux socket already has local key, no need to create temporary agent")
        
        if needs_local_key and id_file:
            log_info("Creating temporary SSH agent for local key (needed for connection)...")
            try:
                temp_sock, temp_pid = setup_temp_agent(id_file)
                temp_agent_sock = temp_sock
                temp_agent_pid = temp_pid
                log_info("Temporary SSH agent created")
            except Exception as e:
                log_warn(f"Failed to create temporary agent: {e}")
    
    # Determine level
    try:
        my_level = determine_security_level(
            playbook_dir, ssh_config_file,
            mux_ssh_auth_sock=mux_ssh_auth_sock,
            temp_agent_sock=temp_agent_sock,
            use_identity_file=bool(temp_agent_sock),
            identity_file=str(find_identity_file()) if find_identity_file() else None
        )
    except Exception as e:
        log_error(f"Failed to determine security level: {e}")
        sys.exit(1)
    
    # Patch SSH config
    patch_jump_aliases(playbook_dir, ssh_config_file, my_level)
    
    # Handle level override
    if level is not None and level != MAX_LEVEL and level < my_level:
        log_warn(f"LOWER level to {level}")
        my_level = level
    
    # Setup multiplexer if needed
    # We need mux if we have both a local agent (temp or regular) and remote agent
    local_agent_sock = None
    if temp_agent_sock and verify_socket_working(temp_agent_sock):
        local_agent_sock = temp_agent_sock
    elif has_local_agent:
        # Use the existing local agent
        if org_ssh_auth_sock and verify_socket_working(org_ssh_auth_sock):
            local_agent_sock = org_ssh_auth_sock
        elif os.environ.get("SSH_AUTH_SOCK") and verify_socket_working(os.environ["SSH_AUTH_SOCK"]):
            current_sock = os.environ["SSH_AUTH_SOCK"]
            if current_sock != sca_ssh_auth_sock and current_sock != mux_ssh_auth_sock:
                local_agent_sock = current_sock
    
    # Expand socket paths before checking
    expanded_sca_sock = str(expand_path(sca_ssh_auth_sock))
    
    if local_agent_sock and verify_socket_working(expanded_sca_sock):
        needs_mux_setup = True
        expanded_mux_sock_check = str(expand_path(mux_ssh_auth_sock))
        if verify_socket_working(expanded_mux_sock_check):
            # Check if mux already has the keys we need
            local_key_fingerprint = None
            try:
                result = subprocess.run(
                    ["ssh-add", "-l"],
                    env={"SSH_AUTH_SOCK": local_agent_sock, **os.environ},
                    capture_output=True,
                    text=True,
                    timeout=5
                )
                if result.returncode == 0 and result.stdout:
                    parts = result.stdout.splitlines()[0].split()
                    if len(parts) >= 2:
                        local_key_fingerprint = parts[1]
            except Exception:
                pass
            
            if local_key_fingerprint and check_key_in_agent(expanded_mux_sock_check, local_key_fingerprint):
                needs_mux_setup = False
                log_info("Mux socket already has local keys, skipping setup")
        
        if needs_mux_setup:
            log_info("Setting up multiplexer for local agent + remote agent")
            org_sock_for_mux = local_agent_sock
            
            try:
                mux_result = setup_python_multiplexer(
                    playbook_dir,
                    expanded_sca_sock,
                    org_sock_for_mux,
                    reverse=reverse
                )
                omux_socket = mux_result["socket"]
                omux_pid = mux_result["pid"]
                skip_symlink = False
            except Exception as e:
                log_error(f"Failed to setup Python multiplexer: {e}")
                return {"my_level": my_level, "ssh_auth_sock": sca_ssh_auth_sock}
            
            mux_pid = omux_pid
            
            if not skip_symlink:
                omux_expanded = expand_path(omux_socket)
                target_expanded = expand_path(mux_ssh_auth_sock)
                if omux_expanded != target_expanded:
                    try:
                        target_path = Path(target_expanded)
                        # Check if symlink already exists and points to the right target
                        if target_path.is_symlink():
                            current_target = target_path.readlink()
                            if str(current_target) == omux_socket:
                                log_debug(f"Symlink already exists and is correct: {target_expanded} -> {omux_socket}")
                            else:
                                target_path.unlink()
                                target_path.symlink_to(omux_socket)
                                log_debug(f"Updated symlink: {target_expanded} -> {omux_socket}")
                        elif target_path.exists():
                            # Regular file exists, remove it
                            target_path.unlink()
                            target_path.symlink_to(omux_socket)
                            log_debug(f"Replaced file with symlink: {target_expanded} -> {omux_socket}")
                        else:
                            # Ensure parent directory exists
                            target_path.parent.mkdir(parents=True, exist_ok=True)
                            target_path.symlink_to(omux_socket)
                            log_debug(f"Created symlink: {target_expanded} -> {omux_socket}")
                    except OSError as e:
                        log_debug(f"Could not create symlink: {e}")
            
            os.environ["ORG_MUX_SSH_AUTH_SOCK"] = omux_socket
            # Use expanded path for environment variable
            expanded_mux_sock = str(expand_path(mux_ssh_auth_sock))
            os.environ["SSH_AUTH_SOCK"] = expanded_mux_sock
    
    # Use the multiplexed socket if available, otherwise use remote agent
    # Expand paths before checking
    expanded_mux_sock = str(expand_path(mux_ssh_auth_sock))
    expanded_sca_sock = str(expand_path(sca_ssh_auth_sock))
    
    if verify_socket_working(expanded_mux_sock):
        log_info(f"Using working multiplexed SSH_AUTH_SOCK={expanded_mux_sock}")
        final_sock = expanded_mux_sock
    elif verify_socket_working(expanded_sca_sock):
        log_info(f"Using working remote SSH_AUTH_SOCK={expanded_sca_sock}")
        final_sock = expanded_sca_sock
        os.environ["MUX_SSH_AUTH_SOCK"] = expanded_sca_sock
    else:
        log_error("No working agent socket found")
        log_debug(f"Mux socket: {expanded_mux_sock} (exists: {Path(expanded_mux_sock).exists()})")
        log_debug(f"Remote socket: {expanded_sca_sock} (exists: {Path(expanded_sca_sock).exists()})")
        sys.exit(1)
    
    os.environ["SSH_AUTH_SOCK"] = final_sock
    
    # Show available keys
    log_info(f"Verifying with: 'SSH_AUTH_SOCK={final_sock} ssh-add -l'")
    try:
        result = subprocess.run(
            ["ssh-add", "-l"],
            env={"SSH_AUTH_SOCK": final_sock, **os.environ},
            capture_output=True,
            text=True,
            timeout=5
        )
        for line in result.stdout.splitlines():
            log_info(line)
    except Exception:
        pass
    
    return {
        "my_level": my_level,
        "ssh_pid": ssh_pid,
        "mux_pid": mux_pid,
        "ssh_auth_sock": final_sock
    }


def main():
    """Main entry point."""
    global sca_exiting, ssh_pid, mux_pid, temp_agent_pid, temp_agent_sock
    
    # Set up signal handlers
    signal.signal(signal.SIGINT, cleanup_handler)
    signal.signal(signal.SIGTERM, cleanup_handler)
    
    # Get configuration from environment (set by Ansible-generated script)
    # Resolve playbook_dir to absolute path - if not set, use directory containing this module
    playbook_dir_env = os.environ.get("PLAYBOOK_DIR", "")
    if playbook_dir_env:
        playbook_dir = str(Path(playbook_dir_env).resolve())
    else:
        # Default to directory containing sca package (where sshagentmux.py should be)
        # Try to find it relative to the sca package location
        sca_package_dir = Path(__file__).parent.parent.resolve()
        if (sca_package_dir / "sshagentmux.py").exists():
            playbook_dir = str(sca_package_dir)
        else:
            # Fallback to current directory
            playbook_dir = str(Path.cwd().resolve())
    
    ssh_config_file = os.environ.get("SSH_CONFIG_FILE", "config")
    sca_ssh_auth_sock = os.environ.get("SCA_SSH_AUTH_SOCK", str(Path.home() / ".ssh" / "scadev-agent.sock"))
    mux_ssh_auth_sock = os.environ.get("MUX_SSH_AUTH_SOCK", str(Path.home() / ".ssh" / "scadev-mux.sock"))
    rusername = os.environ.get("RUSERNAME", "")
    org_ssh_auth_sock = os.environ.get("ORG_SSH_AUTH_SOCK", os.environ.get("SSH_AUTH_SOCK", ""))
    
    # If RUSERNAME is not set, try to read from localvars.yml
    if not rusername:
        localvars_path = Path(playbook_dir) / "localvars.yml"
        if localvars_path.exists():
            try:
                with open(localvars_path, 'r') as f:
                    for line in f:
                        if line.strip().startswith("remote_username:"):
                            rusername = line.split(":", 1)[1].strip()
                            break
            except Exception:
                pass
    
    # Validate rusername
    if not rusername:
        from .logging_utils import log_error
        log_error("RUSERNAME not set. Set it in environment or localvars.yml")
        log_error("Example: export RUSERNAME=wb")
        sys.exit(1)
    
    # Parse CLI arguments (if click is available)
    if cli and hasattr(cli, 'click') and cli.click:
        try:
            cli.cli_main(standalone_mode=False)
        except SystemExit:
            # CLI handled the command (--list, --find, --add, --kill)
            return
    elif cli and hasattr(cli, 'cli_main'):
        # Fallback: try to use CLI even without click
        try:
            result = cli.cli_main()
            if result is None:
                # CLI handled it, exit
                return
        except SystemExit:
            return
    
    # Get options from environment (set by CLI)
    reverse = os.environ.get("REVERSE") == "1"
    level_str = os.environ.get("LEVEL")
    level = int(level_str) if level_str else MAX_LEVEL
    ssh_args = os.environ.get("SSH_ARGS", "")
    
    # Check for existing connections
    conn_status = check_existing_connections(sca_ssh_auth_sock, mux_ssh_auth_sock)
    my_socks_working = conn_status["working"]
    
    # Validate local agent
    try:
        agent_info = validate_local_agent(org_ssh_auth_sock)
        temp_agent_sock = agent_info.get("temp_agent_sock")
        temp_agent_pid = agent_info.get("temp_agent_pid")
        use_identity_file = agent_info.get("use_identity_file", False)
        identity_file = agent_info.get("identity_file")
    except RuntimeError as e:
        log_error(str(e))
        sys.exit(1)
    
    # Setup connection
    if not my_socks_working:
        result = setup_new_connection(
            playbook_dir, ssh_config_file,
            sca_ssh_auth_sock, mux_ssh_auth_sock,
            rusername, org_ssh_auth_sock,
            agent_info.get("temp_agent_sock"),
            agent_info.get("temp_agent_pid"),
            use_identity_file, identity_file,
            reverse, level
        )
    else:
        result = use_existing_connection(
            playbook_dir, ssh_config_file,
            sca_ssh_auth_sock, mux_ssh_auth_sock,
            org_ssh_auth_sock, rusername,
            reverse, level
        )
    
    my_level = result["my_level"]
    ssh_pid = result.get("ssh_pid")
    mux_pid = result.get("mux_pid")
    final_ssh_auth_sock = result["ssh_auth_sock"]
    
    # Set environment variables
    os.environ["SCA_SSH_AUTH_SOCK"] = sca_ssh_auth_sock
    os.environ["MUX_SSH_AUTH_SOCK"] = mux_ssh_auth_sock
    os.environ["SCA_SUBSHELL"] = "SCA-KEY"
    os.environ["SCA_USER"] = rusername
    os.environ["SCA_JUMPHOST"] = f"sca-jump-level{my_level}"
    os.environ["SCA_LEVEL"] = str(my_level)
    
    logname = os.environ.get("LOGNAME", os.environ.get("USER", ""))
    log_success(f"Hello {rusername}({logname}) you are level {my_level} and using sca-jump-level{my_level}")
    
    # Execute command or start shell
    execute_command_or_shell(
        playbook_dir, ssh_config_file,
        final_ssh_auth_sock, mux_ssh_auth_sock,
        org_ssh_auth_sock, ssh_args
    )


if __name__ == "__main__":
    main()
