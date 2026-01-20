"""
Multiplexer setup: Python (sshagentmux.py) implementation.
"""
import os
import re
import shutil
import subprocess
import tempfile
import threading
import time
from pathlib import Path
from typing import Dict, Optional, Tuple

from .platform_utils import get_home_dir, is_macos, is_windows
from .logging_utils import (
    log_info, log_error, log_success, log_warn, log_debug, log_note,
    color_file_header, color_reset
)
from .socket_utils import wait_for_socket, verify_socket_working
from .process import kill_if_exists, process_exists


def setup_python_multiplexer(
    playbook_dir: str,
    sca_ssh_auth_sock: str,
    org_ssh_auth_sock: str,
    reverse: bool = False
) -> Dict[str, str]:
    """
    Setup Python multiplexer (sshagentmux.py).
    
    Args:
        playbook_dir: Directory containing sshagentmux.py
        sca_ssh_auth_sock: Remote agent socket
        org_ssh_auth_sock: Local/temporary agent socket
        reverse: Whether to reverse agent order
        
    Returns:
        Dictionary with 'socket' and 'pid' keys
    """
    log_info("Starting Python multiplexer (sshagentmux.py)...")
    
    # Resolve playbook_dir to absolute path
    playbook_dir_resolved = Path(playbook_dir).resolve()
    sshagentmux_path = playbook_dir_resolved / "sshagentmux.py"
    
    if not sshagentmux_path.exists():
        # Try alternative locations
        alt_paths = [
            Path.cwd() / "sshagentmux.py",
            Path(__file__).parent.parent / "sshagentmux.py",  # Relative to sca package
        ]
        for alt_path in alt_paths:
            if alt_path.exists():
                sshagentmux_path = alt_path.resolve()
                log_debug(f"Found sshagentmux.py at alternative location: {sshagentmux_path}")
                break
        else:
            raise RuntimeError(f"sshagentmux.py not found at {sshagentmux_path} or alternative locations")
    
    # The Python multiplexer uses SSH_AUTH_SOCK as the primary agent and --socket as the alternate
    # We set SSH_AUTH_SOCK to the remote agent, and pass the local/temporary agent as --socket
    env = os.environ.copy()
    
    if reverse:
        log_info("Reversing the order of the agents")
        env["SSH_AUTH_SOCK"] = sca_ssh_auth_sock
        primary_sock = sca_ssh_auth_sock
        alternate_sock = org_ssh_auth_sock
    else:
        # Set SSH_AUTH_SOCK to remote agent (primary)
        env["SSH_AUTH_SOCK"] = sca_ssh_auth_sock
        primary_sock = sca_ssh_auth_sock
        alternate_sock = org_ssh_auth_sock
    
    # Expand socket paths to absolute paths (sshagentmux.py needs absolute paths)
    from .platform_utils import expand_path
    from .socket_utils import verify_socket_working
    expanded_primary = str(expand_path(primary_sock))
    expanded_alternate = str(expand_path(alternate_sock))
    
    # Validate sockets before calling sshagentmux.py
    if not verify_socket_working(expanded_primary):
        raise RuntimeError(f"Primary socket is not working: {expanded_primary}")
    
    if not verify_socket_working(expanded_alternate):
        log_warn(f"Alternate socket is not working: {expanded_alternate}")
        log_warn("sshagentmux.py may fail or hang. Continuing anyway...")
    
    # Update environment with expanded paths
    env["SSH_AUTH_SOCK"] = expanded_primary
    
    # Run sshagentmux.py and capture its output (which sets environment variables)
    # sshagentmux.py daemonizes, outputs env vars to stdout, then exits
    cmd = [
        str(sshagentmux_path),
        "--socket", expanded_alternate,
        "--envname", "OMUX_"
    ]
    
    log_debug(f"Running: {' '.join(cmd)}")
    log_debug(f"Primary socket: {expanded_primary}")
    log_debug(f"Alternate socket: {expanded_alternate}")
    
    try:
        # sshagentmux.py should daemonize and exit quickly after printing env vars
        # Use a reasonable timeout - daemonization should complete in a few seconds
        # Use Popen so we can handle interrupts better
        process = subprocess.Popen(
            cmd,
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        
        # Set up signal handler to kill process on interrupt
        import signal
        def signal_handler(signum, frame):
            log_info("Interrupted, killing sshagentmux.py...")
            try:
                process.kill()
            except Exception:
                pass
            raise KeyboardInterrupt()
        
        old_handler = signal.signal(signal.SIGINT, signal_handler)
        
        try:
            # Read output line by line - sshagentmux.py outputs env vars and exits quickly
            # The daemon continues running in the background, but parent exits after printing
            stdout_lines = []
            stderr_lines = []
            
            # Read stdout until we get the env vars (usually just 1 line)
            import select
            import sys as sys_module
            
            # Use a shorter timeout for reading - env vars should appear quickly
            start_time = time.time()
            timeout_seconds = 5
            
            while time.time() - start_time < timeout_seconds:
                # Check if process has exited
                if process.poll() is not None:
                    # Process exited, read remaining output
                    remaining_stdout, remaining_stderr = process.communicate()
                    if remaining_stdout:
                        stdout_lines.extend(remaining_stdout.splitlines())
                    if remaining_stderr:
                        stderr_lines.extend(remaining_stderr.splitlines())
                    break
                
                # Try to read a line from stdout (non-blocking if possible)
                try:
                    # On Unix, we can use select to check if data is available
                    if hasattr(select, 'select'):
                        ready, _, _ = select.select([process.stdout], [], [], 0.1)
                        if ready:
                            line = process.stdout.readline()
                            if line:
                                stdout_lines.append(line.rstrip())
                                # If we got the env vars line, we're done
                                if "OMUX_SSH_AUTH_SOCK" in line:
                                    # Give it a moment to finish, then break
                                    time.sleep(0.1)
                                    break
                    else:
                        # Fallback: just wait a bit
                        time.sleep(0.1)
                except (ValueError, OSError):
                    # Pipe closed or error
                    break
            
            # If process is still running, that's OK - it's the daemon
            # Just get any remaining output
            if process.poll() is None:
                # Process is still running (daemon), try to read any buffered output
                try:
                    import fcntl
                    import errno
                    # Set non-blocking
                    flags = fcntl.fcntl(process.stdout.fileno(), fcntl.F_GETFL)
                    fcntl.fcntl(process.stdout.fileno(), fcntl.F_SETFL, flags | os.O_NONBLOCK)
                    while True:
                        try:
                            line = process.stdout.readline()
                            if not line:
                                break
                            stdout_lines.append(line.rstrip())
                            if "OMUX_SSH_AUTH_SOCK" in line:
                                break
                        except (IOError, OSError) as e:
                            if e.errno != errno.EAGAIN:
                                break
                            time.sleep(0.01)
                except (ImportError, AttributeError, OSError):
                    # fcntl not available or error, just use what we have
                    pass
            
            stdout = '\n'.join(stdout_lines)
            stderr = '\n'.join(stderr_lines)
            
            result = type('Result', (), {
                'returncode': 0 if stdout else process.returncode or 0,
                'stdout': stdout,
                'stderr': stderr
            })()
            
        except subprocess.TimeoutExpired:
            log_error("sshagentmux.py timed out - daemonization may have failed")
            log_error("This can happen if one of the agent sockets is not accessible")
            process.kill()
            try:
                stdout, stderr = process.communicate(timeout=2)
            except subprocess.TimeoutExpired:
                process.terminate()
                stdout, stderr = process.communicate(timeout=2)
            raise subprocess.TimeoutExpired(cmd, 5, stdout or "", stderr or "")
        finally:
            # Restore original signal handler
            signal.signal(signal.SIGINT, old_handler)
        
        if result.returncode != 0:
            log_error(f"sshagentmux.py failed with return code {result.returncode}")
            if result.stderr:
                log_error(f"stderr: {result.stderr}")
            if result.stdout:
                log_debug(f"stdout: {result.stdout}")
            raise RuntimeError(f"sshagentmux.py failed: {result.stderr or 'Unknown error'}")
        
        # Parse output to extract environment variables
        # Format: export OMUX_SSH_AUTH_SOCK=...; export OMUX_SSH_AGENT_PID=...;
        output = result.stdout
        omux_socket = None
        omux_pid = None
        
        for line in output.splitlines():
            if "OMUX_SSH_AUTH_SOCK" in line:
                match = re.search(r'OMUX_SSH_AUTH_SOCK=([^;]+)', line)
                if match:
                    omux_socket = match.group(1).strip().strip("'\"")
            elif "OMUX_SSH_AGENT_PID" in line:
                match = re.search(r'OMUX_SSH_AGENT_PID=([^;]+)', line)
                if match:
                    try:
                        omux_pid = int(match.group(1).strip())
                    except ValueError:
                        pass
        
        if not omux_socket:
            log_error(f"Failed to get multiplexer socket from sshagentmux.py")
            log_debug(f"Output was: {output}")
            raise RuntimeError("Failed to get multiplexer socket")
        
        log_info(f"Python multiplexer started (PID: {omux_pid})")
        
        return {
            "socket": omux_socket,
            "pid": omux_pid
        }
        
    except subprocess.TimeoutExpired:
        log_error("sshagentmux.py timed out (daemonization may have failed)")
        raise RuntimeError("sshagentmux.py timed out")
    except Exception as e:
        log_error(f"Error starting Python multiplexer: {e}")
        raise


