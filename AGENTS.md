# AGENTS.md

## Project Overview
**SSH Secure Gateway (SCA)** - where **SCA** stands for **SSH Central Agent** - is a sophisticated, secure, multi-level SSH access system. It allows users to connect to remote hosts via a centralized jump host infrastructure while maintaining access to both local and remote SSH keys through a custom agent multiplexer.

The system implements SSH agent multiplexing to combine local and remote SSH keys (e.g., a local YubiKey agent and a remote server agent) into a single socket, allowing users to maintain their authentication while accessing different security levels.

## Architecture
The system relies on three main pillars:

1.  **Level-Based Access Control**: Users are assigned security levels (0-3) that determine which jump hosts they can access. Access is enforced via specific jump hosts (e.g., `sca-jmp-level1`).
2.  **SSH Agent Multiplexing**: The `sshagentmux.py` Python daemon acts as a proxy, combining multiple SSH agents into a single socket. This allows authentication challenges to be satisfied by keys from either source.
3.  **Dynamic Configuration**: The system uses Ansible and Jinja2 templates to generate complex `ssh_config` files dynamically based on user permissions and host definitions.

### Key Architecture Patterns
-   **Socket-based Communication**: Uses Unix sockets for SSH agent communication (`~/.ssh/scadev-agent.sock`, `~/.ssh/scadev-mux.sock`).
-   **Multi-level Jump Hosts**: `sca-jmp-level0` through `sca-jmp-level3`.
-   **Host Aliasing**: Multiple aliases per host for different connection modes (`*_my`, `*_local`, `*_org`, `*_mux`, `*_direct`).
-   **Environment Variable Passing**: Uses `SCA_*` environment variables for configuration state.

## Key Components & File Structure

### Core Scripts
-   **`sca`** (SSH Central Agent): The main CLI entry point. It sets up the environment, starts `sshagentmux.py`, and manages the SSH subshell.
-   **`sshagentmux.py`**: The core logic for the agent multiplexer. It implements the SSH agent protocol to forward signing requests to the appropriate upstream agent.
-   **`functions.sh`** - Shell functions for host management (list, find, add, connect).
-   **`addhost`** - Script to add new hosts to the configuration.

### Configuration Management
-   **`playbook.yml`**: Ansible playbook for system deployment and configuration.
-   **`config`**: The **generated** SSH configuration file. **Do not edit this directly.**
-   **`config_single`**: Single-host configuration variant.
-   **`localvars.yml`**: Local variable overrides for Ansible deployment.
-   **`hosts/`**: Directory containing individual host configuration files (YAML-like).
-   **`templates/`**: Jinja2 templates (`config.j2`, `sca.j2`, etc.) used to generate the final files.

## Development & Usage Guidelines

### The `sca` Script (SSH Central Agent)
This is the primary tool for interaction. It creates a subshell with `SSH_AUTH_SOCK` pointing to the multiplexer.

> [!WARNING]
> The `sca` script is generated from `templates/sca.j2`. **Do not edit `sca` directly.** Make changes in the template and regenerate.

**Common Commands:**
```bash
# Start SSH gateway with local key
./sca --key=local

# Start with remote key
./sca --key=remote

# List all configured hosts
./sca --list

# Find a specific host
./sca --find <hostname>

# Connect to specific host
./sca --ssh <hostname>

# Start and wait for connection (useful for background agents)
./sca --wait

# Kill all agents and remote connections
./sca --kill
```

### Configuration Management
**Important**: The `config` file is generated. Never edit it directly.
1.  **Modify**: Edit `playbook.yml`, `localvars.yml`, files in `hosts/`, or templates in `templates/`.
2.  **Apply**: Run `ansible-playbook playbook.yml` to regenerate the configuration.

### Adding a New Host
1.  Create or edit a file in `hosts/`.
2.  Follow the existing format (Host, Hostname, User, Port, etc.).
3.  Run the Ansible playbook to regenerate the `config`.

## Environment Variables
Key environment variables used throughout the system:
-   `SCA_SUBSHELL`: Indicates running in sca subshell (e.g., `SCA-KEY`).
-   `SCA_LEVEL`: The current user's security level (0-3).
-   `SCA_USER`: Remote username.
-   `SCA_JUMPHOST`: Current jump host.
-   `LOCAL_SSH_AUTH_SOCK`: Original SSH agent socket.
-   `MUX_SSH_AUTH_SOCK`: Multiplexed agent socket.
-   `SCA_SSH_AUTH_SOCK`: Remote agent socket.

## Security & Debugging

### Security Considerations
-   **Never log or expose SSH agent sockets or key material.**
-   User level permissions are enforced at the jump host level.
-   All connections route through controlled jump hosts.

### Debugging
-   **Verbose Output**: Use `./sca --debug` to see script execution flow.
-   **Agent Status**: Check `ssh-add -l` inside the subshell to see available keys.
-   **Socket Check**: Monitor socket files in `~/.ssh/scadev-*`.
-   **Multiplexer Logs**: `sshagentmux.py` logs to stderr. Check for "SSH_AGENT_ERROR" or signing failures.
-   **SSH Config Test**: `ssh -F config -T <hostname>`

## Deep Dive: sshagentmux.py

The `sshagentmux.py` script is the heart of the multi-agent capability. It acts as a transparent proxy that sits between the SSH client and two upstream agents.

### Core Logic
1.  **Initialization**:
    *   Takes an existing `SSH_AUTH_SOCK` (Default Agent) and a second socket path via `--socket` (Alternate Agent).
    *   Creates a new listening socket (the "Mux Socket").
    *   Spawns two threads (`UpstreamSocketThread`), one for each upstream agent, to maintain persistent connections.

2.  **Request Handling**:
    *   **Listing Keys (`SSH2_AGENTC_REQUEST_IDENTITIES`)**:
        *   When the client asks for keys, the multiplexer forwards the request to **both** agents.
        *   It merges the returned keys into a single list.
        *   **Crucially**, it builds an internal `_identity_map` that maps each key's blob to the specific agent that owns it.
    *   **Signing Data (`SSH2_AGENTC_SIGN_REQUEST`)**:
        *   When the client wants to sign data (authenticate), it sends the key blob.
        *   The multiplexer looks up the key in `_identity_map`.
        *   It forwards the signing request **only** to the correct agent.
    *   **Extensions**: Forwarded to the default agent.

3.  **Key Identification**:
    *   The script parses raw SSH key blobs to extract metadata (Type, Size, Fingerprint, Comment).
    *   This allows for detailed logging of which key is being used and from which agent.

4.  **Logging**:
    *   Logs are written to stderr.
    *   Look for `SSH: Found ... key` to see key discovery.
    *   Look for `SSH: Sign: ...` to see authentication attempts.

## Using ssh-agent-mux (Rust)

The `sca` (SSH Central Agent) script supports using `ssh-agent-mux` (a Rust-based alternative) instead of the built-in Python multiplexer. This is recommended for better performance and stability.

`ssh-agent-mux` combines multiple SSH agents' keys into a single agent, allowing you to use keys from different sources (like 1Password, YubiKey, or standard ssh-agent) simultaneously.

### Installation

**Option 1: From crates.io (recommended)**
```bash
cargo install ssh-agent-mux
```

**Option 2: Binary releases**
Download from [GitHub releases](https://github.com/overhacked/ssh-agent-mux/releases)

**Option 3: Build from source**
```bash
git clone https://github.com/overhacked/ssh-agent-mux.git
cd ssh-agent-mux/
cargo build --release
# Binary will be at target/release/ssh-agent-mux
```

### Configuration

Create `~/.config/ssh-agent-mux/ssh-agent-mux.toml`:

```toml
# Socket paths of upstream SSH agents to combine keys from
# The order affects which key is tried first for authentication
agent_sock_paths = [
    # Your local SSH agent (check with: echo $SSH_AUTH_SOCK)
    "~/.ssh/agent.sock",  # Replace with your actual local agent path
    # The remote agent from ssh-secure-gateway
    "~/.ssh/scadev-agent.sock",
]

# ssh-agent-mux's own socket path (default: ~/.ssh/ssh-agent-mux.sock)
# Your SSH client will connect to this socket
listen_path = "~/.ssh/ssh-agent-mux.sock"

# Log level: error, warn, info, or debug
log_level = "warn"
```

**Important**: 
- Use absolute paths or `~` for home directory
- The order of `agent_sock_paths` determines which keys are tried first
- Replace the first agent path with your actual local agent socket (find it with `echo $SSH_AUTH_SOCK`)

### Running the Service

**macOS:**
```bash
# Install and start the service (auto-starts on installation)
ssh-agent-mux --install-service
```

**Linux (systemd):**
```bash
# Install the service
ssh-agent-mux --install-service

# Enable and start the service
systemctl --user enable --now ssh-agent-mux.service
# OR
ssh-agent-mux --restart-service
```

### Usage in sca

The `sca` (SSH Central Agent) script will automatically detect `ssh-agent-mux` if it is installed. You can also force it:

```bash
./sca --mux=rust
```

If you want to force the Python version:

```bash
./sca --mux=python
```

### Verifying Setup

Check that ssh-agent-mux is running:
```bash
# Check if the process is running
pgrep -x ssh-agent-mux

# List keys available through ssh-agent-mux
SSH_AUTH_SOCK=~/.ssh/ssh-agent-mux.sock ssh-add -l
```

### Configuring Logging (macOS)

By default, `ssh-agent-mux` on macOS logs to the system log. To enable file-based logging for easier access, edit the launchd plist file:

**Edit `~/Library/LaunchAgents/net.ross-williams.ssh-agent-mux.plist`** and add these keys inside the `<dict>` section:

```xml
<key>StandardOutPath</key>
<string>/Users/YOUR_USERNAME/Library/Logs/ssh-agent-mux.log</string>
<key>StandardErrorPath</key>
<string>/Users/YOUR_USERNAME/Library/Logs/ssh-agent-mux.err.log</string>
```

Replace `YOUR_USERNAME` with your actual username, or use `$HOME`:

```bash
# Quick way to add logging to the plist
PLIST=~/Library/LaunchAgents/net.ross-williams.ssh-agent-mux.plist
if [ -f "$PLIST" ]; then
    # Backup first
    cp "$PLIST" "$PLIST.bak"
    
    # Add logging paths (insert before closing </dict>)
    sed -i '' '/<\/dict>/i\
    <key>StandardOutPath</key>\
    <string>'"$HOME"'/Library/Logs/ssh-agent-mux.log</string>\
    <key>StandardErrorPath</key>\
    <string>'"$HOME"'/Library/Logs/ssh-agent-mux.err.log</string>
    ' "$PLIST"
    
    # Restart the service
    launchctl kickstart -k gui/$(id -u)/net.ross-williams.ssh-agent-mux
fi
```

After adding these keys, you can easily view logs with:
```bash
tail -f ~/Library/Logs/ssh-agent-mux.log
tail -f ~/Library/Logs/ssh-agent-mux.err.log
```

### Debugging

**View logs:**

**macOS (launchd):**
```bash
# Check service status
launchctl list | grep ssh-agent-mux

# View logs (stdout/stderr go to system log)
log stream --predicate 'process == "ssh-agent-mux"' --level debug

# Or view recent logs
log show --predicate 'process == "ssh-agent-mux"' --last 1h

# Alternative: if running manually, logs go to stderr
# You can redirect to a file when starting:
# ssh-agent-mux 2>> ~/.config/ssh-agent-mux/ssh-agent-mux.log
```

**Linux (systemd):**
```bash
# Check service status
systemctl --user status ssh-agent-mux

# View logs
journalctl --user -u ssh-agent-mux

# Follow logs in real-time
journalctl --user -u ssh-agent-mux -f

# View logs with more detail
journalctl --user -u ssh-agent-mux -n 100
```

**Increase log verbosity:**

Edit `~/.config/ssh-agent-mux/ssh-agent-mux.toml` and set:
```toml
log_level = "debug"
```

Then restart the service:
```bash
# macOS
launchctl kickstart -k gui/$(id -u)/net.ross-williams.ssh-agent-mux

# Linux
systemctl --user restart ssh-agent-mux
```

**Common issues:**
- If keys aren't showing up, verify all `agent_sock_paths` are correct and accessible
- Ensure `~/.ssh/scadev-agent.sock` exists when `sca` is running
- Check that your local agent socket path is correct (it may change on macOS)
