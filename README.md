# SSH Central Agent (SCA)

**SCA** stands for **SSH Central Agent** - a sophisticated SSH gateway system that provides secure, multi-level SSH access to remote hosts through a centralized jump host infrastructure.

## What is SCA?

The **SSH Central Agent (SCA)** is a gateway system that:

- **Centralizes SSH agent management** - Combines local and remote SSH keys into a single, unified agent
- **Provides multi-level access control** - Routes connections through security-level-based jump hosts (levels 0-3)
- **Enables seamless authentication** - Allows you to use keys from different sources (local YubiKey, remote server agents, etc.) simultaneously
- **Manages secure connections** - Handles SSH agent forwarding and multiplexing automatically

The `sca` command creates a subshell environment where your SSH client can access both local and remote SSH keys through a single agent socket, making it easy to connect to hosts across different security zones without manually managing multiple SSH agents.

## Use Case: Centralized YubiKey Access via SSH Gateway

A common enterprise deployment pattern involves:

1. **SSH Gateway Hosts**: Multi-level jump hosts (`sca-jmp-level1`, `sca-jmp-level2`, `sca-jmp-level3`, etc.) that route connections to protected infrastructure based on security levels
2. **Central Servers with YubiKeys**: Each jump host (level 1 and above) can have one or more YubiKeys physically attached and managed by the SSH agent. Level 0 typically does not use YubiKeys.
3. **Local Agent Access**: Users connect to the appropriate gateway based on their security level, which forwards the remote SSH agent socket (containing YubiKey keys) to their local machine

### How It Works

When you run `sca`, it:
- Connects to the SSH gateway host corresponding to your security level (level 1-x) using your local credentials
- Establishes an SSH agent forwarding connection to the jump host's agent (which has access to one or more YubiKeys)
- Creates a local socket (`~/.ssh/scadev-agent.sock`) that proxies authentication requests to the remote YubiKey(s)
- Multiplexes this remote agent with your local agent, giving you access to both sets of keys seamlessly

**Multi-YubiKey Support**: Each jump host can have multiple YubiKeys attached, and all keys from all YubiKeys on that host become available through the forwarded agent socket. This allows for redundancy, different key types, or multiple security roles within the same level.

### Benefits

- **Centralized Security**: YubiKeys remain physically secured at the jump host servers, never leaving the controlled environment
- **Multi-Level Architecture**: Different security levels (1-x) can have their own YubiKey(s), allowing for granular access control and separation of concerns
- **Scalable Key Management**: Each level can have one or more YubiKeys, supporting redundancy, different key types, or multiple security roles
- **No Physical Access Required**: Users don't need direct physical access to the YubiKeys - authentication happens remotely through the gateway
- **Seamless Experience**: Once connected via `sca`, you can use YubiKey-protected keys just like local keys - no manual intervention needed
- **Multi-User Access**: Multiple authorized users at the same security level can access the same secure keys simultaneously through their own gateway connections
- **Audit Trail**: All authentication attempts go through the centralized gateway, providing better security monitoring and logging
- **Key Protection**: Private keys never leave the secure server - only signing operations are forwarded, keeping the actual key material safe

This architecture is ideal for organizations that need to provide secure SSH access to sensitive infrastructure while maintaining strict control over hardware security keys across multiple security levels.

### Server Setup Documentation

Detailed documentation for setting up the `sca-jmp` (jump host) and `sca-key` (YubiKey server) infrastructure will be published in a future release. This will include:

- Jump host configuration and deployment
- YubiKey server setup and agent configuration
- Multi-level security architecture implementation
- Best practices for production deployments

**Interested in Enterprise Deployment?**

If your company is interested in implementing this SSH gateway architecture with centralized YubiKey management, we can help with setup and deployment. Please contact us for assistance with:

- Architecture design and planning
- Jump host and YubiKey server configuration
- Security level implementation
- Custom deployment requirements

## Quick Start

### Prerequisites

1. **Generate an SSH key** (if you don't have one):

```bash
# Standard key
ssh-keygen -t ed25519 -C your_email@example.com -f ~/.ssh/id_ed25519 -N yourpassword

# Or with YubiKey
ssh-keygen -t ecdsa-sk -O no-touch-required -C "your_email@example.com (notouch+passphrase)" -f ~/.ssh/id_your_sk
```

2. **Ensure your SSH agent is running**:

```bash
# Check if agent is running
ssh-add -l

# If not, start it
eval $(ssh-agent)

# Add your key
ssh-add ~/.ssh/id_ed25519
```

### Installation

**Recommended location:** Check out the repository in `~/.ssh/sca`. The playbook will adapt to any location, but `~/.ssh/sca` is the recommended path.

**First-time setup:**

1. **Clone the repository:**
   ```bash
   git clone https://github.com/styliteag/ssh-central-agent ~/.ssh/sca
   # or git clone https://github.com/styliteag/ssh-central-agent ~/.ssh/sca
   ```

2. **Create the hosts directory:**
   After checkout, create a `hosts` directory. This can be:
   - A symlink to another private repository (recommended for team setups)
   - An empty directory (if you don't have access to the private hosts repo yet)
   - A separate private git repository
   
   ```bash
   # Option 1: Create empty directory
   mkdir hosts
   
   # Option 2: Clone private repo as hosts directory
   git clone <private-hosts-repo-url> hosts
   ```

3. **Run the Ansible playbook:**
   ```bash
   ansible-playbook playbook.yml
   ```

   This will:
   - Generate the `sca` (SSH Central Agent) script from templates
   - Create SSH configuration files
   - Set up shell integration (.bashrc/.zshrc)

**Note:** The playbook automatically adapts to wherever you've checked out the repository. See [SETUP.md](SETUP.md) for detailed setup instructions.

### Usage

Start a shell with access to remote keys using the SSH Central Agent:

```bash
sca
```

Or use `eval \`sca -e\`` to set the SSH agent in your current shell (similar to `ssh-agent -s`):

```bash
eval `sca -e --key=local`
# Now SSH_AUTH_SOCK is set in your current shell
ssh-add -l  # List available keys
```

**Direct SSH Connection:**

You can also connect directly to hosts without starting a subshell. Positional arguments are automatically treated as SSH arguments:

```bash
sca user@hostname                    # Connect using remote agent (default)
sca --ssh user@hostname              # Same as above (explicit)
sca --key=local user@hostname        # Connect using local agent
sca --key=mux user@hostname          # Connect using multiplexed agent
```

When using SSH options that start with `-` (like `-p`, `-o`), use `--` to separate SCA options from SSH arguments:

```bash
sca --key=remote -- -p9922 root@10.20.3.254 hostname
sca --key=local -- -o StrictHostKeyChecking=no user@host
sca --key=mux -- -p9922 -v user@hostname
```

All arguments after `--ssh` or `--` are passed directly to `ssh`, so you can use any SSH options:

```bash
sca --key=local --ssh -p9922 -v user@hostname
sca --key=mux --ssh user@hostname "command to run"
```

### Command Options

**Basic Usage:**
```bash
sca --key=local         # Start subshell with local key only
sca --key=remote        # Start subshell with remote key only (default)
sca --key=mux           # Start subshell with multiplexed agent (local + remote)
```

**Host Management:**
```bash
sca --list              # List all configured hosts
sca --find hostname     # Find and display information about a specific host
sca --add hostname      # Add a new host to the configuration
sca --ssh [args...]     # Connect directly via ssh (all args passed to ssh)
```

**Direct SSH Connection:**
```bash
sca user@host                          # Connect using remote agent (default)
sca --ssh user@host                    # Same as above (explicit)
sca --key=local user@host              # Connect using local agent
sca --key=mux --ssh -p9922 user@host  # Connect using multiplexed agent with options
sca --key=remote -- -p9922 root@10.20.3.254 hostname  # Use -- for SSH options starting with -
sca --key=remote --ssh host command    # Execute command on remote host
```

**Advanced Options:**
```bash
sca -e --key=local      # Output env vars for eval (use with eval \`sca -e --key=local\`)
sca --wait              # Run in background and monitor connection, restart if needed
sca --kill              # Kill all agents and connections, remove socket files
sca -d                  # Enable debug mode (verbose output)
sca -r                  # Reverse the order of agents when multiplexing
sca -l 2                # Set security level (0-3, default: auto-detect)
sca --mux=rust          # Use Rust multiplexer instead of Python (default)
```

**Combined Options:**
```bash
sca -dr --key=local     # Debug mode + reverse agent order
sca --wait --key=local  # Background monitoring mode
```

## SSH Agent Multiplexing

The system includes its own SSH agent multiplexer implementation (`sshagentmux.py`) that combines local and remote SSH agents into a single socket. Additionally, if available, the system can use the external [ssh-agent-mux](https://github.com/overhacked/ssh-agent-mux) project, which provides better performance and additional features.

### Option 1: Built-in Python Multiplexer (Default)
The project includes `sshagentmux.py`, a Python-based SSH agent multiplexer that combines your local and remote SSH agents. This is the default implementation and requires no additional dependencies beyond Python.

### Option 2: ssh-agent-mux (Optional, Explicit Opt-In)
If [ssh-agent-mux](https://github.com/overhacked/ssh-agent-mux) is installed, you can choose to use it explicitly via:

```bash
sca --mux=rust
```

This Rust-based multiplexer offers better performance, but it is **not** compatible with some older or non-standard SSH implementations (for example certain Sophos appliances). In those cases you may see errors like:

```text
[ssh_agent_lib::agent] Error handling message: Proto(SshKey(Encoding(Length)))
```

If you encounter such errors, switch back to the default Python multiplexer (no `--mux` flag, or `--mux=python`) and consider reporting the issue upstream to the `ssh-agent-mux` project to see if they can improve compatibility.

**Installation:**
```bash
cargo install ssh-agent-mux
```

**Configuration:**
Create `~/.config/ssh-agent-mux/ssh-agent-mux.toml`:
```toml
agent_sock_paths = [
    "~/.ssh/agent.sock",           # Your local agent
    "~/.ssh/scadev-agent.sock",    # Remote agent
]
listen_path = "~/.ssh/ssh-agent-mux.sock"
log_level = "warn"
```

**Start the service:**
```bash
# macOS
ssh-agent-mux --install-service

# Linux
ssh-agent-mux --install-service
systemctl --user enable --now ssh-agent-mux.service
```

**Enable logging (macOS):**
Edit `~/Library/LaunchAgents/net.ross-williams.ssh-agent-mux.plist` and add:
```xml
<key>StandardOutPath</key>
<string>/Users/YOUR_USERNAME/Library/Logs/ssh-agent-mux.log</string>
<key>StandardErrorPath</key>
<string>/Users/YOUR_USERNAME/Library/Logs/ssh-agent-mux.err.log</string>
```

Then restart: `launchctl kickstart -k gui/$(id -u)/net.ross-williams.ssh-agent-mux`

**View logs:**
```bash
# macOS (if logging configured)
tail -f ~/Library/Logs/ssh-agent-mux.log

# macOS (system log)
log stream --predicate 'process == "ssh-agent-mux"' --level debug

# Linux
journalctl --user -u ssh-agent-mux -f
```

## Shell Integration

Add to your `~/.zshrc` or `~/.bashrc`:

```bash
# SCA-KEY subshell integration (SSH Central Agent)
if [ -n "$SCA_SUBSHELL" ] ; then
  echo "SCA_SUBSHELL: $SCA_SUBSHELL"
  PS1="$PS1($SCA_SUBSHELL) "
  if [ -n "$MUX_SSH_AUTH_SOCK" ] ; then
    export SSH_AUTH_SOCK=$MUX_SSH_AUTH_SOCK
  elif [ -n "$SCA_SSH_AUTH_SOCK" ] ; then
    export SSH_AUTH_SOCK=$SCA_SSH_AUTH_SOCK
  fi
else
  export LOCAL_SSH_AUTH_SOCK=$SSH_AUTH_SOCK
fi
```

## Troubleshooting

**Check agent status:**
```bash
ssh-add -l
```

**View socket files:**
```bash
ls -la ~/.ssh/scadev-*
```

**Kill and restart:**
```bash
sca --kill
sca
```

## Documentation

See [AGENTS.md](AGENTS.md) for detailed documentation including:
- Architecture overview
- Configuration management
- Debugging guide
- Complete ssh-agent-mux setup

## macOS Notes

For macOS, you may need to use `/usr/local/bin/ssh-agent` instead of the built-in one:

```bash
which ssh
# Should show: /usr/local/bin/ssh

ssh -V
# Should show: OpenSSH_8.8p1 or later
```

If needed:
```bash
pkill ssh-agent
eval $(/usr/local/bin/ssh-agent)
ssh-add ~/.ssh/id_xx_sk
```
