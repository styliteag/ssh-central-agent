# SSH Secure Gateway (SCA)

**SCA** stands for **SSH Central Agent** - a sophisticated SSH gateway system that provides secure, multi-level SSH access to remote hosts through a centralized jump host infrastructure.

## What is SCA?

The **SSH Central Agent (SCA)** is a gateway system that:

- **Centralizes SSH agent management** - Combines local and remote SSH keys into a single, unified agent
- **Provides multi-level access control** - Routes connections through security-level-based jump hosts (levels 0-3)
- **Enables seamless authentication** - Allows you to use keys from different sources (local YubiKey, remote server agents, etc.) simultaneously
- **Manages secure connections** - Handles SSH agent forwarding and multiplexing automatically

The `sca` command creates a subshell environment where your SSH client can access both local and remote SSH keys through a single agent socket, making it easy to connect to hosts across different security zones without manually managing multiple SSH agents.

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

Run the Ansible playbook to set up the system:

```bash
ansible-playbook playbook.yml
```

This will:
- Generate the `sca` (SSH Central Agent) script from templates
- Create SSH configuration files
- Set up shell integration (.bashrc/.zshrc)

### Usage

Start a shell with access to remote keys using the SSH Central Agent:

```bash
sca
```

Common commands:
```bash
sca --list              # List configured hosts
sca --find hostname     # Find a specific host
sca --wait              # Run in background and monitor
sca --kill              # Kill all agents and connections
```

## SSH Agent Multiplexing

The system supports two multiplexer options:

### Option 1: Python Multiplexer (Built-in)
The default `sshagentmux.py` combines your local and remote SSH agents.

### Option 2: ssh-agent-mux (Recommended)
A Rust-based multiplexer with better performance. 

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
