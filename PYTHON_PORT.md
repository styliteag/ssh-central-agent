# Python Port for Windows Support

## Overview

This branch contains a Python port of the SCA (SSH Central Agent) system, enabling native Windows 11 support while maintaining compatibility with macOS and Linux.

## Architecture

The Python port maintains the same functionality as the bash version but is organized into a clean Python package structure:

```
sca/
├── __init__.py              # Package initialization
├── __main__.py              # Main entry point
├── cli.py                   # CLI argument parsing (click)
├── config.py                # Configuration management
├── agent.py                 # SSH agent operations
├── multiplexer.py           # Multiplexer setup (Python only)
├── connection.py            # Connection management
├── process.py               # Process management (cross-platform)
├── socket_utils.py          # Socket utilities (Unix + Windows)
├── logging_utils.py         # Colored logging (colorama)
└── platform_utils.py        # Platform detection and utilities
```

## Key Features

### Cross-Platform Support
- **Windows**: Supports Windows named pipes (`\\.\pipe\openssh-ssh-agent`)
- **macOS/Linux**: Supports Unix domain sockets
- Automatic platform detection and appropriate handling

### Dependencies
- `click>=8.0.0` - CLI framework
- `colorama>=0.4.6` - Cross-platform colored output
- `psutil>=5.9.0` - Cross-platform process management
- Python 3.9+

### Windows-Specific Notes

1. **SSH Agent**: Windows 11 native OpenSSH uses named pipes instead of Unix sockets
2. **Process Management**: Uses `psutil` instead of `pgrep`/`pkill`
3. **Path Handling**: Uses `pathlib.Path` for cross-platform path operations
4. **Named Pipe Support**: `sshagentmux.py` has been updated to support Windows named pipes (requires `pywin32` for full support)
5. **Multiplexer**: Only Python multiplexer (`sshagentmux.py`) is supported - Rust mux option has been removed

## Installation

### From Source

```bash
# Install dependencies
pip install -r requirements.txt

# Install in development mode
pip install -e .

# Or install normally
pip install .
```

### Dependencies

```bash
pip install click colorama psutil
```

For Windows named pipe support in the multiplexer:
```bash
pip install pywin32  # Windows only
```

## Usage

The Python version maintains the same CLI interface as the bash version:

```bash
# Start subshell with multiplexed agent
python -m sca --key=mux

# Connect directly to a host
python -m sca --ssh hostname

# List hosts
python -m sca --list

# Find host
python -m sca --find hostname
```

After running the Ansible playbook, the generated `sca` script will use the Python implementation.

## Migration from Bash Version

The Python port is designed to be a drop-in replacement:
- Same CLI interface
- Same environment variables
- Same configuration files
- Same behavior

The bash version is preserved as `sca.bash` for fallback if needed.

## Testing

Run tests with pytest:

```bash
pytest tests/
```

## Windows Limitations

1. **Multiplexer Server**: The Python multiplexer (`sshagentmux.py`) can connect to Windows named pipes but creating a listening server on Windows requires additional implementation (currently uses Unix sockets for the server).

2. **Symlinks**: Windows symlink creation may require administrator privileges.

## Development

### Running from Source

```bash
# Set environment variables (normally set by Ansible-generated script)
export PLAYBOOK_DIR=/path/to/sca
export RUSERNAME=your_username
export SCA_SSH_AUTH_SOCK=~/.ssh/scadev-agent.sock
export MUX_SSH_AUTH_SOCK=~/.ssh/scadev-mux.sock
export SSH_CONFIG_FILE=config

# Run
python -m sca --help
```

## Status

- ✅ Core functionality ported
- ✅ Cross-platform socket support
- ✅ Process management with psutil
- ✅ CLI with click
- ✅ Windows named pipe support (client-side)
- ⚠️ Windows server support (multiplexer) - partial (needs pywin32)
- ⚠️ Windows testing - pending
