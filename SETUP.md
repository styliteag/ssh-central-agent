# Setup Guide: Private Hosts Configuration

This repository contains the public SSH Central Agent (SCA) configuration. Host configurations are stored separately in a private repository to keep sensitive information secure.

## Initial Setup

### Recommended Installation Location

**Best practice:** Check out the repository in `~/.ssh/sca`. However, the playbook will adapt to any location - you can install it anywhere on your system.

### Initialize the repositories

1. **Clone the repository:**
   ```bash
   # Recommended location
   git clone https://github.com/styliteag/ssh-central-agent ~/.ssh/sca
   # or git clone git@github.com:styliteag/ssh-central-agent.git ~/.ssh/sca
   cd ~/.ssh/sca
   
   # Or any other location - playbook will adapt
   # git clone <repository-url> /path/to/sca
   # cd /path/to/sca
   ```

2. **Create the hosts directory:**
   
   After checkout, you need to create a `hosts` directory. This can be:
   
   **Option A: Symlink to a separate private repository** (recommended for team setups):
   ```bash
   # Clone your private hosts repository separately
   git clone ssh://git@git-yourdomain.com/your-project/ssh-central-agent-hosts.git ~/sca-hosts
   
   # Create symlink
   ln -s ~/sca-hosts hosts
   ```
   
   **Option B: Clone private repo directly as hosts directory:**
   ```bash
   git clone ssh://git@git-yourdomain.com/your-project/ssh-central-agent-hosts.git hosts
   ```
   
   **Option C: Create empty directory** (if you don't have access to the private hosts repository yet):
   ```bash
   mkdir hosts
   ```
   
   You can add host configuration files later or set up the private repository when available.

3. **Configure local variables:**
   ```bash
   cp localvars-example.yml localvars.yml
   # Edit localvars.yml with your credentials and hostnames
   ```

4. **Run the Ansible playbook:**
   ```bash
   ansible-playbook playbook.yml
   ```
   
   The playbook automatically detects the installation location and adapts all paths accordingly.

### Directory Structure

After setup, your directory structure should look like this:

**Recommended structure (`~/.ssh/sca`):**
```
~/.ssh/sca/                          # Main repository (recommended location)
├── hosts -> ~/sca-hosts/            # Symlink to private repo (or direct clone)
├── playbook.yml
├── templates/
├── localvars.yml
└── ...

~/sca-hosts/                         # Private hosts repository (separate)
    ├── bonis
    ├── caritas
    ├── dev
    └── ...
```

**Alternative structure (if hosts is a direct clone):**
```
~/.ssh/sca/                          # Main repository
├── hosts/                           # Private hosts repository (cloned directly)
│   ├── bonis
│   ├── caritas
│   └── ...
├── playbook.yml
└── ...
```

**Note:** The playbook adapts to any installation location - the paths shown above are just examples.

## Updating

### Update Main Repository
```bash
cd ~/.ssh/sca  # or wherever you installed it
git pull
ansible-playbook playbook.yml
```

### Update Private Hosts Repository

**If hosts is a symlink:**
```bash
cd ~/sca-hosts  # or wherever your private hosts repo is
git pull
```

**If hosts is a direct clone:**
```bash
cd ~/.ssh/sca/hosts
git pull
```

**If hosts is a git submodule:**
```bash
cd ~/.ssh/sca
git submodule update --remote --merge hosts
```

## Notes

- The `hosts/` directory is gitignored in the public repository
- The `hosts` directory can be:
  - A symlink to another private repository (recommended)
  - A direct clone of a private repository
  - An empty directory (if you don't have access to the private repo yet)
- Never copy the hosts directory - always use a symlink or git clone
- The playbook automatically adapts to the installation location
- Both repositories can be updated independently
- Recommended installation location is `~/.ssh/sca`, but any location works