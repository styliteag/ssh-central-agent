# Setup Guide: Private Hosts Configuration

This repository contains the public SSH Central Agent (SCA) configuration. Host configurations are stored separately in a private repository to keep sensitive information secure.

## Initial Setup (with a private hosts repository)

### Initialize the repositories

1. **Clone the parent repository with submodules** (recommended):
   ```bash
   mkdir -p ~/sca
   cd ~/sca
   git clone git@github.com:styliteag/ssh-central-agent.git ssh-central-agent
   git clone ssh://git@git-yourdomain.com/your-project/ssh-central-agent-hosts.git ssh-central-agent-hosts
   ```

   If you already cloned without submodules, initialize them:
   ```bash
   cd ~/sca
   git submodule update --init --recursive
   ```

2. **Set up the hosts symlink**:
   
   The `ssh-central-agent-hosts` submodule is located at the repository root. Create a symlink from `ssh-central-agent/hosts` to the submodule:
   ```bash
   cd ~/sca/ssh-central-agent
   ln -s ../ssh-central-agent-hosts hosts
   ```

   **Note**: If you don't have access to the private hosts repository, you can create an empty directory instead:
   ```bash
   cd ~/sca/ssh-central-agent
   mkdir hosts
   ```

3. **Run the Ansible playbook:**
   ```bash
   cd ~/sca/ssh-central-agent
   ansible-playbook playbook.yml
   ```

### Directory Structure

After setup, your `~/sca` directory should look like this:

```
~/sca/
├── ssh-central-agent/              # Public repo (this repository)
│   ├── hosts -> ../ssh-central-agent-hosts/  # Symlink to submodule
│   ├── playbook.yml
│   ├── templates/
│   └── ...
└── ssh-central-agent-hosts/        # Private repo submodule (host configurations)
    ├── bonis
    ├── caritas
    ├── dev
    └── ...
```

## Updating

### Update All Repositories (Parent + Submodules)
```bash
cd ~/sca
git pull
git submodule update --remote --merge
cd ssh-central-agent
ansible-playbook playbook.yml
```

### Update Public Repository Only
```bash
cd ~/sca/ssh-central-agent
git pull
ansible-playbook playbook.yml
```

### Update Private Hosts Submodule Only
```bash
cd ~/sca/ssh-central-agent-hosts
git pull
```

Or update from the parent repository:
```bash
cd ~/sca
git submodule update --remote ssh-central-agent-hosts
```

## Notes

- The `hosts/` directory is gitignored in the public repository
- Always use a symlink - never copy the hosts directory
- The symlink approach allows the playbook to work without any code changes
- Both repositories can be updated independently
- Use `git submodule update --init --recursive` if submodules weren't initialized during clone