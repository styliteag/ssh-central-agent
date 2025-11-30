# Setup Guide: Private Hosts Configuration

This repository contains the public SSH Central Agent (SCA) configuration. Host configurations are stored separately in a private repository to keep sensitive information secure.

## Initial Setup

### For New Users

1. **Clone the public repository:**
   ```bash
   cd ~/sca
   git clone git@github.com:styliteag/ssh-central-agent.git
   cd ssh-central-agent
   ```

2. **Set up the hosts directory** (choose one option):

   **Option A: Clone the private hosts repository** (if you have access):
   ```bash
   cd ~/sca
   git clone git@github.com:styliteag/sca-private-hosts.git
   cd ssh-central-agent
   ln -s ../sca-private-hosts hosts
   ```

   **Option B: Create an empty hosts directory** (if you don't have access or want to start fresh):
   ```bash
   cd ~/sca/ssh-central-agent
   mkdir hosts
   ```

3. **Run the Ansible playbook:**
   ```bash
   ansible-playbook playbook.yml
   ```

### Directory Structure

After setup, your `~/sca` directory should look like this:

```
~/sca/
├── ssh-central-agent/          # Public repo (this repository)
│   ├── hosts -> ../sca-private-hosts/  # Symlink (if using private repo)
│   │   OR
│   ├── hosts/                  # Empty directory (if starting fresh)
│   ├── playbook.yml
│   ├── templates/
│   └── ...
└── sca-private-hosts/          # Private repo (optional, host configurations)
    ├── intern
    ├── kunde1
    ├── dev
    └── ...
```

## Updating

### Update Public Repository
```bash
cd ~/sca/ssh-central-agent
git pull
ansible-playbook playbook.yml
```

### Update Private Hosts
```bash
cd ~/sca/sca-private-hosts
git pull
```

## Notes

- The `hosts/` directory is gitignored in the public repository
- Always use a symlink - never copy the hosts directory
- The symlink approach allows the playbook to work without any code changes
- Both repositories can be updated independently