# Host Configuration Files

This directory contains SSH host configuration files. Each file defines one or more SSH hosts that can be accessed through the SSH Secure Gateway.

## Format

Each file should contain SSH `Host` blocks in standard SSH config format:

```
Host example-host sca-example-host
    user your_username
    hostname example.com
    port 22
    include ~/.ssh/config_sca_common
```

## Adding Hosts

1. Create a new file in this directory or edit an existing one
2. Add your host configuration following the format above
3. Run `ansible-playbook playbook.yml` to regenerate the SSH config

## Example

See `localvars-example.yml` for configuration examples.

