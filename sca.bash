#!/usr/bin/env -S bash
#
# Copyright 2024, Wim Bonis, Stylite AG
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# shellcheck shell=bash
# shellcheck enable=require-variable-braces
# no-shellcheck enable=all
# shellcheck disable=SC1083 # This is a template file

###############################################################################
# SSH Agent Multiplexer Gateway Script
#
# This script manages SSH agent multiplexing, allowing users to combine
# local and remote SSH agents (e.g., YubiKey agent) into a single socket.
# It supports both Python (sshagentmux.py) and Rust (ssh-agent-mux) multiplexers.
#
# Usage: ./sca [options] [command]
###############################################################################

#==============================================================================
# CONFIGURATION & INITIALIZATION
#==============================================================================

# Template variables (set by Ansible)
export RUSERNAME=wb
export SCA_SSH_AUTH_SOCK=~/.ssh/scadev-agent.sock
export MUX_SSH_AUTH_SOCK=~/.ssh/scadev-mux.sock
export PLAYBOOK_DIR=/Users/bonis/.ssh/sca
export SSH_CONFIG_FILE=config
export SCA_SCRIPT="$0"

# Include helper functions
source "$PLAYBOOK_DIR/functions.sh"

# Call main function with all arguments
sca_main "$@"
