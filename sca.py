#!/usr/bin/env python3
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

###############################################################################
# SSH Agent Multiplexer Gateway Script (Shim)
#
# This is a shim script that calls the Python SCA module.
# The actual implementation is in the sca/ Python package.
###############################################################################

import os
import sys
from pathlib import Path

# Set environment variables (same as original template)
os.environ["RUSERNAME"] = "wb"
os.environ["SCA_SSH_AUTH_SOCK"] = "~/.ssh/scadev-agent.sock"
os.environ["MUX_SSH_AUTH_SOCK"] = "~/.ssh/scadev-mux.sock"
os.environ["PLAYBOOK_DIR"] = "/Users/bonis/.ssh/sca"
os.environ["SSH_CONFIG_FILE"] = "config"
os.environ["SCA_SCRIPT"] = __file__

# Change to playbook directory so Python can find the sca package
playbook_dir = Path("/Users/bonis/.ssh/sca").resolve()
try:
    os.chdir(playbook_dir)
except OSError as e:
    print(f"Error: Cannot change to directory: {playbook_dir}: {e}", file=sys.stderr)
    sys.exit(1)

# Execute Python module
if __name__ == "__main__":
    # Use -m to run as module, which will handle imports correctly
    import subprocess
    sys.exit(subprocess.run([sys.executable, "-m", "sca"] + sys.argv[1:]).returncode)
