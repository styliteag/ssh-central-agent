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

#####################
# Funtions
#####################

list() {
  echo "## Listing Hosts" >&2
  cat $PLAYBOOK_DIR/hosts/*
}

find() {
  echo "Finding agent" >&2
  echo "Searching for agent: $1" >&2
  grep -i -A7 $1 $PLAYBOOK_DIR/hosts/*
}

add() {
  echo "Adding Host: $1" >&2
  echo "Add is broken right now" >&2
  echo "Use addhost instead" >&2
  #pushd $PLAYBOOK_DIR
  #./addhost $*
  #popd
  exit 1
}

connect() {
  echo "Connecting to Host:" >&2
  if [ "$KEY" = "local" ]; then
    MYSSH="ssh -o 'IdentityAgent \"$SSH_AUTH_SOCK\"' -o 'IdentityFile none'"
  elif [ "$KEY" = "remote" ]; then 
    MYSSH="ssh -o 'IdentityAgent \"$SCA_SSH_AUTH_SOCK\"' -o 'IdentityFile none'"
  else
    MYSSH="ssh"
  fi
}

do_cmd() {
    echo "CMD: $OPTARG" >&2
    echo "ARGS: $*" >&2
    CMD=$OPTARG
    ARGS=$*
    # Is function $CMD defined?
    if type $CMD >/dev/null 2>&1; then
      $CMD $ARGS
    else
      echo "Command $CMD not found" >&2
    fi
}
