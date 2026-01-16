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
# Functions
#####################

list() {
  echo "## Listing Hosts" >&2
  cat $PLAYBOOK_DIR/hosts/*
}

find() {
  local hostname="$1"
  local config_file="$PLAYBOOK_DIR/config"
  local hosts_dir="$PLAYBOOK_DIR/hosts"
  local output_file=$(mktemp)
  
  echo "Searching for host: $hostname" >&2
  
  # Helper function to extract and print Host block from a file
  extract_host_block() {
    local file="$1"
    local line_num="$2"
    
    # Find the start of this Host block (go backwards to find the Host line)
    local start_line=$line_num
    while [ $start_line -gt 0 ]; do
      local line_content=$(sed -n "${start_line}p" "$file" 2>/dev/null)
      # Check if this line starts a Host or Match block
      if echo "$line_content" | grep -qiE "^\s*(Host|Match)"; then
        break
      fi
      start_line=$((start_line - 1))
    done
    
    # Find the end of this Host block (next Host or Match line, or end of file)
    local total_lines=$(wc -l < "$file" 2>/dev/null)
    local end_line=$total_lines
    local next_line=$((start_line + 1))
    
    while [ $next_line -le $total_lines ]; do
      local line_content=$(sed -n "${next_line}p" "$file" 2>/dev/null)
      # Check if this line starts a new Host or Match block
      if echo "$line_content" | grep -qiE "^\s*(Host|Match)"; then
        end_line=$((next_line - 1))
        break
      fi
      next_line=$((next_line + 1))
    done
    
    # Extract the block and filter out empty lines and standalone (non-indented) comment lines
    local block_content=$(sed -n "${start_line},${end_line}p" "$file" 2>/dev/null)
    
    # Filter: remove empty lines and standalone comment lines (not indented, not part of Host block)
    # Keep the Host line and all indented lines (which are part of the Host block)
    local filtered_content=$(echo "$block_content" | grep -v '^$' | awk '
      /^\s*(Host|Match)/ { print; next }  # Host/Match line - always keep
      /^\s/ { print; next }  # Indented lines (part of block) - keep
      /^[^\s#]/ { print; next }  # Non-indented, non-comment lines - keep
      /^#/ && /^\s+#/ { print; next }  # Indented comments (part of block) - keep
      # Skip standalone (non-indented) comment lines
    ')
    
    # Print the file name and the filtered Host block
    echo "--- $file (lines $start_line-$end_line) ---"
    echo "$filtered_content"
    echo ""
  }
  
  # Helper function to find Host block start line for any given line number
  find_host_block_start() {
    local file="$1"
    local line_num="$2"
    local start_line=$line_num
    while [ $start_line -gt 0 ]; do
      local line_content=$(sed -n "${start_line}p" "$file" 2>/dev/null)
      # Check if this line starts a Host or Match block
      if echo "$line_content" | grep -qiE "^\s*(Host|Match)"; then
        echo "$start_line"
        return 0
      fi
      start_line=$((start_line - 1))
    done
    return 1
  }
  
  # Helper function to search for matches in all lines
  search_in_all_lines() {
    local file="$1"
    # Escape special regex characters in hostname
    local escaped_hostname=$(echo "$hostname" | sed 's/[.[\*^$()+?{|]/\\&/g')
    # Search for the hostname in all lines (case-insensitive)
    grep -ni "${escaped_hostname}" "$file" 2>/dev/null | cut -d: -f1 | sort -u
  }
  
  # Search in config file - find matches in all lines
  if [ -f "$config_file" ]; then
    local matching_lines=$(search_in_all_lines "$config_file")
    if [ -n "$matching_lines" ]; then
      local unique_starts=""
      while IFS= read -r line_num; do
        local start_line=$(find_host_block_start "$config_file" "$line_num")
        if [ -n "$start_line" ]; then
          if ! echo "$unique_starts" | grep -q "^${start_line}$"; then
            unique_starts="${unique_starts}${start_line}"$'\n'
          fi
        fi
      done <<< "$matching_lines"
      
      if [ -n "$unique_starts" ]; then
        echo "$unique_starts" | grep -v '^$' | sort -n | while IFS= read -r start_line; do
          extract_host_block "$config_file" "$start_line"
        done >> "$output_file"
      fi
    fi
  fi
  
  # Search in hosts/* files - find matches in all lines
  if [ -d "$hosts_dir" ]; then
    for host_file in "$hosts_dir"/*; do
      if [ -f "$host_file" ]; then
        local matching_lines=$(search_in_all_lines "$host_file")
        if [ -n "$matching_lines" ]; then
          local unique_starts=""
          while IFS= read -r line_num; do
            local start_line=$(find_host_block_start "$host_file" "$line_num")
            if [ -n "$start_line" ]; then
              if ! echo "$unique_starts" | grep -q "^${start_line}$"; then
                unique_starts="${unique_starts}${start_line}"$'\n'
              fi
            fi
          done <<< "$matching_lines"
          
          if [ -n "$unique_starts" ]; then
            echo "$unique_starts" | grep -v '^$' | sort -n | while IFS= read -r start_line; do
              extract_host_block "$host_file" "$start_line"
            done >> "$output_file"
          fi
        fi
      fi
    done
  fi
  
  # Display results
  if [ -s "$output_file" ]; then
    cat "$output_file"
    rm -f "$output_file"
  else
    echo "No host found matching: $hostname" >&2
    rm -f "$output_file"
    return 1
  fi
}

add() {
  echo "Adding Host: $*" >&2
  (cd "$PLAYBOOK_DIR" && ./addhost "$@")
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
    CMD="$1"
    shift
    ARGS="$*"
    echo "CMD: $CMD" >&2
    echo "ARGS: $ARGS" >&2
    # Is function $CMD defined?
    if type "$CMD" >/dev/null 2>&1; then
      "$CMD" $ARGS
    else
      echo "Command $CMD not found" >&2
    fi
}
