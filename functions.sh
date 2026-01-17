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

#==============================================================================
# COLOR AND LOGGING UTILITIES
#==============================================================================

# Color helper function
color() {
    if [ -t 1 ] && [ -z "${NO_COLOR:-}" ] && command -v tput >/dev/null 2>&1; then
        tput "$@"
    fi
}

# Color helper for stderr (SCA uses stderr for logging)
color_stderr() {
    if [ -t 2 ] && [ -z "${NO_COLOR:-}" ] && command -v tput >/dev/null 2>&1; then
        tput "$@"
    fi
}

# Logging functions with colors (use color_stderr since output goes to stderr)
log_error() {
    echo "$(color_stderr setaf 1)$(color_stderr bold)ERROR:$(color_stderr sgr0) $(color_stderr setaf 1)$*$(color_stderr sgr0)" >&2
}

log_warn() {
    echo "$(color_stderr setaf 3)$(color_stderr bold)WARNING:$(color_stderr sgr0) $(color_stderr setaf 3)$*$(color_stderr sgr0)" >&2
}

log_info() {
    echo "$(color_stderr setaf 4)$(color_stderr bold)INFO:$(color_stderr sgr0) $(color_stderr setaf 4)$*$(color_stderr sgr0)" >&2
}

log_success() {
    echo "$(color_stderr setaf 2)$(color_stderr bold)✓$(color_stderr sgr0) $(color_stderr setaf 2)$*$(color_stderr sgr0)" >&2
}

log_debug() {
    if [ "${DEBUG:-0}" == "1" ]; then
        echo "$(color_stderr setaf 5)$(color_stderr bold)DEBUG:$(color_stderr sgr0) $(color_stderr setaf 5)$*$(color_stderr sgr0)" >&2
    fi
}

log_note() {
    echo "$(color_stderr setaf 6)$(color_stderr bold)NOTE:$(color_stderr sgr0) $(color_stderr setaf 6)$*$(color_stderr sgr0)" >&2
}

# Color codes for syntax highlighting
color_reset() {
    color sgr0
}

color_host() {
    color setaf 4  # Blue
    color bold
}

color_directive() {
    color setaf 6  # Cyan
}

color_value() {
    color setaf 3  # Yellow
}

color_comment() {
    # Try gray (8), fallback to dim white (7)
    if color setaf 8 >/dev/null 2>&1; then
        color setaf 8
    else
        color setaf 7
        color dim
    fi
}

color_file_header() {
    color setaf 5  # Magenta
    color dim
}

# Syntax highlight a line of SSH config
highlight_line() {
    local line="$1"

    # Host or Match directive (bold blue for keyword, yellow for values)
    if [[ "$line" =~ ^([[:space:]]*)(Host|Match)[[:space:]]+(.+)$ ]]; then
        local indent="${BASH_REMATCH[1]}"
        local keyword="${BASH_REMATCH[2]}"
        local values="${BASH_REMATCH[3]}"
        printf "%s%s%s%s %s%s%s\n" \
            "$indent" \
            "$(color_host)" \
            "$keyword" \
            "$(color_reset)" \
            "$(color_value)" \
            "$values" \
            "$(color_reset)"
        return
    fi

    # Comment lines (gray/dim)
    if [[ "$line" =~ ^[[:space:]]*# ]]; then
        printf "%s%s%s\n" "$(color_comment)" "$line" "$(color_reset)"
        return
    fi

    # Directives with values (cyan directive, yellow value)
    if [[ "$line" =~ ^([[:space:]]+)([A-Za-z][A-Za-z0-9]*)[[:space:]]+(.+)$ ]]; then
        local indent="${BASH_REMATCH[1]}"
        local directive="${BASH_REMATCH[2]}"
        local value="${BASH_REMATCH[3]}"
        printf "%s%s%s%s %s%s%s\n" \
            "$indent" \
            "$(color_directive)" \
            "$directive" \
            "$(color_reset)" \
            "$(color_value)" \
            "$value" \
            "$(color_reset)"
        return
    fi

    # Default: just print the line
    printf "%s\n" "$line"
}

#==============================================================================
# HOST MANAGEMENT FUNCTIONS
#==============================================================================

list() {
  echo "## Listing Hosts" >&2
  cat $PLAYBOOK_DIR/hosts/*
}

#==============================================================================
# HOST SEARCH HELPER FUNCTIONS
#==============================================================================

# Helper function to find Host block start line for any given line number
find_host_block_start() {
  local file="$1"
  local line_num="$2"
  local start_line=$line_num
  while [ $start_line -gt 0 ]; do
    local line_content=$(sed -n "${start_line}p" "$file" 2>/dev/null)
    # Check if this line starts with "Host " (with space) or "Match " (with space)
    if echo "$line_content" | grep -qiE "^[[:space:]]*(Host|Match)[[:space:]]"; then
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
  local hostname="$2"
  # Search for the hostname as a substring in all non-comment lines (case-insensitive)
  # Important: ignore standalone comments like "# Autoadded ..." to avoid jumping to the previous Host block.
  awk -v q="$hostname" '
    BEGIN { q = tolower(q) }
    /^[[:space:]]*#/ { next }
    { if (index(tolower($0), q) > 0) print NR }
  ' "$file" 2>/dev/null
}

# Helper function to extract and print Host block from a file
extract_host_block() {
  local file="$1"
  local line_num="$2"
  
  # Find the start of this Host block (go backwards to find the Host line)
  # Search specifically for "Host " (with space) or "Match " to ensure we get the directive line
  local start_line=$line_num
  while [ $start_line -gt 0 ]; do
    local line_content=$(sed -n "${start_line}p" "$file" 2>/dev/null)
    # Check if this line starts with "Host " (with space) or "Match " (with space)
    if echo "$line_content" | grep -qiE "^[[:space:]]*(Host|Match)[[:space:]]"; then
      break
    fi
    start_line=$((start_line - 1))
  done
  
  # Verify we found a Host/Match line
  if [ $start_line -eq 0 ]; then
    return 1
  fi
  
  local host_line_content=$(sed -n "${start_line}p" "$file" 2>/dev/null)
  # Verify it's actually a Host or Match line with space
  if ! echo "$host_line_content" | grep -qiE "^[[:space:]]*(Host|Match)[[:space:]]"; then
    return 1
  fi
  
  # Find the end of this Host block (next Host or Match line, or end of file)
  local total_lines=$(wc -l < "$file" 2>/dev/null)
  local end_line=$total_lines
  local next_line=$((start_line + 1))
  
  while [ $next_line -le $total_lines ]; do
    local line_content=$(sed -n "${next_line}p" "$file" 2>/dev/null)
    # Check if this line starts a new Host or Match block (with space)
    if echo "$line_content" | grep -qiE "^[[:space:]]*(Host|Match)[[:space:]]"; then
      end_line=$((next_line - 1))
      break
    fi
    next_line=$((next_line + 1))
  done
  
  # Extract the block starting from the Host line
  local block_content=$(sed -n "${start_line},${end_line}p" "$file" 2>/dev/null)
  
  # Always start with the Host line (remove any trailing whitespace)
  local clean_host_line=$(echo "$host_line_content" | sed 's/[[:space:]]*$//')
  
  # Filter the rest: remove empty lines and standalone (non-indented) comment lines
  # Note: we keep this streaming below to preserve colors and avoid buffering.
  
  # Build output: always start with Host line
  # Ensure clean_host_line is not empty
  if [ -z "$clean_host_line" ]; then
    clean_host_line=$(sed -n "${start_line}p" "$file" 2>/dev/null | sed 's/[[:space:]]*$//')
  fi
  
  # Print file header with color
  echo -n "$(color_file_header)"
  echo "--- $file (lines $start_line-$end_line) ---"
  echo -n "$(color_reset)"
  
  # Always print the Host line first with highlighting
  highlight_line "$clean_host_line"
  
  # Print rest of block with highlighting - process line by line directly
  echo "$block_content" | tail -n +2 | while IFS= read -r line || [ -n "$line" ]; do
    # Skip empty lines and standalone (non-indented) comment lines
    if [ -z "$line" ]; then
      continue
    fi
    # Standalone comment (not indented) - skip
    [[ "$line" == \#* ]] && continue
    # Print the line with highlighting
    highlight_line "$line"
  done
  echo ""
}

find() {
  local hostname="$1"
  local config_file="$PLAYBOOK_DIR/config"
  local hosts_dir="$PLAYBOOK_DIR/hosts"
  local found_any=false
  
  echo "Searching for host: $hostname" >&2
  
  # Search in config file - find matches in all lines
  if [ -f "$config_file" ]; then
    local matching_lines=$(search_in_all_lines "$config_file" "$hostname")
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
        local sorted_starts
        sorted_starts=$(echo "$unique_starts" | grep -v '^$' | sort -n)
        while IFS= read -r start_line; do
          [ -z "$start_line" ] && continue
          extract_host_block "$config_file" "$start_line"
          found_any=true
        done <<< "$sorted_starts"
      fi
    fi
  fi
  
  # Search in hosts/* files - find matches in all lines
  if [ -d "$hosts_dir" ]; then
    for host_file in "$hosts_dir"/*; do
      if [ -f "$host_file" ]; then
        local matching_lines=$(search_in_all_lines "$host_file" "$hostname")
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
            local sorted_starts
            sorted_starts=$(echo "$unique_starts" | grep -v '^$' | sort -n)
            while IFS= read -r start_line; do
              [ -z "$start_line" ] && continue
              extract_host_block "$host_file" "$start_line"
              found_any=true
            done <<< "$sorted_starts"
          fi
        fi
      fi
    done
  fi
  
  # Display results
  if [ "$found_any" != "true" ]; then
    echo "No host found matching: $hostname" >&2
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

# Cleanup function for background processes
cleanup() {
    SCA_EXITING=true
    
    # Check if we have anything to clean up
    local has_cleanup=false
    [ -n "$SSH_PID" ] && has_cleanup=true
    [ -n "$MUX_PID" ] && has_cleanup=true
    [ -n "$TAIL_LOG_PID" ] && has_cleanup=true
    [ -n "$RUST_MUX_LOG" ] && [ -f "$RUST_MUX_LOG" ] && has_cleanup=true
    
    if [ "$has_cleanup" != "true" ]; then
        return
    fi
    
    log_info "Cleaning up background processes..."
    
    # Kill SSH agent forwarder
    if [ -n "$SSH_PID" ]; then
        if kill -0 "$SSH_PID" 2>/dev/null; then
            log_info "Stopping SSH agent forwarder (PID $SSH_PID)"
            kill -TERM "$SSH_PID" 2>/dev/null || true
        fi
        log_info "Killing SSH processes with ragent"
        pkill -f " ragent " 2>/dev/null || true
        log_info "Removing SSH agent socket: $SCA_SSH_AUTH_SOCK"
        rm -f "$SCA_SSH_AUTH_SOCK" 2>/dev/null || true
    fi
    
    # Kill multiplexer processes
    if [ -n "$MUX_PID" ]; then
        if kill -0 "$MUX_PID" 2>/dev/null; then
            log_info "Stopping multiplexer (PID $MUX_PID)"
            kill -TERM "$MUX_PID" 2>/dev/null || true
        fi
        # Kill Python multiplexer if we started one
        log_info "Killing Python multiplexer (sshagentmux.py)"
        pkill -f "sshagentmux.py" 2>/dev/null || true
        # Kill ssh-agent-mux if we started it directly (not as service)
        if [ -n "$RUST_MUX_PID" ]; then
            log_info "Killing ssh-agent-mux (PID $RUST_MUX_PID)"
            pkill -x "ssh-agent-mux" 2>/dev/null || true
        fi
        log_info "Removing mux socket: $MUX_SSH_AUTH_SOCK"
        rm -f "$MUX_SSH_AUTH_SOCK" 2>/dev/null || true
    fi
    
    # Kill log tail process
    if [ -n "$TAIL_LOG_PID" ]; then
        if kill -0 "$TAIL_LOG_PID" 2>/dev/null; then
            log_info "Stopping log tail process (PID $TAIL_LOG_PID)"
            kill -TERM "$TAIL_LOG_PID" 2>/dev/null || true
        fi
    fi
    
    # Clean up temp log file if it exists
    if [ -n "$RUST_MUX_LOG" ] && [ -f "$RUST_MUX_LOG" ]; then
        log_info "Removing temp log file: $RUST_MUX_LOG"
        rm -f "$RUST_MUX_LOG" 2>/dev/null || true
    fi
    
    log_info "Cleanup complete"
}

# Kill a process if it exists
kill_if_exists() {
    local pid=$1
    local name=$2
    if [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null; then
        log_info "Stopping $name (PID $pid)"
        kill -TERM "$pid" 2>/dev/null || true
    fi
}

# Check if an SSH agent socket is working
check_agent_socket() {
    local socket=$1
    SSH_AUTH_SOCK="$socket" ssh-add -l >/dev/null 2>&1
}

# Check if SSH process with ragent is still running
check_ssh_agent_running() {
    pgrep -f " ragent " >/dev/null 2>&1
}

# Display harmless error note for ssh-agent-mux
show_harmless_error_note() {
    log_note "You can safely ignore these harmless errors:"
    echo "  $(color setaf 3)-$(color sgr0) 'ERROR [ssh_agent_mux] Unexpected error on socket ... when requesting session-bind@openssh.com extension: Agent: Protocol error: Unexpected response received'" >&2
    echo "  $(color setaf 3)-$(color sgr0) 'ERROR [ssh_agent_lib::agent] Error handling message: Failure'" >&2
}

# Find identity file in common locations
find_identity_file() {
    local key_file
    for key_file in ~/.ssh/id_ed25519 ~/.ssh/id_rsa ~/.ssh/id_ecdsa ~/.ssh/id_dsa; do
        if [ -f "$key_file" ] && [ -r "$key_file" ]; then
            echo "$key_file"
            return 0
        fi
    done
    return 1
}

# Build SSH command with optional identity file
build_ssh_cmd() {
    local cmd="ssh -a -F $PLAYBOOK_DIR/$SSH_CONFIG_FILE"
    if [ "$USE_IDENTITY_FILE" == "true" ] && [ -n "$IDENTITY_FILE" ]; then
        cmd="$cmd -i \"$IDENTITY_FILE\""
    fi
    echo "$cmd"
}

# Determine user security level
determine_security_level() {
    local ssh_cmd ssh_output ssh_exit_code my_level
    
    ssh_cmd=$(build_ssh_cmd)
    log_debug "Determining security level with: $ssh_cmd"
    
    ssh_output=$(eval "$ssh_cmd -o \"SetEnv SCA_NOLEVEL=1\" sca-key groups 2>&1")
    ssh_exit_code=$?
    
    if [ "$ssh_exit_code" -ne 0 ]; then
        log_error "SSH connection failed with exit code $ssh_exit_code"
        log_error "SSH output: $ssh_output"
        return 1
    fi
    
    my_level=$(echo "$ssh_output" | grep "level-" | grep -o -E "level-([0-9]*)" | cut -d"-" -f2 | sort -u | tail -1)
    
    if [ -z "$my_level" ]; then
        log_error "Could not determine your security level. Check your SSH connection."
        if [ -n "$ssh_output" ]; then
            log_error "SSH command output: $ssh_output"
        fi
        return 1
    fi
    
    echo "$my_level"
    return 0
}

# Start remote SSH agent forwarder
start_remote_agent() {
    local level=$1
    local ssh_cmd ssh_pid
    
    ssh_cmd=$(build_ssh_cmd)
    
    log_info "Starting SSH agent forwarder (level $level)..."
    SCA_LOCALUSER=$LOGNAME SCA_REMOTEUSER=$RUSERNAME SCA_IP=$(hostname) \
        eval "$ssh_cmd -tt -a -L $SCA_SSH_AUTH_SOCK:/home/$RUSERNAME/yubikey-agent.sock -o \"SetEnv SCA_LEVEL=$level\" sca-key ragent \"$LOGNAME,$USER,$RUSERNAME,$level,$LEVEL,$HOSTNAME,$HOME\"" >/dev/null 2>&1 &
    
    ssh_pid=$!
    log_success "SSH agent forwarder is running as PID $ssh_pid"
    
    # Wait for connection to establish
    sleep $SSH_INITIAL_DELAY
    local iterations=0
    while [ $iterations -lt $SSH_RETRY_MAX ]; do
        ((iterations++))
        # Check if SSH process is still running
        if ! kill -0 "$ssh_pid" 2>/dev/null; then
            log_error "SSH process (PID $ssh_pid) died unexpectedly"
            return 1
        fi
        # Check if socket exists and is working
        if [ -S "$SCA_SSH_AUTH_SOCK" ] && check_agent_socket "$SCA_SSH_AUTH_SOCK"; then
            echo "$ssh_pid"
            return 0
        fi
        log_info "Trying to connect to agent ($iterations/$SSH_RETRY_MAX)"
        sleep $SSH_RETRY_DELAY
    done
    
    log_error "Cannot connect to agent after $SSH_RETRY_MAX attempts"
    # Check if SSH process is still running
    if kill -0 "$ssh_pid" 2>/dev/null; then
        log_error "SSH process (PID $ssh_pid) is still running but socket is not working"
        kill -TERM "$ssh_pid" 2>/dev/null
    fi
    return 1
}

# Wait for socket to be created
wait_for_socket() {
    local socket=$1
    local max_iterations=${2:-$SOCKET_WAIT_MAX}
    local delay=${3:-$SOCKET_WAIT_DELAY}
    local iterations=0
    
    while [ ! -S "$socket" ] && [ $iterations -lt $max_iterations ]; do
        ((iterations++))
        sleep $delay
    done
    
    [ -S "$socket" ]
}

#==============================================================================
# MULTIPLEXER SETUP
#==============================================================================

# Setup Python multiplexer (sshagentmux.py)
setup_python_multiplexer() {
    log_info "Starting Python multiplexer (sshagentmux.py)..."
    if [ "$REVERSE" == "1" ]; then
        log_info "Reversing the order of the agents"
        SSH_AUTH_SOCK=$SCA_SSH_AUTH_SOCK
        # shellcheck disable=SC1054,SC1009,SC1056,SC1072,SC1073
        eval "$($PLAYBOOK_DIR/sshagentmux.py --socket "${ORG_SSH_AUTH_SOCK}" --envname OMUX_)"
    else
        eval "$($PLAYBOOK_DIR/sshagentmux.py --socket "${SCA_SSH_AUTH_SOCK}" --envname OMUX_)"
    fi
    log_info "Python multiplexer started (PID: $OMUX_SSH_AGENT_PID)"
}

# Execute command or start shell
execute_command_or_shell() {
  if [ "$SHELL_MODE" == "1" ]; then
    # Shell Mode: Output environment variables in ssh-agent format
    # Disable cleanup trap so background processes keep running
    trap - EXIT INT TERM
    echo "SSH_AUTH_SOCK=$SSH_AUTH_SOCK; export SSH_AUTH_SOCK;"
    # Output PID if available (prefer MUX_PID, fallback to SSH_PID)
    AGENT_PID="${MUX_PID:-${SSH_PID:-}}"
    if [ -n "$AGENT_PID" ]; then
      echo "SSH_AGENT_PID=$AGENT_PID; export SSH_AGENT_PID;"
      echo "echo Agent pid $AGENT_PID;"
    fi
    exit 0
    
  elif [ "$SSH_MODE" == "1" ]; then
    # SSH Mode: Direct SSH connection with IdentityAgent
    # Disable cleanup trap since we're not starting any background processes
    trap - EXIT INT TERM
    # Select socket based on --key option (default: remote)
    if [ "$KEY" == "mux" ]; then
      SSH_SOCKET="$MUX_SSH_AUTH_SOCK"
    elif [ "$KEY" == "local" ]; then
      SSH_SOCKET="$ORG_SSH_AUTH_SOCK"
    else
      # Default to remote (KEY=remote or empty)
      SSH_SOCKET="$SCA_SSH_AUTH_SOCK"
    fi
    # Verify socket exists and is working
    if [ ! -S "$SSH_SOCKET" ]; then
      log_error "Socket does not exist: $SSH_SOCKET"
      exit 1
    fi
    if ! check_agent_socket "$SSH_SOCKET"; then
      log_error "Socket is not working: $SSH_SOCKET"
      exit 1
    fi
    log_info "Connecting with IdentityAgent=$SSH_SOCKET: ssh $SSH_ARGS"
    # Use -o IdentityAgent to explicitly specify the agent socket
    eval "ssh -o 'IdentityAgent \"$SSH_SOCKET\"' -o 'IdentityFile none' $SSH_ARGS"
    exit $?
    
  elif [ -n "$MYSSH" ]; then
    log_info "STARTING: $MYSSH $CMD"
    eval $MYSSH $CMD
    
  elif [ -n "$CMD" ]; then
    log_info "STARTING: $CMD"
    eval $CMD
    
  elif [ -n "$WAIT" ]; then
    # Wait Mode: Monitor connection and restart if needed
    log_info "WAIT in a Loop and check every $CHECK_SECONDS if the Connection is dead"
    while true; do
      # Check if we're intentionally exiting (Ctrl-C, etc.)
      if [ "$SCA_EXITING" == "true" ]; then
        log_info "Exiting..."
        break
      fi
      
      # Check the appropriate socket based on whether we're using multiplexer
      SOCKET_TO_CHECK="$MUX_SSH_AUTH_SOCK"
      if [ ! -S "$MUX_SSH_AUTH_SOCK" ] || [ "$MUX_SSH_AUTH_SOCK" == "$SCA_SSH_AUTH_SOCK" ]; then
        # No multiplexer, check remote agent directly
        SOCKET_TO_CHECK="$SCA_SSH_AUTH_SOCK"
      fi
      
      if ! check_agent_socket "$SOCKET_TO_CHECK"; then
        # Don't restart if we're intentionally exiting
        if [ "$SCA_EXITING" == "true" ]; then
          log_info "Exiting due to intentional termination"
          break
        fi
        log_error "Can not Connect to agent!"
        log_info "Stopping background processes before restart..."
        kill_if_exists "$SSH_PID" "SSH"
        kill_if_exists "$MUX_PID" "MUX"
        # Restart Myself
        export SCA_SUBSHELL=
        export SSH_AUTH_SOCK=$ORG_SSH_AUTH_SOCK
        log_info "Restarting MYSELF: $SCA_SCRIPT $ORG_ARGS"
        exec $SCA_SCRIPT $ORG_ARGS
        exit 255 # Should never be reached
      else
        echo -n "." >&2
      fi
      sleep $CHECK_SECONDS
    done
    
  else
    # Default: Start Interactive Subshell
    log_info "Starting Subshell"
    $SHELL
  fi
}

# Setup new connection
setup_new_connection() {
  log_info "No working agent found: Starting new connection"
  rm -f $SCA_SSH_AUTH_SOCK
  rm -f $MUX_SSH_AUTH_SOCK

  # Determine User Security Level
  MY_LEVEL=$(determine_security_level)
  if [ $? -ne 0 ]; then
    exit 1
  fi
  
  log_info "You are a Level $MY_LEVEL user"
  
  if [ -n "$LEVEL" ]; then
    if [ "$LEVEL" -ne "$MAX_LEVEL" ] && [ "$LEVEL" -lt "$MY_LEVEL" ]; then
      # User Requesting Lower Level, allow it
      log_warn "LOWER level to $LEVEL"
      MY_LEVEL=$LEVEL
    fi
  else
    log_error "Can not find your level (Maybe something is not working). Stopping"
    exit 1
  fi

  # Start Remote SSH Agent Forwarder
  # We must use an "interactive" ssh shell here, because we rely on running
  # a few commands in the global bashrc on the jumphost
  SSH_PID=$(start_remote_agent "$MY_LEVEL")
  if [ $? -ne 0 ]; then
    exit 1
  fi

  # Configure SSH Config for Jump Host Selection
  # The ".bak" is needed on MacOSX
  sed -i.bak \
    -e "s/\(-sca-magic-jump\)\(.*\)$/\1/g" \
    -e "s/\(L$MY_LEVEL-sca-magic-jump\)/\1 jump jump_local jump_my sca-jump sca-jump_org sca-jump_local sca-jump_my sca-jump_mux/g" \
    $PLAYBOOK_DIR/$SSH_CONFIG_FILE \
    $PLAYBOOK_DIR/$SSH_CONFIG_FILE_single
  
  log_success "Successfully started a remote agent at $SCA_SSH_AUTH_SOCK"
  
  # Setup Agent Multiplexer (only if we have a local agent)
  SKIP_MULTIPLEXER=false
  if [ "$USE_IDENTITY_FILE" == "true" ] && [ "$LOCAL_SOCK" == "false" ]; then
    # No local agent, only identity file - skip multiplexer
    log_info "No local agent detected, skipping multiplexer setup"
    log_info "Using remote agent directly"
    SKIP_MULTIPLEXER=true
    OMUX_SSH_AUTH_SOCK=$SCA_SSH_AUTH_SOCK
    OMUX_SSH_AGENT_PID=""
  else
    log_info "Muxing the 2 Agents to one"
    USE_RUST_MUX=false
    [ "$MUX_TYPE" = "rust" ] && USE_RUST_MUX=true
  fi

  # Set up multiplexer (only if not skipping)
  if [ "$SKIP_MULTIPLEXER" != "true" ]; then
    # We have a local agent, set up multiplexer
    if [ "$USE_RUST_MUX" == "true" ]; then
      setup_rust_multiplexer
    else
      setup_python_multiplexer
    fi
      
    # Set up multiplexer socket link
    MUX_PID=$OMUX_SSH_AGENT_PID
    # Only create symlink if socket path is different from target
    # Skip symlink creation for Rust mux direct mode since socket is already at target location
    if [ "${SKIP_SYMLINK:-false}" != "true" ]; then
        # Expand paths for comparison (handle ~ expansion)
        OMUX_EXPANDED=$(echo "$OMUX_SSH_AUTH_SOCK" | sed "s|^~|$HOME|")
        TARGET_EXPANDED=$(echo "$MUX_SSH_AUTH_SOCK" | sed "s|^~|$HOME|")
        if [ "$OMUX_EXPANDED" != "$TARGET_EXPANDED" ]; then
            ln -sf "$OMUX_SSH_AUTH_SOCK" $MUX_SSH_AUTH_SOCK
        fi
    fi
    export ORG_MUX_SSH_AUTH_SOCK=$OMUX_SSH_AUTH_SOCK
    export SSH_AUTH_SOCK=$MUX_SSH_AUTH_SOCK
    
    log_info "Verifying with: 'SSH_AUTH_SOCK=$MUX_SSH_AUTH_SOCK ssh-add -l'"
    log_success "You can now use this key (even not in this SUBSHELL, thanks to .ssh/config magic)"
    SSH_AUTH_SOCK=$MUX_SSH_AUTH_SOCK ssh-add -l >&2
  else
    # No multiplexer - use remote agent directly (identity file only mode)
    log_info "No local agent detected, using remote agent directly"
    OMUX_SSH_AUTH_SOCK=$SCA_SSH_AUTH_SOCK
    OMUX_SSH_AGENT_PID=""
    export SSH_AUTH_SOCK=$SCA_SSH_AUTH_SOCK
    export MUX_SSH_AUTH_SOCK=$SCA_SSH_AUTH_SOCK
    log_info "Verifying with: 'SSH_AUTH_SOCK=$SCA_SSH_AUTH_SOCK ssh-add -l'"
    log_success "Using remote agent directly (no local agent to multiplex)"
    SSH_AUTH_SOCK=$SCA_SSH_AUTH_SOCK ssh-add -l >&2
  fi
}

#==============================================================================
# CONNECTION MANAGEMENT
#==============================================================================

# Validate local SSH agent or identity file
validate_local_agent() {
  # Check if local SSH agent is working
  LOCAL_SOCK=false
  USE_IDENTITY_FILE=false
  IDENTITY_FILE=""

  check_agent_socket "$SSH_AUTH_SOCK" && LOCAL_SOCK=true

  if [ "$LOCAL_SOCK" == "false" ]; then
    # No agent found, check for identity files
    log_info "No local SSH agent found, checking for identity files..."
    IDENTITY_FILE=$(find_identity_file)
    if [ -n "$IDENTITY_FILE" ]; then
      USE_IDENTITY_FILE=true
      log_success "Found identity file: $IDENTITY_FILE"
    else
      log_error 'No local SSH agent or identity file found.'
      log_error 'Either start an agent with "eval $(ssh-agent)" and add your keys,'
      log_error 'or ensure you have an identity file at ~/.ssh/id_ed25519, ~/.ssh/id_rsa, etc.'
      exit 1
    fi
  else
    # Agent exists, check if it has keys loaded
    LOCAL_KEYS_NUM=$(ssh-add -l 2>/dev/null | wc -l)
    if [ -z "$LOCAL_KEYS_NUM" ] || [ "$LOCAL_KEYS_NUM" == "0" ]; then
      log_warn "Your local agent has no keys loaded"
      log_info "Checking for identity files as fallback..."
      IDENTITY_FILE=$(find_identity_file)
      if [ -n "$IDENTITY_FILE" ]; then
        USE_IDENTITY_FILE=true
        log_success "Found identity file: $IDENTITY_FILE (will use instead of empty agent)"
      else
        log_error "You have no key in your local agent and no identity file found!"
        exit 1
      fi
    else
      MYKEYS=$(ssh-add -l | wc -l)
      log_success "You have $MYKEYS keys in your local agent"
    fi
  fi
}

# Check existing connections and clean up stale ones
check_existing_connections() {
  SCA_SOCK=false
  MUX_SOCK=false
  MY_SOCKS_WORKING=true

  # Check if socket exists and is working, AND if the SSH process is still running
  if [ -S "$SCA_SSH_AUTH_SOCK" ] && check_agent_socket "$SCA_SSH_AUTH_SOCK" && check_ssh_agent_running; then
    SCA_SOCK=true
  fi

  # Only check for mux socket if we're using multiplexer (will be determined later)
  # For now, check if it exists and is working
  if [ -S "$MUX_SSH_AUTH_SOCK" ]; then
    if check_agent_socket "$MUX_SSH_AUTH_SOCK"; then
      # Also verify SSH process is running (mux depends on it)
      if check_ssh_agent_running; then
        MUX_SOCK=true
      fi
    fi
  fi

  # If remote socket is not working or SSH process is dead, we need to restart
  # If mux socket doesn't exist but remote does, that's OK (might be identity-file-only mode)
  if [ "$SCA_SOCK" == "false" ]; then
    log_info "Killing remote agent by finding ssh with ragent"
    pkill -f " ragent "
    log_info "Killing muxagent by kill sshagentmux.py"
    pkill -f "sshagentmux.py"
    log_info "Killing ssh-agent-mux processes"
    pkill -x "ssh-agent-mux" 2>/dev/null || true
    log_info "Removing stale socket files"
    rm -f "$SCA_SSH_AUTH_SOCK" 2>/dev/null || true
    rm -f "$MUX_SSH_AUTH_SOCK" 2>/dev/null || true
    MY_SOCKS_WORKING=false
  elif [ "$MUX_SOCK" == "false" ] && [ -S "$MUX_SSH_AUTH_SOCK" ]; then
    # Mux socket exists but not working - restart multiplexer
    log_info "Mux socket exists but not working, restarting multiplexer"
    pkill -f "sshagentmux.py"
    pkill -x "ssh-agent-mux" 2>/dev/null || true
    rm -f "$MUX_SSH_AUTH_SOCK" 2>/dev/null || true
    MY_SOCKS_WORKING=false
  fi
}

# Use existing connection
use_existing_connection() {
  # Still need to determine level for environment variables
  MY_LEVEL=$(determine_security_level)
  if [ $? -ne 0 ]; then
    log_error "Failed to determine security level for existing connection"
    exit 1
  fi
  
  if [ -n "$LEVEL" ]; then
    if [ "$LEVEL" -ne "$MAX_LEVEL" ] && [ "$LEVEL" -lt "$MY_LEVEL" ]; then
      # User Requesting Lower Level, allow it
      log_warn "LOWER level to $LEVEL"
      MY_LEVEL=$LEVEL
    fi
  fi
  
  # Determine which socket to use
  if [ -S "$MUX_SSH_AUTH_SOCK" ] && check_agent_socket "$MUX_SSH_AUTH_SOCK"; then
    log_info "Using working multiplexed SSH_AUTH_SOCK=$MUX_SSH_AUTH_SOCK"
    export SSH_AUTH_SOCK=$MUX_SSH_AUTH_SOCK
  elif [ -S "$SCA_SSH_AUTH_SOCK" ] && check_agent_socket "$SCA_SSH_AUTH_SOCK"; then
    log_info "Using working remote SSH_AUTH_SOCK=$SCA_SSH_AUTH_SOCK"
    export SSH_AUTH_SOCK=$SCA_SSH_AUTH_SOCK
    export MUX_SSH_AUTH_SOCK=$SCA_SSH_AUTH_SOCK
  else
    log_error "No working agent socket found"
    exit 1
  fi
}

# Setup Rust multiplexer (ssh-agent-mux)
setup_rust_multiplexer() {
    log_info "Using ssh-agent-mux (Rust)"
    
    if ! command -v ssh-agent-mux >/dev/null 2>&1; then
        log_error "ssh-agent-mux not found in PATH"
        log_info "Hint: Install it from https://github.com/overhacked/ssh-agent-mux"
        log_info "Hint: cargo install ssh-agent-mux"
        log_info "Hint: Or download binary from releases page"
        exit 1
    fi

    CONFIG_FILE="$HOME/.config/ssh-agent-mux/ssh-agent-mux.toml"
    if [ ! -f "$CONFIG_FILE" ]; then
        log_error "Config file not found at $CONFIG_FILE"
        log_info "Hint: Create it with the following content:"
        echo 'agent_sock_paths = [' >&2
        echo '    "'"$SSH_AUTH_SOCK"'",  # Your local agent' >&2
        echo '    "~/.ssh/scadev-agent.sock",  # Remote agent' >&2
        echo ']' >&2
        echo 'listen_path = "~/.ssh/ssh-agent-mux.sock"' >&2
        exit 1
    fi

    # Check if ssh-agent-mux is installed as a service
    RUST_MUX_IS_SERVICE=false
    if [[ "$OSTYPE" == "darwin"* ]]; then
        # Check for launchd service on macOS - check for plist file
        PLIST_FILE="$HOME/Library/LaunchAgents/net.ross-williams.ssh-agent-mux.plist"
        if [ -f "$PLIST_FILE" ]; then
            # Also verify it's loaded
            if launchctl list 2>/dev/null | grep -q "net.ross-williams.ssh-agent-mux"; then
                RUST_MUX_IS_SERVICE=true
                log_success "Detected ssh-agent-mux as launchd service"
            fi
        fi
    elif command -v systemctl >/dev/null 2>&1; then
        # Check for systemd user service on Linux
        if systemctl --user list-unit-files 2>/dev/null | grep -q "ssh-agent-mux.service"; then
            RUST_MUX_IS_SERVICE=true
            log_success "Detected ssh-agent-mux as systemd service"
        fi
    fi

    if [ "$RUST_MUX_IS_SERVICE" == "true" ]; then
        # Service Mode: Use existing ssh-agent-mux service
        # Extract socket path from config (default: ~/.ssh/ssh-agent-mux.sock)
        RUST_MUX_SOCKET=$(grep -E '^\s*listen_path\s*=' "$CONFIG_FILE" | sed -E 's/^[^"]*"([^"]+)".*/\1/' | sed "s|~|$HOME|")
        if [ -z "$RUST_MUX_SOCKET" ]; then
             RUST_MUX_SOCKET="$HOME/.ssh/ssh-agent-mux.sock"
        fi

        if ! pgrep -x "ssh-agent-mux" >/dev/null; then
             log_error "ssh-agent-mux service is not running"
             log_info "Hint: Start it with: ssh-agent-mux --restart-service"
             if [[ "$OSTYPE" == "darwin"* ]]; then
                 log_info "Hint: Or (macOS): launchctl kickstart -k gui/$(id -u)/net.ross-williams.ssh-agent-mux"
             elif command -v systemctl >/dev/null 2>&1; then
                 log_info "Hint: Or (Linux): systemctl --user start ssh-agent-mux.service"
             fi
             exit 1
        fi

        # Configure macOS logging if needed
        if [[ "$OSTYPE" == "darwin"* ]]; then
         PLIST_FILE="$HOME/Library/LaunchAgents/net.ross-williams.ssh-agent-mux.plist"
         if [ -f "$PLIST_FILE" ]; then
             # Check if logging keys are configured
             if ! grep -q "StandardOutPath" "$PLIST_FILE" || ! grep -q "StandardErrorPath" "$PLIST_FILE"; then
                 log_info "Configuring file-based logging in launchd plist..."
                 cp "$PLIST_FILE" "$PLIST_FILE.bak"
                 # Add logging paths before closing </dict>
                 sed -i '' '/<\/dict>/i\
        <key>StandardOutPath</key>\
        <string>'"$HOME"'/Library/Logs/ssh-agent-mux.log</string>\
        <key>StandardErrorPath</key>\
        <string>'"$HOME"'/Library/Logs/ssh-agent-mux.err.log</string>
' "$PLIST_FILE"
                 log_info "Restarting ssh-agent-mux service to apply logging configuration..."
                 launchctl bootout gui/$(id -u)/net.ross-williams.ssh-agent-mux
                 launchctl bootstrap gui/$(id -u) ~/Library/LaunchAgents/net.ross-williams.ssh-agent-mux.plist
                 sleep 1
             fi
         fi
         
         # Display logs if available
         MACOS_LOG_FILE="$HOME/Library/Logs/ssh-agent-mux.log"
         if [ -f "$MACOS_LOG_FILE" ]; then
              log_info "ssh-agent-mux logs: $MACOS_LOG_FILE"
              show_harmless_error_note
              echo "$(color setaf 6)--- Recent log entries (filtered) ---$(color sgr0)" >&2
              # Filter out harmless errors from ssh-agent-mux
              tail -n 50 "$MACOS_LOG_FILE" | grep -vE "ERROR \[ssh_agent_lib::agent\] Error handling message: Failure|ERROR \[ssh_agent_mux\] Unexpected error on socket.*when requesting session-bind@openssh.com extension.*Protocol error.*Unexpected response received" | tail -n 10 >&2
              echo "$(color setaf 6)--- Tailing logs (filtered, PID will be cleaned up on exit) ---$(color sgr0)" >&2
              # Filter out harmless errors while tailing
              tail -Fq "$MACOS_LOG_FILE" 2>&1 | grep -vE "ERROR \[ssh_agent_lib::agent\] Error handling message: Failure|ERROR \[ssh_agent_mux\] Unexpected error on socket.*when requesting session-bind@openssh.com extension.*Protocol error.*Unexpected response received" >&2 &
              TAIL_LOG_PID=$!
         else
              log_info "To view ssh-agent-mux logs (macOS):"
              echo "  log stream --predicate 'process == \"ssh-agent-mux\"' --level debug" >&2
              show_harmless_error_note
         fi
    elif command -v journalctl >/dev/null 2>&1; then
         # Display logs with filtering for Linux systemd service
         log_info "ssh-agent-mux logs (Linux systemd):"
         show_harmless_error_note
         echo "$(color setaf 6)--- Recent log entries (filtered) ---$(color sgr0)" >&2
         # Filter out harmless errors from recent logs
         journalctl --user -u ssh-agent-mux -n 50 --no-pager 2>/dev/null | grep -vE "ERROR \[ssh_agent_lib::agent\] Error handling message: Failure|ERROR \[ssh_agent_mux\] Unexpected error on socket.*when requesting session-bind@openssh.com extension.*Protocol error.*Unexpected response received" | tail -n 10 >&2
         echo "$(color setaf 6)--- Tailing logs (filtered, PID will be cleaned up on exit) ---$(color sgr0)" >&2
         # Filter out harmless errors while tailing
         journalctl --user -u ssh-agent-mux -f 2>&1 | grep -vE "ERROR \[ssh_agent_lib::agent\] Error handling message: Failure|ERROR \[ssh_agent_mux\] Unexpected error on socket.*when requesting session-bind@openssh.com extension.*Protocol error.*Unexpected response received" >&2 &
         TAIL_LOG_PID=$!
    fi

    # Warn if remote agent socket is not in config
    if ! grep -q "scadev-agent.sock" "$CONFIG_FILE"; then
         log_warn "Your ssh-agent-mux config does not seem to include ~/.ssh/scadev-agent.sock"
         log_info "Hint: Add it to agent_sock_paths in $CONFIG_FILE:"
             echo 'agent_sock_paths = ["'"$SSH_AUTH_SOCK"'", "~/.ssh/scadev-agent.sock"]' >&2
        fi

        OMUX_SSH_AUTH_SOCK=$RUST_MUX_SOCKET
        # Don't set OMUX_SSH_AGENT_PID for services - they're managed by launchctl/systemctl
        OMUX_SSH_AGENT_PID=""
        SKIP_SYMLINK=false
        
    else
        # Direct Mode: Run ssh-agent-mux directly (not as service)
        log_info "ssh-agent-mux is not installed as a service, starting it directly"
        
        # Determine socket path (use mux_auth_sock template variable)
        RUST_MUX_SOCKET=$MUX_SSH_AUTH_SOCK
        
        # Remove socket if it exists
        rm -f "$RUST_MUX_SOCKET"
        
        # Determine agent order based on REVERSE flag
        if [ "$REVERSE" == "1" ]; then
            AGENT1="$SCA_SSH_AUTH_SOCK"
            AGENT2="$SSH_AUTH_SOCK"
        else
            AGENT1="$SSH_AUTH_SOCK"
            AGENT2="$SCA_SSH_AUTH_SOCK"
        fi
        
        # Create temporary config file for ssh-agent-mux
        TEMP_CONFIG=$(mktemp)
        cat > "$TEMP_CONFIG" <<EOF
agent_sock_paths = [
    "$AGENT1",
    "$AGENT2",
]
listen_path = "$RUST_MUX_SOCKET"
log_level = "info"
EOF
        
        # Start ssh-agent-mux with temporary config file
        log_info "Starting ssh-agent-mux directly..."
        # Create temp log file for filtered output
        RUST_MUX_LOG=$(mktemp)
        # Start ssh-agent-mux and filter its output
        ssh-agent-mux --config "$TEMP_CONFIG" > "$RUST_MUX_LOG" 2>&1 &
        RUST_MUX_PID=$!
        log_info "Started ssh-agent-mux as PID $RUST_MUX_PID"
        # Tail the log file with filtering in background
        log_info "Starting log tail process for ssh-agent-mux..."
        tail -Fq "$RUST_MUX_LOG" 2>&1 | grep -vE "ERROR \[ssh_agent_lib::agent\] Error handling message: Failure|ERROR \[ssh_agent_mux\] Unexpected error on socket.*when requesting session-bind@openssh.com extension.*Protocol error.*Unexpected response received" >&2 &
        TAIL_LOG_PID=$!
        log_info "Started log tail process as PID $TAIL_LOG_PID"
        
        # Clean up temp config file after a short delay (process should have read it)
        (sleep 1 && rm -f "$TEMP_CONFIG") &
        
        # Wait for socket to be created
        if ! wait_for_socket "$RUST_MUX_SOCKET"; then
            log_error "Failed to start ssh-agent-mux or create socket at $RUST_MUX_SOCKET"
            kill $RUST_MUX_PID 2>/dev/null
            exit 1
        fi
        
        # Verify it's working
        if ! check_agent_socket "$RUST_MUX_SOCKET"; then
            log_error "ssh-agent-mux socket created but not responding"
            kill $RUST_MUX_PID 2>/dev/null
            exit 1
        fi
        
        OMUX_SSH_AUTH_SOCK=$RUST_MUX_SOCKET
        OMUX_SSH_AGENT_PID=$RUST_MUX_PID
        SKIP_SYMLINK=true
        log_success "Started ssh-agent-mux directly (PID: $RUST_MUX_PID)"
    fi
}

#==============================================================================
# ARGUMENT PARSING
#==============================================================================

# Parse command-line arguments
parse_arguments() {
  local help_text="$1"
  shift
  # Parse arguments manually for cleaner handling of both short and long options
  while [ $# -gt 0 ]; do
  case "$1" in
    -h|--help)
      echo "$help_text" >&2
      exit 1
      ;;
    -d|--debug)
      DEBUG=1
      shift
      ;;
    -r|--reverse)
      REVERSE=1
      shift
      ;;
    -w|--wait)
      WAIT=1
      shift
      ;;
    -e|--env)
      SHELL_MODE=1
      shift
      ;;
    -l|--level)
      if [ -z "$2" ]; then
        log_error "Option $1 requires an argument"
        exit 1
      fi
      LEVEL="$2"
      shift 2
      ;;
    --level=*)
      LEVEL="${1#*=}"
      shift
      ;;
    --key=local)
      KEY=local
      shift
      ;;
    --key=remote)
      KEY=remote
      shift
      ;;
    --key=mux)
      KEY=mux
      shift
      ;;
    --mux=*)
      MUX_TYPE="${1#*=}"
      shift
      ;;
    --list)
      do_cmd "list"
      exit 1
      ;;
    --find|--add)
      CMD_NAME="${1#--}"
      if [ -z "$2" ]; then
        log_error "Option $1 requires an argument"
        exit 1
      fi
      do_cmd "$CMD_NAME" "$2"
      exit 1
      ;;
    -s|--ssh|--connect)
      shift
      # Collect all remaining arguments for SSH (everything after --ssh)
      SSH_ARGS="$*"
      SSH_MODE=1
      # Clear remaining args so they don't get processed as options
      set --
      ;;
    --kill)
      log_info "Killing all agents and remote connections..."
      log_info "Killing remote agent (ssh with ragent)"
      pkill -f " ragent "
      log_info "Killing Python multiplexer (sshagentmux.py)"
      pkill -f "sshagentmux.py"
      log_info "Removing socket files"
      rm -f $SCA_SSH_AUTH_SOCK
      rm -f $MUX_SSH_AUTH_SOCK
      log_success "All agents and connections killed"
      exit 0
      ;;
    --*)
      log_error "Unknown option: $1"
      exit 1
      ;;
    -*)
      # Handle short options that can be combined (e.g., -dr)
      OPTARG="${1#-}"
      while [ -n "$OPTARG" ]; do
        case "${OPTARG:0:1}" in
          h)
            echo "$help_text" >&2
            exit 1
            ;;
          d)
            DEBUG=1
            OPTARG="${OPTARG#?}"
            ;;
          r)
            REVERSE=1
            OPTARG="${OPTARG#?}"
            ;;
          w)
            WAIT=1
            OPTARG="${OPTARG#?}"
            ;;
          e)
            SHELL_MODE=1
            OPTARG="${OPTARG#?}"
            ;;
          s)
            shift
            # Collect all remaining arguments for SSH (everything after -s)
            SSH_ARGS="$*"
            SSH_MODE=1
            # Clear remaining args so they don't get processed as options
            set --
            OPTARG=""
            ;;
          l)
            if [ -z "$2" ]; then
              log_error "Option -l requires an argument"
              exit 1
            fi
            LEVEL="$2"
            shift
            OPTARG=""
            ;;
          *)
            log_error "Unknown option: -${OPTARG:0:1}"
            exit 1
            ;;
        esac
      done
      shift
      ;;
    *)
      # Non-option argument - remaining args are the command
      CMD="$*"
      break
      ;;
  esac
  done
}

#==============================================================================
# MAIN FUNCTION
#==============================================================================

sca_main() {
# Constants
readonly MAX_LEVEL=99                    # Maximum security level to try
readonly SSH_RETRY_MAX=10                # Maximum retries for SSH connection
readonly SSH_RETRY_DELAY=1               # Delay between SSH retries (seconds)
readonly SSH_INITIAL_DELAY=0.1           # Initial delay before checking socket (seconds)
readonly SOCKET_WAIT_MAX=10              # Maximum wait iterations for socket creation
readonly SOCKET_WAIT_DELAY=0.1           # Delay between socket checks (seconds)

# Default values
LEVEL=$MAX_LEVEL            # Maximum security level to try
REVERSE=0                   # Reverse agent order when multiplexing
MUX_TYPE="python"           # Multiplexer type: python (default), rust
CHECK_SECONDS=30            # Seconds between connection checks in wait mode
SHELL_MODE=0                # Output env vars in shell format (like ssh-agent -s)

# Runtime variables
KEY=
MYSSH=
ORG_ARGS=$*
ORG_SSH_AUTH_SOCK=$SSH_AUTH_SOCK
SSH_MODE=0                # Direct SSH connection mode
SSH_ARGS=                 # Arguments for SSH command
# CMD will be set after argument parsing


HELP="Usage: $SCA_SCRIPT [OPTIONS] [command]

Options:
  -h, --help            Show this help message and exit
  -d, --debug           Enable debug mode (verbose output)
  -r, --reverse         Reverse the order of agents when multiplexing
  -w, --wait            Run in background and monitor connection, restart if needed
  -e, --env             Output environment variables in shell format (like ssh-agent -s)
                        Use with: eval \`$SCA_SCRIPT -e --key=local\` to set SSH_AUTH_SOCK in current shell
  -l, --level LEVEL     Set security level (0-3, default: auto-detect)
  --key=local|remote|mux  Specify which key to use (default: remote)
                           local:  Use local SSH agent only
                           remote: Use remote SSH agent only (default)
                           mux:    Use multiplexed agent (combines local + remote)
  --mux=python|rust     Choose multiplexer type (default: python)
  --list                List all configured hosts
  --find HOSTNAME       Find and display information about a specific host
  --add HOSTNAME        Add a new host to the configuration
  -s, --ssh [args...]   Connect directly via ssh with specified agent
                        All arguments after --ssh are passed directly to ssh
                        Use with --key to select agent: local, remote, or mux
  --kill                Kill all agents and remote connections, remove socket files

Examples:
  $SCA_SCRIPT --key=local                    # Start subshell with local key
  $SCA_SCRIPT --key=remote                   # Start subshell with remote key (default)
  $SCA_SCRIPT --key=mux                      # Start subshell with multiplexed agent
  eval \`$SCA_SCRIPT -e --key=local\`         # Set SSH_AUTH_SOCK in current shell
  $SCA_SCRIPT --list                          # List all configured hosts
  $SCA_SCRIPT --find myserver                 # Find host 'myserver'
  $SCA_SCRIPT --ssh myserver                  # Connect to 'myserver' (uses remote agent)
  $SCA_SCRIPT --key=local --ssh user@host     # Connect using local agent
  $SCA_SCRIPT --key=mux --ssh -p9922 host    # Connect using multiplexed agent with custom port
  $SCA_SCRIPT --wait                          # Run in background monitoring mode
  $SCA_SCRIPT --kill                          # Clean up all agents and connections"

# Parse arguments
parse_arguments "$HELP" "$@"

# Set up exit trap for cleanup
SCA_EXITING=false
trap cleanup EXIT INT TERM

validate_local_agent
check_existing_connections

#==============================================================================
# SETUP NEW CONNECTION (if needed)
#==============================================================================

if [ "$MY_SOCKS_WORKING" == "false" ]; then
  setup_new_connection
else
  use_existing_connection
fi

#==============================================================================
# SETUP ENVIRONMENT VARIABLES
#==============================================================================

# SSH_AUTH_SOCK and MUX_SSH_AUTH_SOCK are already set above based on whether
# we're using multiplexer or not. Ensure all environment variables are exported.
export SCA_SSH_AUTH_SOCK=$SCA_SSH_AUTH_SOCK
# Ensure MUX_SSH_AUTH_SOCK is set (may be same as SCA_SSH_AUTH_SOCK if no multiplexer)
export MUX_SSH_AUTH_SOCK=${MUX_SSH_AUTH_SOCK:-$SCA_SSH_AUTH_SOCK}
export SCA_SUBSHELL=SCA-KEY
export SCA_USER=$RUSERNAME
export SCA_JUMPHOST=sca-jump-level$MY_LEVEL
export SCA_LEVEL=$MY_LEVEL

log_success "Hello $RUSERNAME($LOGNAME) you are level $SCA_LEVEL and using $SCA_JUMPHOST"

execute_command_or_shell

#==============================================================================
# CLEANUP (fallback - trap handles most cases)
#==============================================================================

kill_if_exists "$SSH_PID" "SSH"
kill_if_exists "$MUX_PID" "MUX"
kill_if_exists "$TAIL_LOG_PID" "log tail"

exit 0
}
