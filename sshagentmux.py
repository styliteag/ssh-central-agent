#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# vim: tabstop=4 shiftwidth=4 softtabstop=4
#
# Copyright 2015, IBM
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

import argparse
import logging
import logging.handlers
import multiprocessing
import os
import pathlib
import socketserver
import struct
import sys
import tempfile
import atexit
import signal
import hashlib
import re
import socket
import threading
import queue as Queue
import time
import base64
import json

# Windows named pipe support
if sys.platform == "win32":
    try:
        import win32file
        HAS_WIN32 = True
    except ImportError:
        HAS_WIN32 = False
else:
    HAS_WIN32 = False


class _WindowsNamedPipeSocket:
    """Wrapper for Windows named pipes to work like a socket."""
    def __init__(self, handle):
        self.handle = handle
        self._closed = False
    
    def sendall(self, data):
        """Send all data through the named pipe."""
        if self._closed:
            raise socket.error("Pipe is closed")
        try:
            win32file.WriteFile(self.handle, data)
        except Exception as e:
            raise socket.error(f"Write error: {e}")
    
    def recv(self, bufsize):
        """Receive data from the named pipe."""
        if self._closed:
            raise socket.error("Pipe is closed")
        try:
            result, data = win32file.ReadFile(self.handle, bufsize)
            return data
        except Exception as e:
            if "EOF" in str(e) or "broken pipe" in str(e).lower():
                return b""
            raise socket.error(f"Read error: {e}")
    
    def close(self):
        """Close the named pipe."""
        if not self._closed:
            try:
                win32file.CloseHandle(self.handle)
            except Exception:
                pass
            self._closed = True
    
    def __enter__(self):
        return self
    
    def __exit__(self, *args):
        self.close()

LOG = logging.getLogger(__name__)
mypid = 0


def setup_logging(name, level=logging.DEBUG):
    log = logging.getLogger()
    log.setLevel(level)
    # handler = logging.handlers.SysLogHandler(address=address)
    # handler = logging.StreamHandler(sys.stdout)
    handler = logging.FileHandler("/dev/stderr")
    # handler.setLevel(level)

    # Clean format - just the message with minimal prefix
    FORMAT = "SSH: %(message)s"
    formatter = logging.Formatter(fmt=FORMAT)
    handler.setFormatter(formatter)
    log.addHandler(handler)


class UpstreamSocketThread(threading.Thread):
    SSH_AGENT_FAILURE = bytearray(struct.pack('> I B', 1, 5))
    timeout = 30

    def __init__(self, socket_path):
        super(UpstreamSocketThread, self).__init__()
        self._socket_path = socket_path
        queue = Queue.Queue()

        if queue is None:
            queue = Queue.Queue()
        self._queue = queue
        self.daemon = True
        self._sock = None
        self._retries = 5
        self._reconnect()

    def __str__(self):
        return self._socket_path

    def forward_request(self, msg):
        """
        Called my other thread submitting a request
        """
        response_queue = Queue.Queue(1)
        request = (msg, response_queue)
        self._queue.put(request)

        response = response_queue.get(True, self.timeout)

        return response

    def run(self):
        # Reuse connection
        while True:
            request_msg, response_queue = self._queue.get()
            for attempt in range(self._retries):
                try:
                    self._sock.sendall(request_msg)
                    response_msg = self._recv_msg()
                except socket.error as msg:
                    LOG.debug("upstream agent error: %s", msg)
                    for chunk in self._hex_dump_chunks(request_msg):
                        LOG.debug("upstream agent request: %s" % chunk)
                    self._reconnect()
                else:
                    response_queue.put(response_msg)
                    break
            else:
                response_queue.put(self.SSH_AGENT_FAILURE)

    def _hex_dump_chunks(self, msg):
        for i in range(0, len(msg), 16):
            yield " ".join("{:02x}".format(c) for c in msg[i:i + 16])

    def _reconnect(self):
        if self._sock is not None:
            self._sock.close()

        # Check if this is a Windows named pipe
        if sys.platform == "win32" and (
            self._socket_path.startswith("\\\\.\\pipe\\") or
            self._socket_path.startswith("\\\\")
        ):
            # Windows named pipe
            if HAS_WIN32:
                # Use win32pipe for native Windows named pipe support
                try:
                    # Convert \\.\pipe\name to proper format
                    pipe_name = self._socket_path
                    if pipe_name.startswith("\\\\.\\pipe\\"):
                        pipe_name = pipe_name[9:]  # Remove \\.\pipe\
                    
                    # Open named pipe
                    handle = win32file.CreateFile(
                        f"\\\\.\\pipe\\{pipe_name}",
                        win32file.GENERIC_READ | win32file.GENERIC_WRITE,
                        0,
                        None,
                        win32file.OPEN_EXISTING,
                        0,
                        None
                    )
                    # Wrap in a file-like object that works with socket interface
                    # For now, we'll use a workaround with a custom socket wrapper
                    # Note: This is a simplified implementation
                    self._sock = _WindowsNamedPipeSocket(handle)
                except Exception as e:
                    LOG.error("Failed to connect to Windows named pipe %s: %s", self._socket_path, e)
                    raise
            else:
                # Fallback: try to use socket with special Windows handling
                # Windows OpenSSH named pipes can sometimes be accessed via TCP localhost
                # This is a workaround - proper support requires pywin32
                LOG.warning("Windows named pipe support requires pywin32. Install with: pip install pywin32")
                raise socket.error("Windows named pipe support requires pywin32")
        else:
            # Unix socket
            if not hasattr(socket, 'AF_UNIX'):
                raise socket.error("Unix sockets not supported on this platform")
            self._sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            self._sock.connect(self._socket_path)

    def _recv_msg(self):
        msg_length = 4
        msg_buffer = bytearray()

        while len(msg_buffer) < msg_length:
            chunk = self._sock.recv(msg_length - len(msg_buffer))
            if not chunk:
                return
            msg_buffer.extend(chunk)

            if msg_length == 4 and len(msg_buffer) == 4:
                msg_length = 4 + struct.unpack('> I', msg_buffer)[0]

        return msg_buffer


class BaseAgentRequestHandler(socketserver.BaseRequestHandler):
    SSH2_AGENTC_REQUEST_IDENTITIES = 11
    SSH2_AGENT_IDENTITIES_ANSWER = 12
    SSH2_AGENTC_SIGN_REQUEST = 13
    SSH2_AGENTC_EXTENSION = 27
    PEERCRED_STRUCT = struct.Struct('= I I I')

    def handle(self):
        """
        Handle a single SSH agent session
        """
        raise Exception('Unimplemented')

    def _key_digest(self, key_blob):
        m = hashlib.md5()
        # Ensure key_blob is bytes
        if isinstance(key_blob, str):
            key_blob = key_blob.encode('utf-8')
        m.update(key_blob)

        return ':'.join(re.findall(r'.{1,2}', m.hexdigest(), re.DOTALL))

    def _key_digest_sha256(self, key_blob):
        """Generate SHA256 fingerprint of key blob (more secure than MD5)"""
        m = hashlib.sha256()
        # Ensure key_blob is bytes
        if isinstance(key_blob, str):
            key_blob = key_blob.encode('utf-8')
        m.update(key_blob)
        return 'SHA256:' + base64.b64encode(m.digest()).decode('ascii')

    def _parse_key_blob(self, key_blob):
        """
        Parse SSH key blob to extract key type and parameters
        Returns dict with key information
        """
        if not key_blob or len(key_blob) < 4:
            return {"key_type": "unknown", "key_size": 0, "error": "Invalid key blob"}
        
        # Ensure key_blob is bytes
        if isinstance(key_blob, str):
            key_blob = key_blob.encode('latin1')  # SSH blobs use binary data
        
        try:
            # First 4 bytes are length of key type string
            key_type_len = struct.unpack('>I', key_blob[0:4])[0]
            if len(key_blob) < 4 + key_type_len:
                return {"key_type": "unknown", "key_size": 0, "error": "Truncated key blob"}
            
            # Extract key type string
            key_type = key_blob[4:4+key_type_len].decode('ascii')
            
            key_info = {"key_type": key_type, "key_size": 0}
            
            # Parse key-specific parameters
            if key_type == "ssh-rsa":
                key_info.update(self._parse_rsa_key_blob(key_blob, 4 + key_type_len))
            elif key_type.startswith("ecdsa-sha2-"):
                key_info.update(self._parse_ecdsa_key_blob(key_blob, 4 + key_type_len))
            elif key_type == "ssh-ed25519":
                key_info.update(self._parse_ed25519_key_blob(key_blob, 4 + key_type_len))
            else:
                key_info["key_size"] = len(key_blob) * 8  # Rough estimate
            
            return key_info
            
        except Exception as e:
            return {"key_type": "unknown", "key_size": 0, "error": str(e)}

    def _parse_rsa_key_blob(self, key_blob, offset):
        """Parse RSA key parameters from key blob"""
        try:
            # Skip exponent length and exponent
            if offset + 4 > len(key_blob):
                return {"key_size": 0, "error": "Invalid RSA key blob"}
            
            e_len = struct.unpack('>I', key_blob[offset:offset+4])[0]
            offset += 4 + e_len
            
            # Get modulus length
            if offset + 4 > len(key_blob):
                return {"key_size": 0, "error": "Invalid RSA key blob"}
            
            n_len = struct.unpack('>I', key_blob[offset:offset+4])[0]
            # RSA key size is the modulus length in bits
            key_size = n_len * 8
            
            return {"key_size": key_size}
            
        except Exception as e:
            return {"key_size": 0, "error": str(e)}

    def _parse_ecdsa_key_blob(self, key_blob, offset):
        """Parse ECDSA key parameters from key blob"""
        try:
            # Extract curve name
            if offset + 4 > len(key_blob):
                return {"key_size": 0, "error": "Invalid ECDSA key blob"}
            
            curve_len = struct.unpack('>I', key_blob[offset:offset+4])[0]
            if offset + 4 + curve_len > len(key_blob):
                return {"key_size": 0, "error": "Invalid ECDSA key blob"}
            
            curve_name = key_blob[offset+4:offset+4+curve_len].decode('ascii')
            
            # Map curve names to key sizes
            curve_sizes = {
                "nistp256": 256,
                "nistp384": 384,
                "nistp521": 521
            }
            
            key_size = curve_sizes.get(curve_name, 0)
            return {"key_size": key_size, "curve": curve_name}
            
        except Exception as e:
            return {"key_size": 0, "error": str(e)}

    def _parse_ed25519_key_blob(self, key_blob, offset):
        """Parse Ed25519 key parameters from key blob"""
        # Ed25519 keys are always 256 bits
        return {"key_size": 256}

    def _extract_key_info_simple(self, key_blob, key_comment=None):
        """
        Simple key info extraction that works reliably
        """
        key_info = {"key_type": "unknown", "key_size": 0}
        
        # Simple key type extraction
        try:
            if len(key_blob) >= 4:
                key_type_len = struct.unpack('>I', key_blob[0:4])[0]
                if len(key_blob) >= 4 + key_type_len:
                    key_type = key_blob[4:4+key_type_len].decode('ascii')
                    key_info["key_type"] = key_type
        except:
            pass
        
        # Simple comment parsing
        if key_comment:
            try:
                if isinstance(key_comment, (bytes, bytearray)):
                    comment_str = key_comment.decode('utf-8', errors='ignore')
                else:
                    comment_str = str(key_comment)
                key_info["comment"] = comment_str
            except:
                key_info["comment"] = ""
        
        return key_info

    def _extract_key_info(self, key_blob, key_comment=None):
        """
        Extract comprehensive key information including type, size, and fingerprints
        """
        key_info = self._parse_key_blob(key_blob)
        
        # Add fingerprints
        key_info["md5_fingerprint"] = self._key_digest(key_blob)
        key_info["sha256_fingerprint"] = self._key_digest_sha256(key_blob)
        
        # Parse comment if provided
        if key_comment:
            comment_info = self._parse_key_comment(key_comment)
            key_info.update(comment_info)
        
        return key_info

    def _parse_key_comment(self, key_comment):
        """
        Parse key comment to extract username and hostname
        """
        if not key_comment:
            return {"username": None, "hostname": None, "comment": ""}
        
        try:
            comment_str = key_comment.decode('utf-8') if isinstance(key_comment, bytes) else key_comment
        except UnicodeDecodeError:
            comment_str = str(key_comment)
        
        # Look for user@hostname pattern
        if '@' in comment_str:
            parts = comment_str.split('@', 1)
            if len(parts) == 2:
                username = parts[0].strip()
                hostname = parts[1].strip()
                return {"username": username, "hostname": hostname, "comment": comment_str}
        
        # If no @ found, treat entire comment as description
        return {"username": None, "hostname": None, "comment": comment_str}

    def _parse_identities(self, response):
        """
        Parse a SSH2_AGENT_IDENTITIES_ANSWER yielding each identity as a key,
        comment tuple
        """
        r_len, r_type = struct.unpack_from('> I B', response)
        offset = struct.calcsize('> I B')
        if r_type != self.SSH2_AGENT_IDENTITIES_ANSWER:
            return

        id_count = struct.unpack_from('> I', response, offset)[0]
        offset += struct.calcsize('> I')

        for i in range(id_count):
            key_blob_len = struct.unpack_from('> I', response, offset)[0]
            offset += struct.calcsize('> I')
            key_blob = response[offset:offset + key_blob_len]
            offset += key_blob_len

            key_comment_len = struct.unpack_from('> I', response,
                                                 offset)[0]
            offset += struct.calcsize('> I')
            key_comment = response[offset:offset + key_comment_len]
            offset += key_comment_len

            yield(key_blob, key_comment)

    def _build_identities_answer(self, identities):
        """
        Build a SSH2_AGENT_IDENTITIES_ANSWER out of a list of key, comment
        tuples
        """
        answer = bytearray(9)
        # Leave length and identity count zero for now
        struct.pack_into('> I B I', answer, 0, 0,
                         self.SSH2_AGENT_IDENTITIES_ANSWER, 0)

        identity_count = 0
        for key_blob, key_comment in identities:
            blob_length = bytearray(4)
            struct.pack_into('> I', blob_length, 0, len(key_blob))

            answer.extend(blob_length)
            answer.extend(key_blob)

            comment_length = bytearray(4)
            struct.pack_into('> I', comment_length, 0, len(key_comment))

            answer.extend(comment_length)
            answer.extend(key_comment)

            identity_count += 1

        answer_length = len(answer) - 4

        # Now we can fill in the response length and identity count
        struct.pack_into('> I', answer, 0, answer_length)
        struct.pack_into('> I', answer, 5, identity_count)

        return answer

    def _each_msg(self):
        """
        Iterate over agent protocol messages
        """
        while True:
            msg_length = 4
            msg_buffer = bytearray()

            while len(msg_buffer) < msg_length:
                recv_len = msg_length - len(msg_buffer)
                chunk = self.request.recv(recv_len)
                if not chunk:
                    return

                msg_buffer.extend(chunk)
                if msg_length == 4 and len(msg_buffer) == 4:
                    msg_length = 4 + struct.unpack('> I', msg_buffer)[0]

            yield msg_buffer

#    def _fetch_process_info(self):
#        """
#        Retrieve the command line of the process
#        """
#        self.process_info = 'pid={}'.format(self.peer_pid)
#        ps_cmd = ['ps', '-o', 'args', '-ww', '-p', '{}'.format(self.peer_pid)]
#        ps_output = subprocess.check_output(ps_cmd)
#        self.process_info = ps_output.split('\n')[1]


def daemonize(target=None, pidfile=None, stdin='/dev/null', stdout='/dev/null',
              stderr='/dev/null', args=(), kwargs={}, envname=''):

    global mypid

    # if pidfile and os.path.exists(pidfile):
    #    raise RuntimeError('Already running')

    # First fork (detaches from parent)
    try:
        r, w = os.pipe()
        # print('grandparent {}'.format(os.getpid()))
        child = os.fork()
        if child > 0:
            os.close(w)
            grandchild_pid = int(os.fdopen(r).readline().strip())
            # print('grand child pid: {}'.format(grandchild_pid))
            mypid = grandchild_pid
            return
    except OSError:
        raise RuntimeError('fork #1 failed.')

    os.chdir('/')
    os.umask(0o077)
    os.setsid()

    # Second fork (relinquish session leadership)
    try:
        # print('parent {}'.format(os.getpid()))
        child = os.fork()
        if child > 0:
            os.close(r)
            # Pass child (grandchild)'s pid to parent.
            os.write(w, '{}\n'.format(child).encode())
            raise SystemExit(0)
    except OSError as e:
        raise RuntimeError('fork #2 failed with error %s' % e)

    # print('child {}'.format(os.getpid()))
    # Flush I/O buffers
    sys.stdout.flush()
    sys.stderr.flush()

    # Replace file descriptors for stdin, stdout, and stderr
    with open(stdin, 'rb', 0) as f:
        os.dup2(f.fileno(), sys.stdin.fileno())
    with open(stdout, 'ab', 0) as f:
        os.dup2(f.fileno(), sys.stdout.fileno())
    with open(stderr, 'ab', 0) as f:
        os.dup2(f.fileno(), sys.stderr.fileno())

    if pidfile:
        # Write the PID file
        with open(pidfile, 'w') as f:
            print(os.getpid(), file=f)

        # Arrange to have the PID file removed on exit/signal
        atexit.register(lambda: os.remove(pidfile))

    # Signal handler for termination (required)
    def sigterm_handler(signo, frame):
        LOG.debug("SIGTERM received, exiting")
        sys.exit(1)

    signal.signal(signal.SIGTERM, sigterm_handler)

    target(*args, **kwargs)


class AgentMultiplexerRequestHandler(BaseAgentRequestHandler):
    """
    Handle a single SSH agent session
    """

    def setup(self):
        self._identity_map = {}
        self._keys_cache = {}  # Cache key info for sign requests
        # self.fetch_peer_info()
        # Deny connections from other users
        # if self.peer_uid != os.getuid():
        #    raise RuntimeError("Connection from uid {} denied.".format(
        #                       self.peer_uid))

    def handle(self):
        """
        Handle a single SSH agent session
        """
        for request in self._each_msg():
            r_len, r_type = struct.unpack_from('> I B', request)
            LOG.debug(msg="request: type:{} len:{}".format(r_type, r_len))
            if r_type == self.SSH2_AGENTC_REQUEST_IDENTITIES:
                LOG.debug(msg="SSH2_AGENTC_REQUEST_IDENTITIES")
                response = self._merge_identities(request)
            elif r_type == self.SSH2_AGENTC_EXTENSION:
                LOG.debug(msg="SSH2_AGENTC_EXTENSION")
                response = self._handle_extension(request)
            elif r_type == self.SSH2_AGENTC_SIGN_REQUEST:
                LOG.debug(msg="SSH2_AGENTC_SIGN_REQUEST")
                
                # Parse the sign request according to SSH agent protocol
                # Format: byte(type) + string(key_blob) + string(data) + uint32(flags)
                try:
                    offset = 5  # Skip message length and type
                    
                    # Extract key blob
                    key_blob_len = struct.unpack_from('> I', request, offset)[0]
                    offset += 4
                    key_blob = request[offset:offset + key_blob_len]
                    offset += key_blob_len
                    
                    # Extract data to be signed
                    data_len = struct.unpack_from('> I', request, offset)[0]
                    offset += 4
                    data = request[offset:offset + data_len]
                    offset += data_len
                    
                    # Extract flags if present
                    flags = 0
                    if offset + 4 <= len(request):
                        flags = struct.unpack_from('> I', request, offset)[0]
                    
                    # Get key information from cache or analyze now
                    hex_blob = ''.join('{:02x}'.format(b) for b in key_blob)
                    key_info = self._keys_cache.get(hex_blob)
                    if not key_info:
                        try:
                            key_info = self._extract_key_info(key_blob)
                        except:
                            # Fallback to simple extraction
                            key_info = self._extract_key_info_simple(key_blob)
                    
                    # Determine which agent to use
                    agent = self._identity_map.get(hex_blob)
                    if agent is None:
                        LOG.error("SSH_AGENT_ERROR: %s", json.dumps({
                            "operation": "sign_request_error",
                            "error": "key_not_found",
                            "sha256_fingerprint": key_info.get("sha256_fingerprint", ""),
                            "key_type": key_info.get("key_type", "unknown")
                        }, separators=(',', ':')))
                        # Return failure response
                        response = UpstreamSocketThread.SSH_AGENT_FAILURE
                    else:
                        agent_name = "default" if agent == self.server.default_agent else "alternate"
                        
                        # Log detailed sign request information
                        log_data = {
                            "operation": "sign_request",
                            "agent": agent_name,
                            "key_type": key_info.get("key_type", "unknown"),
                            "key_size": key_info.get("key_size", 0),
                            "sha256_fingerprint": key_info.get("sha256_fingerprint", ""),
                            "data_length": data_len,
                            "flags": flags,
                            "username": key_info.get("username"),
                            "hostname": key_info.get("hostname")
                        }
                        
                        # Add curve info for ECDSA keys
                        if "curve" in key_info:
                            log_data["curve"] = key_info["curve"]
                        
                        # Add flag interpretation
                        flag_info = []
                        if flags & 0x01:  # SSH_AGENT_RSA_SHA2_256
                            flag_info.append("RSA_SHA2_256")
                        if flags & 0x02:  # SSH_AGENT_RSA_SHA2_512
                            flag_info.append("RSA_SHA2_512")
                        if flag_info:
                            log_data["flag_names"] = flag_info
                        
                        # Create human-readable log message with better key identification
                        key_desc = f"{key_info.get('key_type', 'unknown')}"
                        if key_info.get('key_size', 0) > 0:
                            key_desc += f" {key_info['key_size']}-bit"
                        
                        # Get user info from comment 
                        user_info = ""
                        if key_info.get("comment"):
                            comment = key_info["comment"]
                            # Clean up comment if it's in bytearray format
                            if isinstance(comment, str) and comment.startswith('bytearray(b\'') and comment.endswith('\')'):
                                comment = comment[12:-2]  # Remove bytearray(b' and ')
                            user_info = f" ({comment})"
                        elif key_info.get("username") and key_info.get("hostname"):
                            user_info = f" ({key_info['username']}@{key_info['hostname']})"
                        
                        LOG.info("Sign: %s key from %s agent%s", 
                                key_desc, agent_name, user_info)
                        
                        # Forward request to appropriate agent
                        response = agent.forward_request(request)
                        
                        # Log response info
                        if response and len(response) > 4:
                            response_type = struct.unpack_from('> B', response, 4)[0]
                            success = response_type != 5  # SSH_AGENT_FAILURE = 5
                            
                            if not success:
                                LOG.warning("SSH sign failed for %s key from %s agent", 
                                           key_info.get("key_type", "unknown"), agent_name)
                        
                except Exception as e:
                    LOG.error("SSH_AGENT_ERROR: %s", json.dumps({
                        "operation": "sign_request_parse_error",
                        "error": str(e),
                        "request_length": len(request)
                    }, separators=(',', ':')))
                    response = UpstreamSocketThread.SSH_AGENT_FAILURE
            else:
                LOG.debug(msg="Unknown request type: {}".format(r_type))

            self.request.sendall(response)

    def _merge_identities(self, request):
        """
        Gather identities from all upstream agents and merge into a single
        response, keep track of where we found each identity
        """
        LOG.debug("DEBUG: _merge_identities called")
        
        # On first request, do startup key discovery using this handler
        if not self.server.startup_keys_discovered:
            self.server.startup_keys_discovered = True
            self._discover_startup_keys()
        
        identities = []
        agent_counts = {}
        
        for agent in self.server.agents():
            response = agent.forward_request(request)
            agent_name = "default" if agent == self.server.default_agent else "alternate"
            agent_identities = []
            
            LOG.debug("DEBUG: Processing agent %s", agent_name)
            
            identities_list = list(self._parse_identities(response))
            LOG.debug("DEBUG: Found %d identities from %s agent", len(identities_list), agent_name)

            for key_blob, key_comment in identities_list:
                try:
                    # Use simple key information extraction
                    key_info = self._extract_key_info_simple(key_blob, key_comment)
                    
                    # Record where each identity came from
                    try:
                        hex_blob = ''.join('{:02x}'.format(b) for b in key_blob)
                    except Exception as e:
                        LOG.debug("DEBUG: hex_blob creation failed: %s", str(e))
                        # Fallback if hex conversion fails
                        hex_blob = str(hash(str(key_blob)))[:16]
                    if hex_blob in self._identity_map and \
                            self._identity_map[hex_blob] != agent:
                        LOG.error("Identity collision: %s found in both %s and %s agents", 
                                  key_info.get('sha256_fingerprint', 'unknown'), agent_name, 
                                  "default" if self._identity_map[hex_blob] == self.server.default_agent else "alternate")

                    self._identity_map[hex_blob] = agent
                    
                    # Store key info for later use in sign requests
                    self._keys_cache[hex_blob] = key_info
                    
                    # Log individual key discovery (only once per server session, skip if already logged on startup)
                    key_fingerprint = hex_blob[:16]  # Use hex blob as fingerprint
                    if key_fingerprint not in self.server.logged_keys and "startup_logged" not in self.server.logged_keys:
                        self.server.logged_keys.add(key_fingerprint)
                        
                        key_desc = f"{key_info.get('key_type', 'unknown')}"
                        
                        user_info = ""
                        if key_info.get("comment"):
                            user_info = f"({key_info['comment']})"
                        
                        LOG.debug("DEBUG: About to log key discovery")
                        LOG.info("Found %s key in %s agent %s", key_desc, agent_name, user_info)
                        LOG.debug("DEBUG: Logged key discovery")
                    
                    agent_identities.append(key_info)
                    
                except Exception as e:
                    # If key analysis fails, fall back to basic logging
                    LOG.debug("Key analysis failed for identity: %s", str(e))
                    
                    # Ensure key_blob is bytes for hex conversion
                    if isinstance(key_blob, str):
                        blob_bytes = key_blob.encode('latin1')
                    else:
                        blob_bytes = key_blob
                    hex_blob = ''.join('{:02x}'.format(b) for b in blob_bytes)
                    self._identity_map[hex_blob] = agent
                    
                    # Try to at least get the key type from the blob
                    try:
                        if len(key_blob) >= 4:
                            key_type_len = struct.unpack('>I', key_blob[0:4])[0]
                            if len(key_blob) >= 4 + key_type_len:
                                key_type = key_blob[4:4+key_type_len].decode('ascii')
                                
                                # Try to get comment info too
                                comment_str = ""
                                if key_comment:
                                    try:
                                        if isinstance(key_comment, (bytes, bytearray)):
                                            comment_str = key_comment.decode('utf-8')
                                        else:
                                            comment_str = str(key_comment)
                                    except:
                                        comment_str = ""
                                
                                # Log the fallback discovery (only once per key, skip if already logged on startup)
                                key_id = f"{agent_name}_{key_type}_{blob_bytes[:4].hex()}"
                                if key_id not in self.server.logged_keys and "startup_logged" not in self.server.logged_keys:
                                    self.server.logged_keys.add(key_id)
                                    # Clean up comment display
                                    if comment_str:
                                        # Extract user@host from comment if possible
                                        if '@' in comment_str and not comment_str.startswith('bytearray'):
                                            user_info = f" ({comment_str})"
                                        elif comment_str.startswith('bytearray(b\'') and comment_str.endswith('\')'):
                                            # Parse bytearray format
                                            clean_comment = comment_str[12:-2]  # Remove bytearray(b' and ')
                                            user_info = f" ({clean_comment})"
                                        else:
                                            user_info = f" ({comment_str})"
                                    else:
                                        user_info = ""
                                    LOG.info("Found %s key in %s agent %s", 
                                            key_type, agent_name, user_info)
                                
                                # Store fallback key info for later use
                                fallback_key_info = {
                                    "key_type": key_type,
                                    "key_size": 0,
                                    "comment": comment_str
                                }
                                self._keys_cache[hex_blob] = fallback_key_info
                                agent_identities.append({"key_type": key_type})
                            else:
                                key_id = f"{agent_name}_unknown_{hex_blob[:8]}"
                                if key_id not in self.server.logged_keys and "startup_logged" not in self.server.logged_keys:
                                    self.server.logged_keys.add(key_id)
                                    LOG.info("Found unknown key in %s agent (truncated blob)", agent_name)
                                agent_identities.append({"key_type": "unknown"})
                        else:
                            key_id = f"{agent_name}_unknown_{hex_blob[:8]}"
                            if key_id not in self.server.logged_keys and "startup_logged" not in self.server.logged_keys:
                                self.server.logged_keys.add(key_id)
                                LOG.info("Found unknown key in %s agent (short blob)", agent_name)
                            agent_identities.append({"key_type": "unknown"})
                    except Exception as e2:
                        key_id = f"{agent_name}_unknown_{hex_blob[:8]}"
                        if key_id not in self.server.logged_keys and "startup_logged" not in self.server.logged_keys:
                            self.server.logged_keys.add(key_id)
                            LOG.info("Found unknown key in %s agent (parse error: %s)", agent_name, str(e2))
                        agent_identities.append({"key_type": "unknown"})
                
                # Always add the identity regardless of analysis success
                identity = (key_blob, key_comment)
                identities.append(identity)

            agent_counts[agent_name] = len(agent_identities)
            
            # Summary logging removed for cleaner output

        # Log summary only on first call or when counts change
        default_count = agent_counts.get("default", 0)
        alternate_count = agent_counts.get("alternate", 0)
        total_count = len(identities)
        
        summary_key = (total_count, default_count, alternate_count)
        if self.server.last_summary != summary_key:
            self.server.last_summary = summary_key
            LOG.info("Agent: %d identities available (%d local, %d remote)", 
                     total_count, default_count, alternate_count)

        return self._build_identities_answer(identities)

    def _handle_extension(self, request):
        return self.server.default_agent.forward_request(request)
    
    def _discover_startup_keys(self):
        """
        Discover and log all available keys on startup
        """
        try:
            # Create a REQUEST_IDENTITIES message to query agents
            request_identities_msg = bytearray(struct.pack('> I B', 1, 11))  # SSH2_AGENTC_REQUEST_IDENTITIES = 11
            
            total_keys = 0
            agent_counts = {}
            
            for agent in self.server.agents():
                agent_name = "default" if agent == self.server.default_agent else "alternate"
                agent_keys = 0
                
                # Try to query the agent
                try:
                    response = agent.forward_request(request_identities_msg)
                    
                    # Parse identities using the existing method
                    identities_list = list(self._parse_identities(response))
                    
                    for key_blob, key_comment in identities_list:
                        try:
                            # Use simple key information extraction
                            key_info = self._extract_key_info_simple(key_blob, key_comment)
                            
                            key_desc = f"{key_info.get('key_type', 'unknown')}"
                            
                            user_info = ""
                            if key_info.get("comment"):
                                user_info = f" ({key_info['comment']})"
                            
                            LOG.info("Found %s key in %s agent%s", key_desc, agent_name, user_info)
                            agent_keys += 1
                            total_keys += 1
                            
                        except Exception as e:
                            LOG.debug("Failed to analyze key on startup: %s", str(e))
                            LOG.info("Found unknown key in %s agent", agent_name)
                            agent_keys += 1
                            total_keys += 1
                    
                    agent_counts[agent_name] = agent_keys
                    
                except Exception as e:
                    LOG.debug("Failed to query %s agent on startup: %s", agent_name, str(e))
                    agent_counts[agent_name] = 0
            
            # Only log summary if we found keys
            if total_keys > 0:
                # Log summary
                default_count = agent_counts.get("default", 0)
                alternate_count = agent_counts.get("alternate", 0)
                LOG.info("Agent: %d identities available (%d local, %d remote)", 
                         total_keys, default_count, alternate_count)
                
                # Mark all keys as logged so they don't appear again in first request
                self.server.logged_keys.add("startup_logged")
                self.server.last_summary = (total_keys, default_count, alternate_count)
            
        except Exception as e:
            LOG.debug("Startup key discovery failed: %s", str(e))

class AgentMultiplexer(socketserver.ThreadingUnixStreamServer):
    timeout = 3

    def __init__(self, listening_sock, default_agent_sock,
                 alternate_agent_sock):
        # XXX BaseServer is an old style class, so we need to explicitly call
        # our parents initializer
        socketserver.ThreadingUnixStreamServer.__init__(
            self, listening_sock, AgentMultiplexerRequestHandler)

        self.default_agent = UpstreamSocketThread(default_agent_sock)
        self.default_agent.start()
        self.alternate_agent = UpstreamSocketThread(alternate_agent_sock)
        self.alternate_agent.start()
        
        # Server-wide state to track logged keys across all requests
        self.logged_keys = set()
        self.last_summary = None
        
        # Server-wide state will be initialized, startup key discovery will be done on first request
        self.startup_keys_discovered = False

    def agents(self):
        yield self.default_agent
        yield self.alternate_agent


def start_agent_mux(ready_pipeout, parent_pid, upstream_socket,
                    alternative_socket):
    # generate unique socket path
    if sys.platform == "win32":
        # On Windows, use a named pipe or TCP socket
        # For now, use a named pipe path format
        pipe_name = f"ssh_auth_{os.getpid()}"
        sock_path = f"\\\\.\\pipe\\{pipe_name}"
        # Note: Full Windows named pipe server support would require
        # implementing a custom server class. For now, this is a placeholder.
        # The multiplexer will work for connecting to Windows named pipes,
        # but creating a listening server on Windows needs additional work.
        LOG.warning("Windows named pipe server creation not fully implemented")
        LOG.warning("Multiplexer can connect to Windows named pipes but cannot create a server")
        # Fallback: use TCP localhost socket on Windows
        import socket as sock_module
        tcp_socket = sock_module.socket(sock_module.AF_INET, sock_module.SOCK_STREAM)
        tcp_socket.bind(('127.0.0.1', 0))
        tcp_socket.listen(1)
        sock_path = f"tcp://127.0.0.1:{tcp_socket.getsockname()[1]}"
        LOG.info("Using TCP socket on Windows: %s", sock_path)
    else:
        sock_dir = tempfile.mkdtemp()
        sock_path = sock_dir + '/ssh_auth.sock'

    # pass all sockets to AgentMultiplexer
    # Note: On Windows, AgentMultiplexer uses UnixStreamServer which won't work
    # This needs a Windows-compatible server implementation
    if sys.platform == "win32":
        LOG.error("Windows server support not fully implemented")
        LOG.error("The multiplexer server requires Unix sockets or a Windows named pipe server implementation")
        raise NotImplementedError("Windows server support requires additional implementation")
    
    server = AgentMultiplexer(sock_path, upstream_socket, alternative_socket)

    # Let parent know the socket is ready
    ready_pipeout.send(sock_path)
    ready_pipeout.close()

    # Startup key discovery will be done on first request when agents are ready

    while check_pid(parent_pid):
        server.handle_request()

    if sys.platform != "win32":
        os.unlink(sock_path)
        os.rmdir(sock_dir)


def check_pid(pid):
    try:
        os.kill(pid, 0)
    except OSError:
        return False
    else:
        return True


def same_socket(sock1, sock2):
    return os.path.realpath(sock1) != os.path.realpath(sock2)


def socket_working(sock):
    """
    Check if a socket (Unix socket or Windows named pipe) is working.
    """
    if not sock:
        return False
    
    # Windows named pipe check
    if sys.platform == "win32" and (sock.startswith("\\\\.\\pipe\\") or sock.startswith("\\\\")):
        if HAS_WIN32:
            try:
                pipe_name = sock
                if pipe_name.startswith("\\\\.\\pipe\\"):
                    pipe_name = pipe_name[9:]
                handle = win32file.CreateFile(
                    f"\\\\.\\pipe\\{pipe_name}",
                    win32file.GENERIC_READ | win32file.GENERIC_WRITE,
                    0,
                    None,
                    win32file.OPEN_EXISTING,
                    0,
                    None
                )
                win32file.CloseHandle(handle)
                return True
            except Exception:
                return False
        else:
            # Without pywin32, we can't properly check Windows named pipes
            # Return True optimistically (caller should handle errors)
            return True
    
    # Unix socket check - use original logic for compatibility
    try:
        r = os.path.realpath(sock)
        p = pathlib.Path(r)
        if p.is_socket():
            return True
        else:
            LOG.error("%s no Socket", r)
            return False
    except Exception:
        return False
    r = os.path.realpath(sock)

    p = pathlib.Path(r)

    if p.is_socket():
        return True
    else:
        LOG.error("%s no Socket", r)
        return False


def main():
    # fetch alternate socket path from command line
    parser = argparse.ArgumentParser()
    parser.add_argument('--foreground', '-f', action='store_true',
                        help="Start in foreground")
    parser.add_argument('--debug', '-d', action='store_true',
                        help="Enable debug logging")
    parser.add_argument('--socket', required=True,
                        help='alternative SSH agent socket')
    parser.add_argument('--envname', default="",
                        help='prefix of the ENV variable on stdout')

    args, extra_args = parser.parse_known_args()

    if extra_args and extra_args[0] == '--':
        extra_args = extra_args[1:]

    level = logging.INFO
    if args.debug:
        level = logging.DEBUG
    setup_logging("sshagentmux", level)

    LOG.debug("Starting sshagentmux")

    # use specified socket if SSH_AUTH_SOCK is not present in environment
    sock_path = args.socket

    if socket_working(os.environ['SSH_AUTH_SOCK']):
        if socket_working(args.socket):
            # Both Sockets are working
            LOG.debug("Sockets: %s and %s",
                      os.environ['SSH_AUTH_SOCK'], args.socket)
            upstream_socket = os.environ['SSH_AUTH_SOCK']
            # Save original parent pid so we can detect when it exits
            parent_pid = os.getppid()
            if extra_args:
                parent_pid = os.getpid()
            # Start proxy process and wait for it to creating auth socket
            # Using a pipe for compatibility with OpenBSD
            ready_pipein, ready_pipeout = multiprocessing.Pipe()
            daemonize(target=start_agent_mux,
                      # stderr=os.path.expanduser('~/.sshagentmux.log'),
                      # pidfile="/tmp/sshagentmux.pid",
                      envname=args.envname,
                      args=(ready_pipeout, parent_pid, upstream_socket,
                            args.socket)
                      )
            # Wait for server to setup listening socket
            sock_path = ready_pipein.recv()
            ready_pipein.close()
            ready_pipeout.close()
            if not os.path.exists(sock_path):
                LOG.info('Agent Multiplexer failed to create auth socket')
                sys.exit(1)
        else:
            # Only SSH_AUTH_SOCK is working
            LOG.debug("Just using SSH_AUTH_SOCK")
            sock_path = os.environ['SSH_AUTH_SOCK']

    else:
        # SSH_AUTHSOCK is not working
        LOG.debug("Just using %s", args.socket)
        sock_path = args.socket

    # Behave like ssh-agent(1)
    if extra_args:
        # start command if specified in extra_args
        os.environ['SSH_AUTH_SOCK'] = sock_path
        os.execvp(extra_args[0], extra_args)
        os.kill(mypid, signal.SIGKILL)
    else:
        # print how to setup environment (same behavior as ssh-agent)
        print('{:s}SSH_AUTH_SOCK={:s};export {:s}SSH_AUTH_SOCK;'
              '{:s}SSH_AGENT_PID={:d};export {:s}SSH_AGENT_PID;'
              .format(
                    args.envname, sock_path, args.envname,
                    args.envname, mypid, args.envname
                ))
    if args.foreground:
        LOG.debug("Waiting for parent to exit")
        try:
            while check_pid(mypid):
                time.sleep(1)
        except KeyboardInterrupt:
            LOG.debug("Parent interrupted")
            os.kill(mypid, signal.SIGKILL)
        LOG.debug("Parent exited")
    LOG.debug("Main exited")

if __name__ == '__main__':
    main()
