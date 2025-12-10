#!/usr/bin/env python3
"""Test SOCKS5 authentication behavior."""

import socket
import struct
import sys

def test_socks5_auth(proxy_host, proxy_port, user=None, password=None):
    """Test SOCKS5 with optional authentication."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(5.0)
    sock.connect((proxy_host, proxy_port))
    
    # 1. HELLO - ofrecer ambos métodos (NO_AUTH y USER_PASS)
    if user and password:
        # Ofrecer solo USER_PASS
        sock.sendall(b'\x05\x01\x02')
        print(f"[→] HELLO: offering USER_PASS only")
    else:
        # Ofrecer solo NO_AUTH
        sock.sendall(b'\x05\x01\x00')
        print(f"[→] HELLO: offering NO_AUTH only")
    
    resp = sock.recv(2)
    print(f"[←] HELLO response: {resp.hex()}")
    
    if resp[0] != 0x05:
        print(f"[✗] Invalid SOCKS version: {resp[0]}")
        sock.close()
        return False
        
    selected_method = resp[1]
    
    if selected_method == 0x00:  # NO_AUTH
        print(f"[✓] Server selected: NO_AUTH")
        if user:
            print(f"[!] WARNING: Server accepted NO_AUTH even though we offered USER_PASS!")
    elif selected_method == 0x02:  # USER_PASS
        print(f"[✓] Server selected: USER_PASS")
        
        # 2. Send authentication
        auth_req = struct.pack('B', 1)  # version
        auth_req += struct.pack('B', len(user)) + user.encode()
        auth_req += struct.pack('B', len(password)) + password.encode()
        sock.sendall(auth_req)
        print(f"[→] AUTH: user='{user}' pass='{password}'")
        
        auth_resp = sock.recv(2)
        print(f"[←] AUTH response: {auth_resp.hex()}")
        
        if auth_resp[0] != 1 or auth_resp[1] != 0:
            print(f"[✗] Auth FAILED (status={auth_resp[1]})")
            sock.close()
            return False
        else:
            print(f"[✓] Auth SUCCESS")
    else:
        print(f"[✗] Server responded with method {selected_method:#x}")
        sock.close()
        return False
    
    # 3. Try to connect somewhere
    req = b'\x05\x01\x00\x03'  # VER, CMD=CONNECT, RSV, ATYP=domain
    req += struct.pack('B', len('example.org')) + b'example.org'
    req += struct.pack('!H', 80)
    sock.sendall(req)
    print(f"[→] CONNECT to example.org:80")
    
    resp = sock.recv(10)
    print(f"[←] CONNECT response: {resp.hex()}")
    
    if len(resp) >= 2 and resp[1] == 0:
        print(f"[✓] Connection SUCCESS")
        sock.close()
        return True
    else:
        print(f"[✗] Connection FAILED (reply={resp[1]})")
        sock.close()
        return False

if __name__ == '__main__':
    # Parse command line arguments
    if len(sys.argv) >= 5:
        host = sys.argv[1]
        port = int(sys.argv[2])
        user = sys.argv[3]
        password = sys.argv[4]
    else:
        # Default values
        host = 'localhost'
        port = 1080
        user = 'rocky'
        password = 'julii'
    
    print(f"\nTesting with: {host}:{port}, user={user}, pass={password}")
    
    print("\n=== Test 1: NO credentials (NO_AUTH) ===")
    test_socks5_auth(host, port)
    
    print(f"\n=== Test 2: Valid credentials ({user}:{password}) ===")
    test_socks5_auth(host, port, user, password)
    
    print(f"\n=== Test 3: Invalid credentials ({user}:WRONG_PASSWORD) ===")
    test_socks5_auth(host, port, user, 'WRONG_PASSWORD')
