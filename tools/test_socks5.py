#!/usr/bin/env python3
"""Test SOCKS5 proxy with authentication."""

import socket
import struct
import sys

def socks5_connect(proxy_host, proxy_port, user, password, dest_host, dest_port, use_ipv4=False):
    """Connect through SOCKS5 proxy with user/pass auth."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(10.0)  # timeout de 10 segundos
    sock.connect((proxy_host, proxy_port))
    
    # 1. HELLO (método 0x02 = username/password)
    sock.sendall(b'\x05\x01\x02')
    resp = sock.recv(2)
    if resp[0] != 0x05 or resp[1] != 0x02:
        print(f"SOCKS5 HELLO failed: {resp.hex()}")
        return None
    print("[OK] SOCKS5 HELLO: auth method username/password")
    
    # 2. AUTH (RFC 1929)
    auth_req = struct.pack('B', 1)  # version
    auth_req += struct.pack('B', len(user)) + user.encode()
    auth_req += struct.pack('B', len(password)) + password.encode()
    sock.sendall(auth_req)
    
    auth_resp = sock.recv(2)
    if len(auth_resp) != 2 or auth_resp[0] != 1 or auth_resp[1] != 0:
        print(f"[FAIL] Auth failed: {auth_resp.hex()}")
        sock.close()
        return None
    print(f"[OK] Auth successful for user '{user}'")
    
    # 3. CONNECT request
    req = b'\x05\x01\x00'  # VER, CMD=CONNECT, RSV
    
    if use_ipv4:
        # ATYP=IPv4 (0x01)
        req += b'\x01'
        # Convertir IP string a bytes
        ip_parts = [int(p) for p in dest_host.split('.')]
        req += bytes(ip_parts)
    else:
        # ATYP=domain (0x03)
        req += b'\x03'
        req += struct.pack('B', len(dest_host)) + dest_host.encode()
    
    req += struct.pack('!H', dest_port)
    sock.sendall(req)
    
    # 4. CONNECT response
    resp = sock.recv(10)
    if len(resp) < 10 or resp[1] != 0:
        print(f"[FAIL] CONNECT failed: {resp.hex()}")
        sock.close()
        return None
    print(f"[OK] Connected to {dest_host}:{dest_port}")
    
    return sock

if __name__ == '__main__':
    if len(sys.argv) < 3:
        print(f"Usage: {sys.argv[0]} <username> <password>")
        print(f"Example: {sys.argv[0]} rocky julii")
        sys.exit(1)
    
    user = sys.argv[1]
    password = sys.argv[2]
    
    # Test 1: conectar a 93.184.216.34 (example.com IP) puerto 80
    print("\n=== Test 1: Connecting via IPv4 address (ATYP=0x01) ===")
    sock = socks5_connect('localhost', 1080, user, password, '93.184.216.34', 80, use_ipv4=True)
    if sock:
        print("[Sending HTTP request...]")
        sock.sendall(b'GET / HTTP/1.0\r\nHost: example.org\r\n\r\n')
        print("[Waiting for response...]")
        try:
            response = sock.recv(4096)
            if response:
                print("\n--- HTTP Response ---")
                print(response.decode('utf-8', errors='replace')[:300])
                print("\n[SUCCESS] IP connection working!")
            else:
                print("\n[FAIL] Empty response from server")
        except socket.timeout:
            print("\n[FAIL] Timeout waiting for response - COPY state not working?")
        sock.close()
    else:
        print("\n[FAIL] Could not connect via IP")
    
    # Test 2: conectar con dominio
    print("\n=== Test 2: Connecting via domain name ===")
    sock = socks5_connect('localhost', 1080, user, password, 'example.org', 80)
    if sock:
        # Enviar HTTP GET
        sock.sendall(b'GET / HTTP/1.0\r\nHost: example.org\r\n\r\n')
        response = sock.recv(4096)
        print("\n--- HTTP Response ---")
        print(response.decode('utf-8', errors='replace')[:300])
        sock.close()
        print("\n[SUCCESS] SOCKS5 proxy working with domain!")
    else:
        print("\n[FAIL] Could not connect through proxy with domain")
