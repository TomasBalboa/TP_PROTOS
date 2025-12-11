#!/usr/bin/env python3 (ya se puede probar directamente desde client)
"""
- Auth (RFC 1929): [VER=0x01][ULEN][USERNAME][PLEN][PASSWORD]
- Command: [VER=0x01][CMD][LEN][PAYLOAD] where PAYLOAD is ASCII args
           separated by ':' (same as server parser expects).
The server closes the connection after responding to one command.

Vamos a hacer un cliente de management simple que haga auth + un comando.
"""

import argparse
import socket
import sys
from typing import Iterable

MGMT_VERSION = 0x01

COMMAND_CODES = {
    "add_user": 0,
    "delete_user": 1,
    "list_users": 2,
    "stats": 3,
}

STATUS_TEXT = {
    0: "OK",
    1: "FORBIDDEN",
    2: "INVALID_VERSION",
    3: "INVALID_COMMAND",
    4: "INVALID_ARGS",
    5: "INVALID_LENGTH",
    6: "SERVER_ERROR",
}


def build_auth_frame(user: str, password: str) -> bytes:
    user_b = user.encode("utf-8")
    pass_b = password.encode("utf-8")
    if len(user_b) > 0xFF or len(pass_b) > 0xFF:
        raise ValueError("username/password too long (max 255 bytes)")
    return bytes([MGMT_VERSION, len(user_b)]) + user_b + bytes([len(pass_b)]) + pass_b


def build_command_frame(cmd: str, args: Iterable[str]) -> bytes:
    if cmd not in COMMAND_CODES:
        raise ValueError(f"unknown command: {cmd}")
    payload_str = ":".join(args)
    payload = payload_str.encode("utf-8")
    if len(payload) > 0xFF:
        raise ValueError("payload too long (max 255 bytes)")
    return bytes([MGMT_VERSION, COMMAND_CODES[cmd], len(payload)]) + payload


def recv_exact(sock: socket.socket, n: int) -> bytes:
    chunks = []
    remaining = n
    while remaining > 0:
        chunk = sock.recv(remaining)
        if not chunk:
            break
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def recv_until_close(sock: socket.socket, bufsize: int = 4096) -> bytes:
    chunks = []
    while True:
        try:
            chunk = sock.recv(bufsize)
        except socket.timeout:
            break
        if not chunk:
            break
        chunks.append(chunk)
    return b"".join(chunks)


def main() -> int:
    parser = argparse.ArgumentParser(description="Management client (auth + single command)")
    parser.add_argument("command", choices=COMMAND_CODES.keys(), help="command to execute")
    parser.add_argument("args", nargs="*", help="command arguments")
    parser.add_argument("--host", default="127.0.0.1", help="management host")
    parser.add_argument("--port", type=int, default=8080, help="management port")
    parser.add_argument("--user", default="admin", help="username")
    parser.add_argument("--password", default="0000", help="password (por defecto 0000 como en el server)")
    parser.add_argument("--timeout", type=float, default=3.0, help="socket timeout seconds")

    ns = parser.parse_args()

    auth_frame = build_auth_frame(ns.user, ns.password)
    cmd_frame = build_command_frame(ns.command, ns.args)

    with socket.create_connection((ns.host, ns.port), timeout=ns.timeout) as sock:
        sock.settimeout(ns.timeout)
        sock.sendall(auth_frame)
        auth_resp = recv_exact(sock, 2)
        if len(auth_resp) != 2:
            print("[auth] short response", file=sys.stderr)
            return 1
        ver, status = auth_resp[0], auth_resp[1]
        if ver != MGMT_VERSION:
            print(f"[auth] bad version {ver:#02x}", file=sys.stderr)
            return 1
        if status != 0:
            print(f"[auth] failed: status={status} ({STATUS_TEXT.get(status, 'UNKNOWN')})")
            return 1
        print("[auth] ok")

        sock.sendall(cmd_frame)
        resp = recv_until_close(sock)

    if len(resp) < 2:
        print("[cmd] no response", file=sys.stderr)
        return 1

    ver, status = resp[0], resp[1]
    body = resp[2:]
    status_msg = STATUS_TEXT.get(status, "UNKNOWN")
    print(f"[cmd] version={ver:#02x} status={status} ({status_msg})")
    if body:
        try:
            print(body.decode("utf-8", errors="replace"))
        except Exception:
            print(body)
    return 0 if status == 0 else 1


if __name__ == "__main__":
    sys.exit(main())