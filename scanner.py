#!/usr/bin/env python3
import argparse
import json
import socket
import sys
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime

COMMON_SERVICES = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns", 80: "http",
    110: "pop3", 139: "netbios", 143: "imap", 443: "https", 445: "smb",
    3306: "mysql", 3389: "rdp", 5432: "postgresql", 8080: "http-alt",
}
HTTP_PORTS = {80, 8000, 8008, 8080}


def parse_ports(spec):
    """Turn '22,80,1-100' into a sorted list of ports."""
    ports = set()
    for part in spec.split(","):
        if "-" in part:
            lo, hi = part.split("-")
            ports.update(range(int(lo), int(hi) + 1))
        else:
            ports.add(int(part))
    return sorted(p for p in ports if 1 <= p <= 65535)


def grab_banner(sock, port):
    """Read whatever the service says first (HTTP needs a request first)."""
    try:
        if port in HTTP_PORTS:
            sock.sendall(b"HEAD / HTTP/1.0\r\n\r\n")
        data = sock.recv(1024).decode(errors="ignore").strip()
        return data.replace("\r", " ").replace("\n", " | ")[:200]
    except OSError:
        return ""


def scan_port(target, port, timeout):
    """TCP connect scan: if the handshake completes, the port is open."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            if s.connect_ex((target, port)) != 0:
                return None
            return {
                "port": port,
                "service": COMMON_SERVICES.get(port, "unknown"),
                "banner": grab_banner(s, port),
            }
    except OSError:
        return None


def check_vulns(result, db):
    """Compare the banner and port against the local database."""
    findings = []
    banner = result["banner"].lower()
    for sig in db["banner_signatures"]:
        if sig["match"].lower() in banner:
            findings.append(sig)
    note = db["risky_ports"].get(str(result["port"]))
    if note:
        findings.append({"cve": "N/A", "severity": "Warning", "description": note})
    return findings


def main():
    p = argparse.ArgumentParser(description="Port scanner with vulnerability lookup")
    p.add_argument("target", help="IP address or hostname to scan")
    p.add_argument("-p", "--ports", default="1-1024", help="e.g. 22,80 or 1-65535")
    p.add_argument("-t", "--timeout", type=float, default=1.0)
    p.add_argument("-w", "--workers", type=int, default=100, help="parallel threads")
    p.add_argument("--db", default="vulns.json")
    p.add_argument("-o", "--out", help="save results to a JSON file")
    args = p.parse_args()

    try:
        ip = socket.gethostbyname(args.target)
    except socket.gaierror:
        sys.exit(f"Cannot resolve {args.target}")

    with open(args.db) as f:
        db = json.load(f)

    ports = parse_ports(args.ports)
    print(f"Scanning {ip} ({len(ports)} ports) at {datetime.now():%H:%M:%S}")

    with ThreadPoolExecutor(max_workers=args.workers) as pool:
        results = [r for r in pool.map(lambda pt: scan_port(ip, pt, args.timeout), ports) if r]

    total = 0
    for r in results:
        r["findings"] = check_vulns(r, db)
        total += len(r["findings"])
        print(f"\n[OPEN] {r['port']}/tcp  {r['service']}")
        if r["banner"]:
            print(f"   banner: {r['banner']}")
        for f in r["findings"]:
            print(f"   [!] {f['severity']}: {f['cve']} - {f['description']}")

    print(f"\nDone: {len(results)} open ports, {total} findings")

    if args.out:
        with open(args.out, "w") as f:
            json.dump({"target": ip, "results": results}, f, indent=2)
        print(f"Saved report to {args.out}")


if __name__ == "__main__":
    main()

