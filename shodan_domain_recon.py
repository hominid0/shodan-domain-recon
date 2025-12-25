#!/usr/bin/env python3
"""
Shodan Domain Recon
Passive OSINT domain reconnaissance using the Shodan API.

Author: Miguel Jiménez Cámara
Use case: Bug bounty & responsible disclosure
"""

import shodan
import os
import sys
import socket
from datetime import datetime

RESULTS_DIR = "results"


def banner():
    print("""
========================================================
 Shodan Domain Recon
 Passive OSINT | Bug Bounty Oriented
========================================================
""")


def save(line, f):
    print(line)
    f.write(line + "\n")


def resolve(hostname):
    try:
        return socket.gethostbyname(hostname)
    except:
        return None


def main(domain):
    api_key = os.getenv("SHODAN_API_KEY")
    if not api_key:
        print("[!] SHODAN_API_KEY not found in environment variables")
        sys.exit(1)

    api = shodan.Shodan(api_key)
    os.makedirs(RESULTS_DIR, exist_ok=True)

    output_file = os.path.join(RESULTS_DIR, f"{domain}.txt")

    with open(output_file, "w", encoding="utf-8") as f:
        save(f"[+] Target domain: {domain}", f)
        save(f"[+] Timestamp: {datetime.utcnow()} UTC", f)
        save("=" * 80, f)

        # 1. DNS passive enumeration
        save("\n[1] DNS Passive Enumeration (Shodan)", f)
        save("-" * 80, f)

        try:
            dns_info = api.dns.domain_info(domain)
            subdomains = dns_info.get("subdomains", [])
        except Exception as e:
            save(f"[!] DNS error: {e}", f)
            subdomains = []

        full_subdomains = [f"{s}.{domain}" for s in subdomains]
        save(f"[+] Subdomains found: {len(full_subdomains)}", f)

        for sub in full_subdomains:
            save(f"  - {sub}", f)

        # 2. Resolve subdomains
        save("\n[2] DNS Resolution", f)
        save("-" * 80, f)

        ip_map = {}

        for sub in full_subdomains:
            ip = resolve(sub)
            if ip:
                ip_map.setdefault(ip, set()).add(sub)
                save(f"[RESOLVED] {sub} → {ip}", f)
            else:
                save(f"[UNRESOLVED] {sub}", f)

        # 3. Shodan search (domain-based)
        save("\n[3] Shodan Search (Domain-based)", f)
        save("-" * 80, f)

        queries = [
            f"hostname:{domain}",
            f"ssl.cert.subject.CN:{domain}",
            f"ssl.cert.subject.CN:*.{domain}"
        ]

        discovered_ips = set()

        for query in queries:
            save(f"\n[QUERY] {query}", f)

            try:
                results = api.search(query, limit=100)
            except shodan.APIError as e:
                save(f"[!] Search error: {e}", f)
                continue

            save(f"[+] Results: {results['total']}", f)

            for match in results.get("matches", []):
                ip = match.get("ip_str")
                discovered_ips.add(ip)

                save("\n-------------------------------", f)
                save(f"IP: {ip}", f)
                save(f"Port: {match.get('port')}", f)
                save(f"Org: {match.get('org')}", f)
                save(f"Product: {match.get('product')}", f)

                http = match.get("http")
                if http:
                    save("HTTP:", f)
                    save(f"  Title: {http.get('title')}", f)
                    save(f"  Server: {http.get('server')}", f)
                    save(f"  Host: {http.get('host')}", f)

                ssl = match.get("ssl")
                if ssl:
                    cert = ssl.get("cert", {})
                    subject = cert.get("subject", {})
                    issuer = cert.get("issuer", {})
                    save("SSL:", f)
                    save(f"  Subject CN: {subject.get('CN')}", f)
                    save(f"  Issuer CN: {issuer.get('CN')}", f)

        # 4. Shodan host enumeration
        save("\n[4] Shodan Host Enumeration (IP-based)", f)
        save("-" * 80, f)

        all_ips = set(ip_map.keys()) | discovered_ips

        for ip in all_ips:
            save("\n====================================", f)
            save(f"IP: {ip}", f)

            if ip in ip_map:
                save("Associated subdomains:", f)
                for sub in ip_map[ip]:
                    save(f"  - {sub}", f)

            try:
                host = api.host(ip)
            except shodan.APIError as e:
                save(f"[!] Host error: {e}", f)
                continue

            save(f"Org: {host.get('org')}", f)
            save(f"ISP: {host.get('isp')}", f)
            save(f"ASN: {host.get('asn')}", f)

            for svc in host.get("data", []):
                save("\n  [SERVICE]", f)
                save(f"  Port: {svc.get('port')}/{svc.get('transport')}", f)
                save(f"  Product: {svc.get('product')}", f)
                save(f"  Version: {svc.get('version')}", f)
                if svc.get("tags"):
                    save(f"  Tags: {', '.join(svc.get('tags'))}", f)

        save("\n[+] Recon completed.", f)

    print(f"\n[✔] Results saved to {output_file}")


if __name__ == "__main__":
    banner()

    if len(sys.argv) != 2:
        print("Usage: python shodan_domain_recon.py example.com")
        sys.exit(1)

    main(sys.argv[1])
