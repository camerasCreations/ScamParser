#!/usr/bin/env python3
"""
Quick utility to process email headers from command line.
Usage: python quick_parse.py <header_file>
"""

import sys
import json
from pathlib import Path
from utils import (
    extract_domains_and_ips,
    get_abuse_emails_for_domain,
    get_abuse_emails_for_ip,
    generate_abuse_email,
)


def quick_parse(header_file):
    """Quickly parse a header file and show results."""
    try:
        with open(header_file, "r", encoding="utf-8") as f:
            headers_str = f.read()
    except FileNotFoundError:
        print(f"Error: File not found - {header_file}")
        sys.exit(1)

    print("\n" + "="*60)
    print("QUICK PARSE RESULTS")
    print("="*60)

    # Extract
    domains, ips = extract_domains_and_ips(headers_str)
    
    print(f"\nFound {len(domains)} domains: {', '.join(sorted(domains)) if domains else 'None'}")
    print(f"Found {len(ips)} IPs: {', '.join(sorted(ips)) if ips else 'None'}")

    if not domains and not ips:
        print("\nNo extractable information found.")
        return

    # Lookup
    print("\n" + "-"*60)
    print("ABUSE CONTACTS:")
    print("-"*60)

    contacts = {}
    
    for domain in sorted(domains):
        emails = get_abuse_emails_for_domain(domain)
        for email in emails:
            if email and email not in contacts:
                contacts[email] = domain
                print(f"\n{domain}:")
                print(f"  Abuse Contact: {email}")

    for ip in sorted(ips):
        emails = get_abuse_emails_for_ip(ip)
        for email in emails:
            if email and email not in contacts:
                contacts[email] = ip
                print(f"\n{ip}:")
                print(f"  Abuse Contact: {email}")

    if not contacts:
        print("\nNo abuse contacts found via WHOIS.")

    # Save results
    results = {
        "file": header_file,
        "domains": sorted(list(domains)),
        "ips": sorted(list(ips)),
        "abuse_contacts": contacts,
    }
    
    output_file = Path("quick_parse_results.json")
    with open(output_file, "w") as f:
        json.dump(results, f, indent=2)
    
    print(f"\n✓ Results saved to {output_file}")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python quick_parse.py <header_file>")
        print("\nExample: python quick_parse.py sample_headers.txt")
        sys.exit(1)
    
    quick_parse(sys.argv[1])
