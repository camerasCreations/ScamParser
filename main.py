#!/usr/bin/env python3
"""
Scam Parser - Email Header Analysis & Abuse Report Generator
Parses email headers to extract vendors and generates abuse reports
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

# Config file path
CONFIG_FILE = Path("user_config.json")


def load_config():
    """Load user configuration from file or create default."""
    if CONFIG_FILE.exists():
        with open(CONFIG_FILE, "r") as f:
            return json.load(f)
    return {
        "name": "",
        "email": "",
        "handle": "",
        "location": "",
    }


def save_config(config):
    """Save user configuration to file."""
    with open(CONFIG_FILE, "w") as f:
        json.dump(config, f, indent=2)
    print(f"✓ Configuration saved to {CONFIG_FILE}")


def setup_user_info():
    """Get or update user information."""
    config = load_config()
    print("\n" + "="*60)
    print("SETUP USER INFORMATION")
    print("="*60)
    print("(Press Enter to keep existing values)\n")

    name = input(f"Your name [{config['name']}]: ").strip() or config["name"]
    email = input(f"Your email [{config['email']}]: ").strip() or config["email"]
    handle = input(f"Your handle/username [{config['handle']}]: ").strip() or config["handle"]
    location = input(f"Your location [{config['location']}]: ").strip() or config["location"]

    config = {"name": name, "email": email, "handle": handle, "location": location}
    save_config(config)
    return config


def get_email_headers():
    """Get email headers from user input or file."""
    print("\n" + "="*60)
    print("INPUT EMAIL HEADERS")
    print("="*60)
    print("Choose input method:")
    print("1. Paste headers directly (end with blank line)")
    print("2. Load from file")
    choice = input("\nEnter choice (1 or 2): ").strip()

    if choice == "2":
        file_path = input("Enter file path: ").strip()
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                return f.read()
        except FileNotFoundError:
            print(f"✗ File not found: {file_path}")
            return None
    else:
        print("\nPaste email headers below (enter a blank line when done):\n")
        lines = []
        while True:
            try:
                line = input()
                if line.strip() == "":
                    if lines:  # Stop if we have content and hit a blank line
                        break
                else:
                    lines.append(line)
            except EOFError:
                break
        return "\n".join(lines) if lines else None


def parse_and_report(headers_str, user_config):
    """Parse headers and generate abuse reports with date-based file."""
    print("\n" + "="*60)
    print("PARSING EMAIL HEADERS")
    print("="*60)

    # Extract domains and IPs
    domains, ips = extract_domains_and_ips(headers_str)

    print(f"\nFound {len(domains)} unique domains:")
    for domain in sorted(domains):
        print(f"  • {domain}")

    print(f"\nFound {len(ips)} unique IPs:")
    for ip in sorted(ips):
        print(f"  • {ip}")

    if not domains and not ips:
        print("\n✗ No domains or IPs found in the headers.")
        return

    # Collect unique abuse emails
    print("\n" + "="*60)
    print("FINDING ABUSE CONTACTS")
    print("="*60)
    print("Note: WHOIS lookups may take 1-2 minutes. Please be patient...")

    all_abuse_emails = []

    print("\nLooking up domain WHOIS information...")
    total_domains = len(domains)
    for idx, domain in enumerate(sorted(domains), 1):
        print(f"  [{idx}/{total_domains}] {domain}...", end=" ", flush=True)
        emails = get_abuse_emails_for_domain(domain, timeout=10, max_retries=1)
        if emails:
            all_abuse_emails.extend(emails)
            print(f"OK - {len(emails)} contact(s)")
        else:
            print("no contacts found")

    print("\nLooking up IP WHOIS information...")
    total_ips = len(ips)
    for idx, ip in enumerate(sorted(ips), 1):
        print(f"  [{idx}/{total_ips}] {ip}...", end=" ", flush=True)
        emails = get_abuse_emails_for_ip(ip, timeout=10, max_retries=1)
        if emails:
            all_abuse_emails.extend(emails)
            print(f"OK - {len(emails)} contact(s)")
        else:
            print("no contacts found")

    # Remove duplicates and sort
    unique_emails = sorted(set(all_abuse_emails))

    if not unique_emails:
        print("\n✗ No abuse contacts found. You may need to manually search for them.")
        return

    # Generate single email with all recipients in BCC
    print("\n" + "="*60)
    print("GENERATED ABUSE REPORT")
    print("="*60)

    subject, to_recipient, bcc_list, email_body, filename = generate_abuse_email(
        user_config["name"],
        user_config["email"],
        domains,
        ips,
        unique_emails,
        headers_str,
    )

    print(f"\nTO: {to_recipient}")
    print(f"BCC ({len(bcc_list)} recipients): {', '.join(bcc_list[:3])}" + 
          (f" +{len(bcc_list)-3} more" if len(bcc_list) > 3 else ""))
    print(f"\n{'─'*60}")
    print(email_body)
    print(f"{'─'*60}\n")

    # Save email to file with date-based name
    output_file = Path(filename)
    with open(output_file, "w") as f:
        f.write(email_body)
    print(f"✓ Email saved to {output_file}")

    # Also save as JSON for reference
    json_file = Path(filename.replace('.txt', '.json'))
    json_data = {
        "filename": filename,
        "subject": subject,
        "to": to_recipient,
        "bcc": bcc_list,
        "domains": sorted(list(domains)),
        "ips": sorted(list(ips)),
        "total_abuse_contacts": len(bcc_list),
    }
    with open(json_file, "w") as f:
        json.dump(json_data, f, indent=2)
    print(f"✓ Metadata saved to {json_file}")

    return email_body


def main():
    """Main entry point."""
    print("\n" + "#"*60)
    print("#  SCAM PARSER - Email Abuse Report Generator")
    print("#"*60)

    while True:
        print("\nMAIN MENU:")
        print("1. Setup/Update user information")
        print("2. Parse email headers and generate reports")
        print("3. Exit")
        choice = input("\nEnter choice (1-3): ").strip()

        if choice == "1":
            setup_user_info()
        elif choice == "2":
            user_config = load_config()
            if not all([user_config["name"], user_config["email"]]):
                print("\n✗ Please setup user information first (option 1)")
                continue

            headers = get_email_headers()
            if headers:
                parse_and_report(headers, user_config)
            else:
                print("✗ No headers provided.")
        elif choice == "3":
            print("\nGoodbye!")
            break
        else:
            print("✗ Invalid choice. Please try again.")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\nInterrupted by user.")
        sys.exit(0)
    except Exception as e:
        print(f"\n✗ Error: {e}", file=sys.stderr)
        sys.exit(1)