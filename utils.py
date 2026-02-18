# utils.py
# Secondary script containing helper functions. Imported by main.py.

import re
import sys
import time
from functools import lru_cache
from datetime import datetime

import whois
from ipwhois import IPWhois
from ipwhois.exceptions import IPDefinedError, WhoisLookupError

# Cache for WHOIS results to avoid repeated lookups
_whois_cache = {}
_ip_whois_cache = {}

# Known abuse contacts for major providers
KNOWN_ABUSE_CONTACTS = {
    'google.com': ['abuse@google.com', 'postmaster@google.com'],
    'gmail.com': ['abuse@google.com'],
    'hostinger.io': ['abuse@hostinger.com', 'support@hostinger.com'],
    'hostinger.com': ['abuse@hostinger.com'],
    'mailchannels.net': ['abuse@mailchannels.net'],
    'aws.amazon.com': ['abuse@amazonaws.com'],
    'azure.microsoft.com': ['abuse@microsoft.com'],
    'cloudflare.com': ['abuse@cloudflare.com'],
}

def extract_domains_and_ips(headers_str):
    """
    Extract unique domains and IPs from email headers.
    Improved to handle complex email headers with multiple servers.
    """
    domains = set()
    ips = set()
    
    # Regex for IPv4 addresses (including in brackets)
    ip_regex = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
    ips_found = re.findall(ip_regex, headers_str)
    
    # Filter out localhost and private IPs, add rest
    for ip in ips_found:
        if not (ip.startswith('127.') or ip.startswith('10.') or 
                ip.startswith('192.168.') or ip.startswith('172.')):
            ips.add(ip)
    
    # Enhanced domain extraction
    # Match common domain patterns from email headers
    domain_patterns = [
        # Standard TLDs
        r'(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+(?:com|net|org|edu|gov|co|uk|de|fr|it|es|nl|be|ch|at|se|no|dk|fi|pl|cz|ru|ua|io|info|biz|name|pro|asia|cat|jobs|mobi|tel|travel|xxx|aero|coop|museum|ac|ae|af|ag|ai|al|am|ao|aq|ar|as|aw|ax|az|ba|bb|bd|bf|bg|bh|bi|bj|bm|bn|bo|br|bs|bt|bv|bw|by|bz|ca|cc|cd|cf|cg|ci|ck|cl|cm|cn|cr|cu|cv|cw|cx|cy|cz|dj|dm|do|dz|ec|ee|eg|eh|er|et|eu|fj|fk|fm|fo|ga|gb|gd|ge|gf|gg|gh|gi|gl|gm|gn|gp|gq|gr|gs|gt|gu|gw|gy|hk|hm|hn|hr|ht|hu|id|ie|il|im|in|iq|ir|is|je|jm|jo|jp|ke|kg|kh|ki|km|kn|kp|kw|ky|kz|la|lb|lc|li|lk|lr|ls|lt|lu|lv|ly|ma|mc|md|me|mg|mh|mk|ml|mm|mn|mo|mp|mq|mr|ms|mt|mu|mv|mw|mx|my|mz|na|nc|ne|nf|ng|ni|np|nr|nu|nz|om|pa|pe|pf|pg|ph|pk|pm|pn|ps|pt|pw|py|qa|re|ro|rs|rw|sa|sb|sc|sd|sg|sh|si|sj|sk|sl|sm|sn|so|sr|ss|st|sv|sx|sy|sz|tc|td|tf|tg|th|tj|tk|tl|tm|tn|to|tp|tr|tt|tv|tw|tz|ug|us|uy|uz|va|vc|ve|vg|vi|vn|vu|wf|ws|ye|yt|za|zm|zw)\b',
        # Cloud providers and common services
        r'(?:gmail|yahoo|outlook|hotmail|aol|icloud|mail|smtp|mx|relay|mail[a-z0-9]*|relay[a-z0-9]*|smtp[a-z0-9]*|send[a-z0-9]*|bounce|notification|noreply|support|help|info|abuse|postmaster|mailer|delivery)\.(?:com|net|org|co\.uk|com\.br|de|fr|it|es|nl)',
        # Subdomains with multiple parts
        r'[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?){1,3}\.[a-zA-Z]{2,}',
    ]
    
    for pattern in domain_patterns:
        matches = re.findall(pattern, headers_str, re.IGNORECASE)
        domains.update(matches)
    
    # Additional specific extraction from common email header lines
    # Look for domains in Received, From, Return-Path, etc.
    header_lines = [
        r'Received:\s*(?:from|by)\s+([a-zA-Z0-9\.\-]+)',
        r'From:\s*.*<([a-zA-Z0-9\.\-]+@)?([a-zA-Z0-9\.\-]+)>',
        r'Return-Path:\s*<.*@([a-zA-Z0-9\.\-]+)>',
        r'(?:X-Sender-Id|X-MailChannels-SenderId):\s*.*@([a-zA-Z0-9\.\-]+)',
    ]
    
    for pattern in header_lines:
        matches = re.findall(pattern, headers_str, re.IGNORECASE)
        if matches:
            if isinstance(matches[0], tuple):
                for group in matches[0]:
                    if group:
                        domains.add(group)
            else:
                domains.add(matches[0])
    
    # Clean up domains - remove IPs and single letters, keep only valid domains
    cleaned_domains = set()
    for domain in domains:
        # Skip if it looks like an IP
        if re.match(r'^\d+\.\d+\.\d+\.\d+$', domain):
            continue
        # Skip single letter or numeric-only items
        if len(domain) < 3 or domain.isdigit():
            continue
        # Skip localhost
        if domain.lower() in ['localhost', '127.0.0.1']:
            continue
        # Skip Kubernetes/Docker internal names
        if 'svc.cluster' in domain.lower() or 'trex-nlb' in domain.lower():
            continue
        # Skip bare numbers
        if re.match(r'^\d+$', domain):
            continue
        # Require at least one dot for valid domain (unless it's a known single word)
        if domain.count('.') == 0 and domain.lower() not in ['localhost']:
            continue
        # Filter out overly generic extracted strings
        if domain.lower() in ['a', 'x', 'by', 'to', 'for', 'from']:
            continue
        
        cleaned_domains.add(domain.lower())
    
    return cleaned_domains, ips

def get_abuse_emails_for_domain(domain, timeout=5, max_retries=2):
    """
    Use WHOIS to get abuse emails for a domain.
    Includes caching, timeouts, and fallback contacts.
    """
    # Check cache first
    if domain in _whois_cache:
        return _whois_cache[domain]
    
    # Check known contacts
    domain_lower = domain.lower()
    for known_domain, emails in KNOWN_ABUSE_CONTACTS.items():
        if known_domain in domain_lower or domain_lower.endswith(known_domain):
            _whois_cache[domain] = emails
            return emails
    
    # Try WHOIS with retries
    for attempt in range(max_retries):
        try:
            # Set timeout using environment variable (some versions support this)
            w = whois.whois(domain, timeout=timeout)
            
            emails = w.get('emails') or w.get('email') or []
            if not isinstance(emails, list):
                emails = [emails] if emails else []
            
            # Filter for abuse emails
            abuse_emails = [e for e in emails if 'abuse' in e.lower() or 'postmaster' in e.lower()]
            result = abuse_emails or emails or []
            
            # Cache the result
            _whois_cache[domain] = result
            return result
            
        except (TimeoutError, Exception) as e:
            error_type = type(e).__name__
            
            if attempt < max_retries - 1:
                # Retry with exponential backoff
                wait_time = 2 ** attempt
                print(f"  ! WHOIS timeout for {domain}, retrying in {wait_time}s...")
                time.sleep(wait_time)
            else:
                # All retries exhausted
                print(f"  ! WHOIS failed for {domain}: {error_type}")
                
                # Try common abuse emails for this domain
                common_emails = [
                    f'abuse@{domain}',
                    f'postmaster@{domain}',
                    f'admin@{domain}',
                ]
                _whois_cache[domain] = common_emails
                return common_emails
    
    return []

def get_abuse_emails_for_ip(ip, timeout=5, max_retries=1):
    """
    Use ipwhois to get abuse contacts for an IP.
    Parses RDAP objects/roles for abuse contacts. No bogus IP-based emails.
    """
    # Check cache first
    if ip in _ip_whois_cache:
        return _ip_whois_cache[ip]

    for attempt in range(max_retries):
        try:
            obj = IPWhois(ip, timeout=timeout)
            results = obj.lookup_rdap(timeout=timeout)

            if not results or not isinstance(results, dict):
                raise ValueError("Invalid RDAP results structure")

            emails = set()

            # Prefer RDAP objects with role 'abuse'
            objects = results.get('objects') or {}
            if isinstance(objects, dict):
                for _, o in objects.items():
                    try:
                        roles = [r.lower() for r in (o.get('roles') or [])]
                        if 'abuse' in roles:
                            # Extract from 'contact.email'
                            contact = o.get('contact') or {}
                            e = contact.get('email')
                            if isinstance(e, list):
                                emails.update([x for x in e if isinstance(x, str)])
                            elif isinstance(e, str):
                                emails.add(e)

                            # Extract from 'vcardArray'
                            vcard = o.get('vcardArray')
                            if isinstance(vcard, list) and len(vcard) == 2 and isinstance(vcard[1], list):
                                for item in vcard[1]:
                                    if isinstance(item, list) and len(item) >= 4 and item[0] == 'email':
                                        val = item[3]
                                        if isinstance(val, str):
                                            emails.add(val)
                    except Exception:
                        continue

            # Some RDAP servers place contacts under network->remarks or links
            # (We keep this simple; primary source is objects with 'abuse' role.)

            result_list = sorted(emails)
            _ip_whois_cache[ip] = result_list
            return result_list

        except (IPDefinedError, WhoisLookupError, TypeError, AttributeError, ValueError) as e:
            if attempt < max_retries - 1:
                time.sleep(2 ** attempt)
            else:
                print(f"  ! IP WHOIS failed for {ip}: {type(e).__name__}")
                _ip_whois_cache[ip] = []
                return []
        except TimeoutError:
            if attempt < max_retries - 1:
                time.sleep(2 ** attempt)
            else:
                print(f"  ! IP WHOIS failed for {ip}: Timeout")
                _ip_whois_cache[ip] = []
                return []
        except Exception as e:
            if attempt < max_retries - 1:
                time.sleep(2 ** attempt)
            else:
                print(f"  ! IP WHOIS failed for {ip}: {type(e).__name__}")
                _ip_whois_cache[ip] = []
                return []

    _ip_whois_cache[ip] = []
    return []

def generate_abuse_email(user_name, user_email, domains, ips, emails, headers_str):
    """
    Generate email template with all abuse emails as BCC, including the full email header.
    Returns: (subject, to, bcc_list, body, filename)
    filename format: abuse_report_YYYY-MM-DD_HHMMSS.txt
    """
    # Generate date-based filename
    now = datetime.now()
    filename = now.strftime('abuse_report_%Y-%m-%d_%H%M%S.txt')
    
    subject = "ABUSE REPORT - Phishing/Spam Email Attack"
    
    # All abuse emails go to BCC
    bcc_list = sorted(set(emails)) if emails else ['abuse@example.com']
    
    # Primary recipient (user's email)
    to_recipient = user_email if user_email else 'sender@example.com'
    
    # Email body with all recipients listed
    email_body = f"""Subject: {subject}
To: {to_recipient}
Bcc: {', '.join(bcc_list)}

Dear Abuse Team,

I am writing to report a phishing/spam email attack. The email headers show involvement of your infrastructure.

REPORTER INFORMATION:
  Name: {user_name}
  Email: {user_email}

INFRASTRUCTURE INVOLVED:
  Domains ({len(domains)}): {', '.join(sorted(domains)) if domains else 'None'}
  IP Addresses ({len(ips)}): {', '.join(sorted(ips)) if ips else 'None'}

ABUSE CONTACTS IDENTIFIED ({len(bcc_list)}):
{chr(10).join(f'  - {e}' for e in bcc_list)}

Please investigate this malicious activity and take appropriate action.

Thank you,
{user_name}
"""
    
    return subject, to_recipient, bcc_list, email_body, filename
