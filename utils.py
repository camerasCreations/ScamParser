# utils.py
# Secondary script containing helper functions. Imported by main.py.

import re
import sys
import time
import dns.resolver
from email import message_from_file
from email.parser import Parser
from functools import lru_cache
from datetime import datetime

import whois
from ipwhois import IPWhois
from ipwhois.exceptions import IPDefinedError, WhoisLookupError

# Cache for WHOIS results to avoid repeated lookups
_whois_cache = {}
_ip_whois_cache = {}
_email_validation_cache = {}

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
    # Enhanced Received header parsing to get ALL relay information
    received_lines = re.findall(r'Received:.*?(?=\nReceived:|\n[A-Z][a-zA-Z-]+:|$)', headers_str, re.IGNORECASE | re.DOTALL)
    
    for received in received_lines:
        # Extract from "from hostname" part
        from_matches = re.findall(r'(?:from|From)\s+([a-zA-Z0-9](?:[a-zA-Z0-9\-\.]{0,253}[a-zA-Z0-9])?)', received)
        domains.update([m for m in from_matches if m])
        
        # Extract from "by hostname" part
        by_matches = re.findall(r'(?:by|By)\s+([a-zA-Z0-9](?:[a-zA-Z0-9\-\.]{0,253}[a-zA-Z0-9])?)', received)
        domains.update([m for m in by_matches if m])
        
        # Extract from parenthetical (claimed hostname [IP]) format
        paren_matches = re.findall(r'\(([a-zA-Z0-9][a-zA-Z0-9\-\.]+)\s+\[', received)
        domains.update([m for m in paren_matches if m])
        
        # Extract IPs from [IP] format in Received headers
        ip_bracket_matches = re.findall(r'\[(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\]', received)
        for ip in ip_bracket_matches:
            if not (ip.startswith('127.') or ip.startswith('10.') or 
                    ip.startswith('192.168.') or ip.startswith('172.')):
                ips.add(ip)
    
    # Look for domains in other headers
    other_header_patterns = [
        r'From:\s*.*<(?:[a-zA-Z0-9._%+-]+@)?([a-zA-Z0-9\.\-]+)>',
        r'Return-Path:\s*<.*@([a-zA-Z0-9\.\-]+)>',
        r'(?:X-Sender-Id|X-MailChannels-SenderId):\s*.*@([a-zA-Z0-9\.\-]+)',
        r'(?:X-Originating-IP|X-Sender-IP):\s*\[?(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\]?',
        r'Authentication-Results:\s*([a-zA-Z0-9\.\-]+);',
        r'DKIM-Signature:.*d=([a-zA-Z0-9\.\-]+)',
        r'SPF.*@([a-zA-Z0-9\.\-]+)',
    ]
    
    for pattern in other_header_patterns:
        matches = re.findall(pattern, headers_str, re.IGNORECASE)
        for match in matches:
            if match and not match.startswith('127.') and not match.startswith('10.'):
                if re.match(r'^\d+\.\d+\.\d+\.\d+$', match):
                    if not (match.startswith('192.168.') or match.startswith('172.')):
                        ips.add(match)
                else:
                    domains.add(match)
    
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

def validate_email(email):
    """
    Validate email address by checking syntax and DNS MX records.
    Returns (is_valid, reason)
    """
    # Check cache first
    if email in _email_validation_cache:
        return _email_validation_cache[email]
    
    # Basic syntax validation
    email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    if not re.match(email_pattern, email):
        result = (False, "Invalid email syntax")
        _email_validation_cache[email] = result
        return result
    
    # Extract domain from email
    try:
        domain = email.split('@')[1]
    except IndexError:
        result = (False, "Invalid email format")
        _email_validation_cache[email] = result
        return result
    
    # Check for MX records (indicates domain can receive email)
    try:
        mx_records = dns.resolver.resolve(domain, 'MX', lifetime=5)
        # Ensure we have at least one MX record
        if mx_records:
            result = (True, "Valid (has MX records)")
            _email_validation_cache[email] = result
            return result
        else:
            result = (False, "No MX records found")
            _email_validation_cache[email] = result
            return result
    except dns.resolver.NXDOMAIN:
        result = (False, "Domain does not exist")
        _email_validation_cache[email] = result
        return result
    except dns.resolver.NoAnswer:
        result = (False, "No MX records (cannot receive email)")
        _email_validation_cache[email] = result
        return result
    except dns.resolver.Timeout:
        result = (False, "DNS timeout")
        _email_validation_cache[email] = result
        return result
    except Exception as e:
        result = (False, f"DNS error: {type(e).__name__}")
        _email_validation_cache[email] = result
        return result

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
            found_emails = abuse_emails or emails or []
            
            # Validate emails before returning
            validated = []
            for email in found_emails:
                is_valid, reason = validate_email(email)
                if is_valid:
                    validated.append(email)
                else:
                    print(f"    ✗ Skipping {email}: {reason}")
            
            # Cache the result
            _whois_cache[domain] = validated
            return validated
            
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
                
                # Validate common emails
                validated = []
                for email in common_emails:
                    is_valid, reason = validate_email(email)
                    if is_valid:
                        validated.append(email)
                
                _whois_cache[domain] = validated
                return validated
    
    return []

def get_abuse_emails_for_ip(ip, timeout=5, max_retries=1):
    """
    Use ipwhois to get abuse contacts for an IP.
    Parses RDAP objects/roles for abuse contacts and extracts from multiple locations.
    """
    # Check cache first
    if ip in _ip_whois_cache:
        return _ip_whois_cache[ip]

    for attempt in range(max_retries):
        try:
            obj = IPWhois(ip, timeout=timeout)
            results = obj.lookup_rdap(depth=1)

            if not results or not isinstance(results, dict):
                raise ValueError("Invalid RDAP results structure")

            emails = set()

            # Method 1: Check for direct abuse_emails field (some RDAP servers provide this)
            if 'abuse_emails' in results and results['abuse_emails']:
                if isinstance(results['abuse_emails'], list):
                    emails.update(results['abuse_emails'])
                elif isinstance(results['abuse_emails'], str):
                    emails.add(results['abuse_emails'])

            # Method 2: Check network->entities for abuse contacts
            network = results.get('network', {})
            if network and isinstance(network, dict):
                entities = network.get('entities', [])
                if isinstance(entities, list):
                    for entity_id in entities:
                        # Look up this entity in objects
                        objects = results.get('objects', {})
                        if isinstance(objects, dict) and entity_id in objects:
                            entity_obj = objects[entity_id]
                            roles = entity_obj.get('roles', [])
                            if roles and isinstance(roles, list):
                                roles_lower = [r.lower() for r in roles if isinstance(r, str)]
                                if 'abuse' in roles_lower:
                                    # Extract emails from this abuse entity
                                    emails.update(_extract_emails_from_rdap_object(entity_obj))

            # Method 3: Parse all RDAP objects with 'abuse' role
            objects = results.get('objects', {})
            if isinstance(objects, dict):
                for obj_id, obj_data in objects.items():
                    if not isinstance(obj_data, dict):
                        continue
                    roles = obj_data.get('roles', [])
                    if roles and isinstance(roles, list):
                        roles_lower = [r.lower() for r in roles if isinstance(r, str)]
                        if 'abuse' in roles_lower:
                            emails.update(_extract_emails_from_rdap_object(obj_data))

            # Method 4: Check ASN information
            asn = results.get('asn', '')
            asn_description = results.get('asn_description', '')
            if asn and asn_description:
                # Some providers: abuse mailbox pattern
                asn_emails = re.findall(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', 
                                       str(asn_description))
                emails.update(asn_emails)

            # Validate and filter emails
            validated_emails = []
            for email in emails:
                if not isinstance(email, str):
                    continue
                email = email.strip().lower()
                if not email:
                    continue
                    
                is_valid, reason = validate_email(email)
                if is_valid:
                    validated_emails.append(email)
                else:
                    print(f"    ✗ Skipping {email}: {reason}")
            
            result_list = sorted(set(validated_emails))
            _ip_whois_cache[ip] = result_list
            return result_list

        except (IPDefinedError, WhoisLookupError) as e:
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
                print(f"  ! IP WHOIS failed for {ip}: {type(e).__name__} - {str(e)}")
                _ip_whois_cache[ip] = []
                return []

    _ip_whois_cache[ip] = []
    return []

def _extract_emails_from_rdap_object(obj):
    """
    Extract email addresses from an RDAP object (handles multiple formats).
    Returns a set of email addresses.
    """
    emails = set()
    
    if not isinstance(obj, dict):
        return emails
    
    # Check contact.email field (ARIN and other RIRs use this)
    contact = obj.get('contact')
    if contact and isinstance(contact, dict):
        email_field = contact.get('email')
        if isinstance(email_field, list):
            # Handle list of dicts with 'value' key: [{'type': None, 'value': 'email@example.com'}]
            for item in email_field:
                if isinstance(item, dict) and 'value' in item:
                    emails.add(item['value'])
                elif isinstance(item, str):
                    emails.add(item)
        elif isinstance(email_field, str):
            emails.add(email_field)
    
    # Check vcardArray (standard RDAP format)
    vcard = obj.get('vcardArray')
    if isinstance(vcard, list) and len(vcard) >= 2:
        vcard_data = vcard[1] if len(vcard) >= 2 else []
        if isinstance(vcard_data, list):
            for item in vcard_data:
                if isinstance(item, list) and len(item) >= 4:
                    if item[0] == 'email':
                        val = item[3]
                        if isinstance(val, str):
                            emails.add(val)
                        elif isinstance(val, dict) and 'value' in val:
                            emails.add(val['value'])
    
    # Check direct email field (some providers use this)
    if 'email' in obj:
        email_field = obj['email']
        if isinstance(email_field, list):
            for item in email_field:
                if isinstance(item, dict) and 'value' in item:
                    emails.add(item['value'])
                elif isinstance(item, str):
                    emails.add(item)
        elif isinstance(email_field, str):
            emails.add(email_field)
    
    # Check remarks for abuse emails (some providers include it here)
    remarks = obj.get('remarks')
    if isinstance(remarks, list):
        for remark in remarks:
            if isinstance(remark, dict):
                description = remark.get('description', [])
                if isinstance(description, list):
                    for desc in description:
                        if isinstance(desc, str):
                            # Extract emails from description text
                            found = re.findall(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', desc)
                            emails.update(found)
    
    return emails

def parse_eml_file(file_path):
    """
    Parse a .eml file and extract headers.
    Returns: (headers_str, eml_content) where eml_content is the full file content
    """
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            eml_content = f.read()
        
        # Parse the email
        from email.parser import Parser
        from io import StringIO
        
        parser = Parser()
        msg = parser.parse(StringIO(eml_content))
        
        # Extract all headers
        headers_list = []
        for header_name in msg.keys():
            # Get all values for this header (some headers can appear multiple times)
            values = msg.get_all(header_name)
            for value in values:
                # Decode header if needed
                headers_list.append(f"{header_name}: {value}")
        
        headers_str = "\n".join(headers_list)
        return headers_str, eml_content
        
    except Exception as e:
        print(f"Error parsing .eml file: {e}")
        return None, None

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
    
    # Email body with all recipients listed and FULL HEADERS included
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

{'='*70}
FULL EMAIL HEADERS (EVIDENCE)
{'='*70}

{headers_str}

{'='*70}

Thank you,
{user_name}
"""
    
    return subject, to_recipient, bcc_list, email_body, filename

def generate_eml_file(user_name, user_email, domains, ips, bcc_list, headers_str, original_eml_content=None):
    """
    Generate a RFC822 .eml file that can be imported into Gmail or other email clients.
    If original_eml_content is provided, attaches the original .eml as message/rfc822.
    Returns: (eml_content, eml_filename)
    """
    from email.mime.text import MIMEText
    from email.mime.multipart import MIMEMultipart
    from email.utils import formatdate, make_msgid
    
    # Generate date-based filename
    now = datetime.now()
    eml_filename = now.strftime('abuse_report_%Y-%m-%d_%H%M%S.eml')
    
    # Create the email message
    msg = MIMEMultipart()
    msg['From'] = user_email
    msg['To'] = user_email  # Send to yourself
    msg['Bcc'] = ', '.join(bcc_list)
    msg['Subject'] = 'ABUSE REPORT - Phishing/Spam Email Attack'
    msg['Date'] = formatdate(localtime=True)
    msg['Message-ID'] = make_msgid()
    
    # Create email body with full headers
    body_text = f"""Dear Abuse Team,

I am writing to report a phishing/spam email attack. The email headers show involvement of your infrastructure.

REPORTER INFORMATION:
  Name: {user_name}
  Email: {user_email}

INFRASTRUCTURE INVOLVED:
  Domains ({len(domains)}): {', '.join(sorted(domains)) if domains else 'None'}
  IP Addresses ({len(ips)}): {', '.join(sorted(ips)) if ips else 'None'}

ABUSE CONTACTS (BCC'd on this email - {len(bcc_list)} recipients):
{chr(10).join(f'  - {e}' for e in bcc_list)}

Please investigate this malicious activity and take appropriate action.

{'='*70}
FULL EMAIL HEADERS (EVIDENCE)
{'='*70}

{headers_str}

{'='*70}

Thank you,
{user_name}
"""
    
    # Attach the body as plain text
    msg.attach(MIMEText(body_text, 'plain', 'utf-8'))
    
    # If original .eml content provided, attach it as message/rfc822
    if original_eml_content:
        from email.mime.message import MIMEMessage
        from email import message_from_string
        
        # Parse the original email
        original_msg = message_from_string(original_eml_content)
        
        # Attach as message/rfc822 (standard format for attached emails)
        attachment = MIMEMessage(original_msg, 'rfc822')
        attachment.add_header('Content-Disposition', 'attachment', filename='original_scam_email.eml')
        msg.attach(attachment)
    
    # Return the .eml content as a string
    eml_content = msg.as_string()
    
    return eml_content, eml_filename
