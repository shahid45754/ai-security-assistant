"""
Utility functions for sanitizing data.
"""

import re
import string
from datetime import datetime
from typing import Any, Dict, List, Union


def sanitize_text(text: str) -> str:
    """
    Sanitize text by removing control characters and escaping special characters.
    """
    if not text:
        return ""
    
    # Keep only printable characters plus newline and tab
    printable = set(string.printable)
    sanitized = ''.join(char for char in text if char in printable or char in ['\n', '\t'])
    
    # Replace problematic sequences that might break JSON
    replacements = {
        '<script>': '[script]',
        '</script>': '[/script]',
        '<SCRIPT>': '[SCRIPT]',
        '</SCRIPT>': '[/SCRIPT]',
        'alert(': 'alert(',
        'onerror=': 'onerror=',
        'onload=': 'onload=',
        'javascript:': '[javascript:]',
        'vbscript:': '[vbscript:]',
        'data:text/html': '[data:text/html]',
    }
    
    for old, new in replacements.items():
        sanitized = sanitized.replace(old, new)
    
    return sanitized


def sanitize_for_json(data: Any) -> Any:
    """
    Recursively sanitize data for JSON serialization.
    """
    if isinstance(data, str):
        return sanitize_text(data)
    elif isinstance(data, dict):
        return {k: sanitize_for_json(v) for k, v in data.items()}
    elif isinstance(data, list):
        return [sanitize_for_json(item) for item in data]
    elif isinstance(data, (int, float, bool)):
        return data
    elif data is None:
        return None
    elif isinstance(data, datetime):
        return data.isoformat()
    else:
        return sanitize_text(str(data))


def remove_control_chars(text: str) -> str:
    """
    Remove all control characters from text.
    """
    if not text:
        return text
    # Remove all control characters except newline, carriage return, and tab
    return re.sub(r'[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]', '', text)


def truncate_text(text: str, max_length: int = 500, suffix: str = "...") -> str:
    """
    Truncate text to a maximum length.
    """
    if not text or len(text) <= max_length:
        return text
    return text[:max_length - len(suffix)] + suffix


def extract_ip(text: str) -> Union[str, None]:
    """
    Extract IP address from text.
    """
    ip_pattern = r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'
    match = re.search(ip_pattern, text)
    if match:
        ip = match.group(0)
        # Skip localhost and private IPs (optional)
        if ip not in ['127.0.0.1', '0.0.0.0']:
            return ip
    return None


def extract_timestamp(text: str) -> Union[datetime, None]:
    """
    Extract timestamp from text.
    """
    patterns = [
        # ISO format: 2026-01-15T10:20:30Z
        r'(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z?)',
        # Standard format: 2026-01-15 10:20:30
        r'(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})',
        # Month format: Jan 15 2026 10:20:30
        r'([A-Za-z]{3}\s+\d{1,2}\s+\d{4}\s+\d{2}:\d{2}:\d{2})',
        # Month format: 15/Feb/2026:10:20:30
        r'(\d{1,2}/[A-Za-z]{3}/\d{4}:\d{2}:\d{2}:\d{2})',
        # Apache format: 19/Jul/2026:10:15:30 +0000
        r'(\d{1,2}/[A-Za-z]{3}/\d{4}:\d{2}:\d{2}:\d{2}\s+[+-]\d{4})',
    ]
    
    for pattern in patterns:
        match = re.search(pattern, text)
        if match:
            timestamp_str = match.group(1)
            try:
                # Try ISO format
                if 'T' in timestamp_str:
                    return datetime.fromisoformat(timestamp_str.replace('Z', '+00:00'))
                # Try standard format
                return datetime.strptime(timestamp_str, '%Y-%m-%d %H:%M:%S')
            except:
                try:
                    # Try month format
                    return datetime.strptime(timestamp_str, '%b %d %Y %H:%M:%S')
                except:
                    try:
                        # Try day/month format
                        return datetime.strptime(timestamp_str, '%d/%b/%Y:%H:%M:%S')
                    except:
                        try:
                            # Try Apache format
                            return datetime.strptime(timestamp_str, '%d/%b/%Y:%H:%M:%S %z')
                        except:
                            continue
    return None


def extract_username(text: str) -> Union[str, None]:
    """
    Extract username from text.
    """
    patterns = [
        r'user[=:]\s*([^\s,]+)',
        r'username[=:]\s*([^\s,]+)',
        r'account[=:]\s*([^\s,]+)',
        r'User[=:]\s*([^\s,]+)',
        r'[Ff]or\s+(?:invalid\s+)?user\s+([^\s]+)',
        r'[Ii]nvalid\s+user\s+([^\s]+)',
    ]
    
    for pattern in patterns:
        match = re.search(pattern, text, re.IGNORECASE)
        if match:
            username = match.group(1)
            # Clean up username
            username = username.strip('"\'.,;:')
            if username and username not in ['', 'from', 'for', 'to']:
                return username
    return None


def is_suspicious_ip(ip: str) -> bool:
    """
    Check if an IP address is suspicious.
    """
    suspicious_ips = [
        '0.0.0.0',
        '255.255.255.255',
        '127.0.0.1',
        '::1',
        'localhost',
    ]
    
    if ip in suspicious_ips:
        return False
    
    # Check for private IP ranges
    private_ranges = [
        (10, 0, 0, 0, 10, 255, 255, 255),
        (172, 16, 0, 0, 172, 31, 255, 255),
        (192, 168, 0, 0, 192, 168, 255, 255),
    ]
    
    parts = ip.split('.')
    if len(parts) == 4:
        a, b, c, d = map(int, parts)
        for start_a, start_b, start_c, start_d, end_a, end_b, end_c, end_d in private_ranges:
            if (start_a <= a <= end_a and start_b <= b <= end_b and 
                start_c <= c <= end_c and start_d <= d <= end_d):
                return False
    
    # Check if IP is public (non-private)
    # For simplicity, we consider private IPs as less suspicious
    return True


def merge_dicts(dict1: Dict, dict2: Dict) -> Dict:
    """
    Merge two dictionaries recursively.
    """
    result = dict1.copy()
    for key, value in dict2.items():
        if key in result and isinstance(result[key], dict) and isinstance(value, dict):
            result[key] = merge_dicts(result[key], value)
        else:
            result[key] = value
    return result


def format_duration(seconds: float) -> str:
    """
    Format duration in seconds to a human-readable string.
    """
    if seconds < 60:
        return f"{seconds:.0f} seconds"
    elif seconds < 3600:
        minutes = seconds / 60
        return f"{minutes:.0f} minutes"
    elif seconds < 86400:
        hours = seconds / 3600
        return f"{hours:.1f} hours"
    else:
        days = seconds / 86400
        return f"{days:.1f} days"
