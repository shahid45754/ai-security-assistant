import re
from datetime import datetime
from typing import Optional

from app.models.incident import Incident
from app.parsers.base_parser import BaseParser
from app.core.utils import sanitize_text


class ApacheParser(BaseParser):
    """Parser for Apache access and error logs."""
    
    # Apache log format patterns
    LOG_PATTERNS = {
        'combined': r'^(\S+) \S+ \S+ \[([^\]]+)\] "(\S+) (\S+) (\S+)" (\d{3}) \d+ "([^"]*)" "([^"]*)"',
        'common': r'^(\S+) \S+ \S+ \[([^\]]+)\] "(\S+) (\S+) (\S+)" (\d{3}) \d+',
        'error': r'^\[([^\]]+)\] \[([^:]+):([^\]]+)\] \[pid \d+:[^\]]+\] (.*)',
    }
    
    # Severity mapping for status codes
    SEVERITY_MAP = {
        '4': 'Medium',
        '403': 'High',
        '404': 'Medium',
        '405': 'Medium',
        '5': 'High',
        '500': 'High',
        '502': 'High',
        '503': 'High',
        '504': 'High',
    }

    def parse(self, content: str) -> list[Incident]:
        """Parse Apache log content."""
        incidents = []
        
        for line in content.splitlines():
            if not line.strip():
                continue
            
            incident = self._parse_line(line)
            if incident:
                incidents.append(incident)
                
        return incidents

    def _parse_line(self, line: str) -> Optional[Incident]:
        """Parse a single Apache log line."""
        
        # Try Combined Log Format first
        match = re.search(self.LOG_PATTERNS['combined'], line)
        if match:
            return self._parse_combined_format(match, line)
        
        # Try Common Log Format
        match = re.search(self.LOG_PATTERNS['common'], line)
        if match:
            return self._parse_common_format(match, line)
        
        # Try Error Log Format
        match = re.search(self.LOG_PATTERNS['error'], line)
        if match:
            return self._parse_error_format(match, line)
        
        # If no format matches, try generic parsing
        return self._parse_generic_format(line)

    def _sanitize_description(self, text: str) -> str:
        """Sanitize description to remove control characters."""
        if not text:
            return text
        return sanitize_text(text)

    def _parse_combined_format(self, match, line: str) -> Optional[Incident]:
        """Parse Apache Combined Log Format."""
        groups = match.groups()
        
        source_ip = groups[0]
        timestamp_str = groups[1]
        method = groups[2]
        path = groups[3]
        protocol = groups[4]
        status_code = groups[5]
        bytes_sent = groups[6]
        referer = groups[7] if len(groups) > 7 else ''
        user_agent = groups[8] if len(groups) > 8 else ''
        
        timestamp = self._parse_timestamp(timestamp_str)
        path = self._sanitize_description(path)
        user_agent = self._sanitize_description(user_agent) if user_agent else ''
        
        attack_type = self._detect_attack(path, method, user_agent, status_code)
        
        description = f"{method} {path} - Status: {status_code}"
        if attack_type:
            description = f"{attack_type} - {description}"
        if user_agent:
            description += f" - UA: {user_agent[:50]}"
        
        description = self._sanitize_description(description)
        
        action = f"Apache_{method}_{status_code}"
        if attack_type:
            action = f"Apache_{attack_type.replace(' ', '_')}"
        
        if attack_type or status_code.startswith('4') or status_code.startswith('5'):
            return Incident(
                title=f"Apache: {attack_type or 'Event'} - {path[:50]}",
                description=description[:500],
                source_ip=source_ip,
                destination_ip=None,
                username=None,
                protocol="HTTP",
                port=80 if protocol == 'HTTP/1.0' or protocol == 'HTTP/1.1' else 443,
                action=action,
                log_source="apache",
                timestamp=timestamp,
            )
        
        return None

    def _parse_common_format(self, match, line: str) -> Optional[Incident]:
        """Parse Apache Common Log Format."""
        groups = match.groups()
        
        source_ip = groups[0]
        timestamp_str = groups[1]
        method = groups[2]
        path = groups[3]
        protocol = groups[4]
        status_code = groups[5]
        bytes_sent = groups[6]
        
        timestamp = self._parse_timestamp(timestamp_str)
        path = self._sanitize_description(path)
        
        attack_type = self._detect_attack(path, method, '', status_code)
        
        description = f"{method} {path} - Status: {status_code}"
        if attack_type:
            description = f"{attack_type} - {description}"
        
        description = self._sanitize_description(description)
        
        action = f"Apache_{method}_{status_code}"
        if attack_type:
            action = f"Apache_{attack_type.replace(' ', '_')}"
        
        if attack_type or status_code.startswith('4') or status_code.startswith('5'):
            return Incident(
                title=f"Apache: {attack_type or 'Event'} - {path[:50]}",
                description=description[:500],
                source_ip=source_ip,
                destination_ip=None,
                username=None,
                protocol="HTTP",
                port=80,
                action=action,
                log_source="apache",
                timestamp=timestamp,
            )
        
        return None

    def _parse_error_format(self, match, line: str) -> Optional[Incident]:
        """Parse Apache Error Log Format."""
        groups = match.groups()
        
        timestamp_str = groups[0]
        log_level = groups[1]
        module = groups[2]
        message = groups[3]
        
        timestamp = self._parse_timestamp(timestamp_str)
        message = self._sanitize_description(message)
        
        source_ip = self._extract_ip(line)
        
        suspicious_errors = ['file not found', 'permission denied', 'access denied']
        severity = 'Medium'
        attack_type = None
        
        for sus in suspicious_errors:
            if sus in message.lower():
                severity = 'High'
                if 'permission denied' in message.lower() or 'access denied' in message.lower():
                    attack_type = 'Access Denied'
                break
        
        if attack_type or severity == 'High':
            return Incident(
                title=f"Apache Error: {attack_type or message[:30]}",
                description=f"Apache Error: {message[:500]}",
                source_ip=source_ip,
                destination_ip=None,
                username=None,
                protocol="HTTP",
                port=80,
                action=f"Apache_Error_{log_level.upper()}",
                log_source="apache",
                timestamp=timestamp,
            )
        
        return None

    def _parse_generic_format(self, line: str) -> Optional[Incident]:
        """Parse generic Apache log format."""
        parts = line.split()
        
        if len(parts) >= 3:
            source_ip = self._extract_ip(line)
            
            status_code = None
            for part in parts:
                if part.isdigit() and len(part) == 3:
                    status_code = part
                    break
            
            method = None
            for part in parts:
                if part.upper() in ['GET', 'POST', 'PUT', 'DELETE', 'HEAD', 'OPTIONS', 'PATCH']:
                    method = part
                    break
            
            path = None
            for part in parts:
                if part.startswith('/'):
                    path = part
                    break
            
            if status_code or method or path:
                path = self._sanitize_description(path) if path else ''
                attack_type = self._detect_attack(path or '', method or '', '', status_code or '')
                
                description = f"Apache Event"
                if method:
                    description += f" {method}"
                if path:
                    description += f" {path}"
                if status_code:
                    description += f" - Status: {status_code}"
                if attack_type:
                    description = f"{attack_type} - {description}"
                
                description = self._sanitize_description(description)
                
                if attack_type or (status_code and (status_code.startswith('4') or status_code.startswith('5'))):
                    return Incident(
                        title=f"Apache: {attack_type or 'Event'}",
                        description=description[:500],
                        source_ip=source_ip,
                        destination_ip=None,
                        username=None,
                        protocol="HTTP",
                        port=80,
                        action=f"Apache_{method or 'Event'}_{status_code or 'Unknown'}",
                        log_source="apache",
                        timestamp=datetime.now(),
                    )
        
        return None

    def _parse_timestamp(self, timestamp_str: str) -> datetime:
        """Parse Apache timestamp format."""
        try:
            timestamp_str = timestamp_str.strip('[]')
            parts = timestamp_str.split(' ')
            date_part = parts[0]
            time_part = parts[1] if len(parts) > 1 else ''
            
            day, month, year = date_part.split('/')
            hour, minute, second = time_part.split(':') if time_part else ('00', '00', '00')
            
            month_map = {
                'Jan': 1, 'Feb': 2, 'Mar': 3, 'Apr': 4, 'May': 5, 'Jun': 6,
                'Jul': 7, 'Aug': 8, 'Sep': 9, 'Oct': 10, 'Nov': 11, 'Dec': 12
            }
            
            return datetime(
                int(year),
                month_map.get(month, 1),
                int(day),
                int(hour),
                int(minute),
                int(second)
            )
        except:
            return datetime.now()

    def _detect_attack(self, path: str, method: str, user_agent: str, status_code: str) -> Optional[str]:
        """Detect attack type from path, method, and user agent."""
        path_lower = path.lower()
        ua_lower = user_agent.lower()
        
        # SQL Injection
        if any(x in path_lower for x in ['union select', 'or 1=1', 'information_schema', "'--", '"--']):
            return 'SQL Injection'
        
        # XSS
        if any(x in path_lower for x in ['<script', 'alert(', 'onerror=', 'javascript:']):
            return 'Cross Site Scripting'
        
        # Directory Traversal
        if any(x in path_lower for x in ['../', '/etc/passwd', '/etc/shadow', 'boot.ini']):
            return 'Directory Traversal'
        
        # Command Injection
        if any(x in path_lower for x in ['cmd=', 'exec=', 'system=', ';', '|', '`']):
            return 'Command Injection'
        
        # LFI/RFI
        if any(x in path_lower for x in ['php://filter', 'lfi', 'rfi', 'include=']):
            return 'Local File Inclusion'
        
        # Web Shell
        if any(x in path_lower for x in ['shell', 'webshell', 'cmd', 'backdoor']):
            return 'Web Shell'
        
        # File Upload
        if method.upper() == 'POST' and 'upload' in path_lower:
            return 'Malicious File Upload'
        
        # Admin Access
        if any(x in path_lower for x in ['/admin', '/wp-admin', '/phpmyadmin', '/cpanel']):
            return 'Admin Access'
        
        # Suspicious User Agent
        if any(x in ua_lower for x in ['python-requests', 'curl', 'wget', 'nmap', 'nikto', 'dirbuster', 'gobuster', 'sqlmap']):
            return 'Suspicious Scanner'
        
        return None
