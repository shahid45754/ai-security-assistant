import re
from datetime import datetime
from typing import Optional

from app.models.incident import Incident
from app.parsers.base_parser import BaseParser
from app.core.utils import sanitize_text


class NginxParser(BaseParser):
    """Parser for Nginx access and error logs."""
    
    def parse(self, content: str) -> list[Incident]:
        """Parse Nginx log content."""
        incidents = []
        
        for line in content.splitlines():
            if not line.strip():
                continue
            
            incident = self._parse_line(line)
            if incident:
                incidents.append(incident)
                
        return incidents

    def _parse_line(self, line: str) -> Optional[Incident]:
        """Parse a single Nginx log line."""
        
        # More flexible pattern that handles special characters in the path
        # Nginx Combined Log Format: IP - - [timestamp] "METHOD path protocol" status bytes "referer" "user_agent"
        pattern = r'^(\S+)\s+-\s+-\s+\[([^\]]+)\]\s+"([^"]+)"\s+(\d{3})\s+\d+\s+"([^"]*)"\s+"([^"]*)"'
        match = re.search(pattern, line)
        
        if not match:
            # Try without user agent and referer
            pattern2 = r'^(\S+)\s+-\s+-\s+\[([^\]]+)\]\s+"([^"]+)"\s+(\d{3})\s+\d+'
            match = re.search(pattern2, line)
            if not match:
                # Try even more flexible pattern
                pattern3 = r'^(\S+)\s+-\s+-\s+\[([^\]]+)\]\s+"(\S+)\s+([^"]+?)\s+([^"]+)"\s+(\d{3})'
                match = re.search(pattern3, line)
                if not match:
                    return None
        
        groups = match.groups()
        
        if len(groups) >= 4:
            source_ip = groups[0]
            timestamp_str = groups[1]
            request = groups[2]
            status_code = groups[3] if len(groups) > 3 else '200'
            referer = groups[4] if len(groups) > 4 else ''
            user_agent = groups[5] if len(groups) > 5 else ''
            
            # Parse request into method, path, protocol
            request_parts = request.split(' ')
            if len(request_parts) >= 3:
                method = request_parts[0]
                path = ' '.join(request_parts[1:-1])  # Handle spaces in path
                protocol = request_parts[-1]
            else:
                method = 'GET'
                path = request
                protocol = 'HTTP/1.1'
        else:
            # Try the third pattern
            source_ip = groups[0]
            timestamp_str = groups[1]
            method = groups[2]
            path = groups[3]
            protocol = groups[4]
            status_code = groups[5]
            referer = ''
            user_agent = ''
        
        timestamp = self._parse_timestamp(timestamp_str)
        
        # Sanitize
        path = sanitize_text(path)
        user_agent = sanitize_text(user_agent) if user_agent else ''
        
        # Detect attack type
        attack_type = self._detect_attack(path, method, user_agent, status_code)
        
        # Build description
        description = f"{method} {path} - Status: {status_code}"
        if attack_type:
            description = f"{attack_type} - {description}"
        if user_agent:
            description += f" - UA: {user_agent[:50]}"
        
        description = sanitize_text(description)
        
        # Create action
        action = f"Nginx_{method}_{status_code}"
        if attack_type:
            action = f"Nginx_{attack_type.replace(' ', '_')}"
        
        # Create incident for suspicious activity
        if attack_type or status_code.startswith('4') or status_code.startswith('5'):
            return Incident(
                title=f"Nginx: {attack_type or 'Event'} - {path[:50]}",
                description=description[:500],
                source_ip=source_ip,
                destination_ip=None,
                username=None,
                protocol="HTTP",
                port=80 if protocol == 'HTTP/1.0' or protocol == 'HTTP/1.1' else 443,
                action=action,
                log_source="nginx",
                timestamp=timestamp,
            )
        
        return None

    def _parse_timestamp(self, timestamp_str: str) -> datetime:
        """Parse Nginx timestamp format."""
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
        if any(x in path_lower for x in ['union select', 'or 1=1', 'information_schema', "'--", '"--', "or '1'='1"]):
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
