import re
from datetime import datetime
from typing import Optional

from app.models.incident import Incident
from app.parsers.base_parser import BaseParser
from app.core.utils import sanitize_text


class SSHParser(BaseParser):
    """Parser for SSH authentication logs."""
    
    def parse(self, content: str) -> list[Incident]:
        """Parse SSH log content."""
        incidents = []
        
        for line in content.splitlines():
            if not line.strip():
                continue
            
            incident = self._parse_line(line)
            if incident:
                incidents.append(incident)
                
        return incidents

    def _parse_line(self, line: str) -> Optional[Incident]:
        """Parse a single SSH log line."""
        
        timestamp = self._extract_timestamp(line)
        source_ip = self._extract_ip(line)
        username = self._extract_username(line)
        
        # Check for SSH specific patterns
        is_failure = self._is_failure(line)
        is_success = self._is_success(line)
        is_brute_force = self._is_brute_force(line)
        
        # Build description
        description = f"SSH Authentication - "
        if username:
            description += f"User: {username} "
        if source_ip:
            description += f"From: {source_ip} "
        if is_failure:
            description += "- FAILED"
        elif is_success:
            description += "- SUCCESS"
        if is_brute_force:
            description += " (Brute Force Attempt)"
        
        description = sanitize_text(description)
        
        # Determine severity
        severity = 'Critical' if is_brute_force else 'High' if is_failure else 'Medium'
        
        # Determine action
        if is_brute_force:
            action = "SSH_BRUTE_FORCE"
        elif is_failure:
            action = "SSH_FAILED"
        elif is_success:
            action = "SSH_SUCCESS"
        else:
            action = "SSH_EVENT"
        
        # Create title
        if is_brute_force:
            title = f"SSH Brute Force Attack - {source_ip or 'Unknown IP'}"
        elif is_failure:
            title = f"SSH Authentication Failure - {username or 'Unknown User'}"
        elif is_success:
            title = f"SSH Authentication Success - {username or 'Unknown User'}"
        else:
            title = "SSH Authentication Event"
        
        if is_failure or is_brute_force or (is_success and username and username.lower() in ['root', 'admin']):
            return Incident(
                title=title,
                description=description[:500],
                source_ip=source_ip,
                destination_ip=None,
                username=username,
                protocol="SSH",
                port=22,
                action=action,
                log_source="ssh",
                timestamp=timestamp,
            )
        
        return None

    def _is_failure(self, line: str) -> bool:
        """Check if line indicates SSH failure."""
        line_lower = line.lower()
        failure_patterns = [
            'failed password',
            'authentication failure',
            'invalid user',
            'user not known',
            'authentication failed',
            'permission denied',
            'connection refused',
            'pam_unix.*authentication failure',
            'bad password attempt',
            'did not receive identification',
        ]
        for pattern in failure_patterns:
            if pattern in line_lower:
                return True
        return False

    def _is_success(self, line: str) -> bool:
        """Check if line indicates SSH success."""
        line_lower = line.lower()
        success_patterns = [
            'accepted password',
            'accepted publickey',
            'session opened',
        ]
        for pattern in success_patterns:
            if pattern in line_lower:
                return True
        return False

    def _is_brute_force(self, line: str) -> bool:
        """Check if line indicates SSH brute force."""
        line_lower = line.lower()
        if 'failed password' in line_lower and 'from' in line_lower:
            return True
        if 'invalid user' in line_lower and 'from' in line_lower:
            return True
        return False

    def _extract_timestamp(self, line: str) -> datetime:
        """Extract timestamp from SSH log."""
        patterns = [
            r'(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z?)',
            r'([A-Za-z]{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})',
            r'(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})',
        ]
        
        for pattern in patterns:
            match = re.search(pattern, line)
            if match:
                timestamp_str = match.group(1)
                try:
                    if 'T' in timestamp_str:
                        return datetime.fromisoformat(timestamp_str.replace('Z', '+00:00'))
                    return datetime.strptime(timestamp_str, '%Y-%m-%d %H:%M:%S')
                except:
                    try:
                        return datetime.strptime(timestamp_str, '%b %d %H:%M:%S')
                    except:
                        continue
        
        return datetime.now()

    def _extract_ip(self, line: str) -> Optional[str]:
        """Extract IP address from SSH log."""
        ip_pattern = r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'
        match = re.search(ip_pattern, line)
        if match:
            ip = match.group(0)
            if ip not in ['127.0.0.1', '0.0.0.0']:
                return ip
        return None

    def _extract_username(self, line: str) -> Optional[str]:
        """Extract username from SSH log."""
        patterns = [
            r'[Ff]or\s+(?:invalid\s+)?user\s+([^\s]+)',
            r'[Ff]or\s+([^\s]+)\s+from',
            r'[Ii]nvalid\s+user\s+([^\s]+)',
            r'user[=:]\s*([^\s,]+)',
        ]
        
        for pattern in patterns:
            match = re.search(pattern, line, re.IGNORECASE)
            if match:
                username = match.group(1)
                username = username.strip('"\'.,;:')
                if username and username not in ['', 'from', 'for', 'to']:
                    return username
        
        return None
