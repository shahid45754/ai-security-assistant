
import re
from datetime import datetime
from typing import Optional

from app.models.incident import Incident
from app.parsers.base_parser import BaseParser
from app.core.utils import sanitize_text


class AuthParser(BaseParser):
    """Parser for authentication logs (SSH, FTP, HTTP auth, etc.)."""
    
    # Authentication failure patterns
    FAILURE_PATTERNS = [
        r'Failed password',
        r'authentication failure',
        r'Invalid user',
        r'User not known',
        r'authentication failed',
        r'Permission denied',
        r'Connection refused',
        r'pam_unix.*authentication failure',
        r'Bad password attempt',
        r'530 Login incorrect',
        r'331 Password required',
        r'Login failed',
        r'401 Unauthorized',
        r'403 Forbidden',
        r'sudo:.*authentication failure',
        r'su:.*authentication failure',
    ]
    
    # Success patterns
    SUCCESS_PATTERNS = [
        r'Accepted password',
        r'Accepted publickey',
        r'login:.*accepted',
        r'session opened',
        r'sudo:.*authenticated',
        r'su:.*authenticated',
    ]
    
    # Suspicious usernames
    SUSPICIOUS_USERNAMES = [
        'root', 'admin', 'administrator', 'sysadmin', 'oracle',
        'mysql', 'postgres', 'guest', 'test', 'user', 'anonymous',
        'backup', 'ftp', 'www-data', 'nobody', 'daemon',
    ]

    def parse(self, content: str) -> list[Incident]:
        """Parse authentication log content."""
        incidents = []
        
        for line in content.splitlines():
            if not line.strip():
                continue
            
            incident = self._parse_line(line)
            if incident:
                incidents.append(incident)
                
        return incidents

    def _parse_line(self, line: str) -> Optional[Incident]:
        """Parse a single authentication log line."""
        
        timestamp = self._extract_timestamp(line)
        source_ip = self._extract_ip(line)
        username = self._extract_username(line)
        
        # Detect service
        service = self._detect_service(line)
        
        # Determine if it's a failure or success
        is_failure = self._is_failure(line)
        is_success = self._is_success(line)
        is_brute_force = self._is_brute_force(line)
        is_suspicious_user = username and username.lower() in self.SUSPICIOUS_USERNAMES
        
        # Build description
        description = self._build_description(
            line, service, username, source_ip, 
            is_failure, is_success, is_brute_force, is_suspicious_user
        )
        
        # Determine severity
        severity = self._determine_severity(
            is_failure, is_brute_force, is_suspicious_user, is_success
        )
        
        # Determine action
        action = self._determine_action(
            is_failure, is_success, is_brute_force, service
        )
        
        # Determine title
        title = self._determine_title(
            service, username, source_ip, is_failure, is_success, is_brute_force
        )
        
        # Only create incident if it's suspicious
        if is_failure or is_brute_force or is_suspicious_user:
            return Incident(
                title=title,
                description=description[:500],
                source_ip=source_ip,
                destination_ip=None,
                username=username,
                protocol=service or "auth",
                port=None,
                action=action,
                log_source="auth",
                timestamp=timestamp,
            )
        
        # For successes, only create if username is suspicious
        if is_success and is_suspicious_user:
            return Incident(
                title=title,
                description=description[:500],
                source_ip=source_ip,
                destination_ip=None,
                username=username,
                protocol=service or "auth",
                port=None,
                action=action,
                log_source="auth",
                timestamp=timestamp,
            )
        
        return None

    def _detect_service(self, line: str) -> Optional[str]:
        """Detect the service (ssh, ftp, http, sudo, su)."""
        line_lower = line.lower()
        
        if 'ssh' in line_lower or 'sshd' in line_lower:
            return 'ssh'
        if 'ftp' in line_lower or 'vsftpd' in line_lower or 'proftpd' in line_lower:
            return 'ftp'
        if 'http' in line_lower or 'apache' in line_lower or 'nginx' in line_lower:
            return 'http'
        if 'sudo' in line_lower:
            return 'sudo'
        if 'su:' in line_lower:
            return 'su'
        if 'auth' in line_lower or 'authentication' in line_lower:
            return 'auth'
        
        return None

    def _is_failure(self, line: str) -> bool:
        """Check if line indicates authentication failure."""
        line_lower = line.lower()
        
        for pattern in self.FAILURE_PATTERNS:
            if re.search(pattern, line, re.IGNORECASE):
                return True
        
        failure_keywords = [
            'failed', 'failure', 'invalid', 'incorrect', 
            'denied', 'rejected', 'unauthorized', 'forbidden',
            'not found', 'unknown', 'bad', 'error'
        ]
        
        for keyword in failure_keywords:
            if keyword in line_lower:
                return True
        
        return False

    def _is_success(self, line: str) -> bool:
        """Check if line indicates authentication success."""
        line_lower = line.lower()
        
        for pattern in self.SUCCESS_PATTERNS:
            if re.search(pattern, line, re.IGNORECASE):
                return True
        
        success_keywords = [
            'accepted', 'success', 'authenticated', 'session opened',
            'approved', 'granted'
        ]
        
        for keyword in success_keywords:
            if keyword in line_lower:
                return True
        
        return False

    def _is_brute_force(self, line: str) -> bool:
        """Check if line indicates brute force attempt."""
        line_lower = line.lower()
        
        if 'failed password' in line_lower and 'from' in line_lower:
            return True
        
        return False

    def _build_description(self, line: str, service: Optional[str], 
                          username: Optional[str], source_ip: Optional[str],
                          is_failure: bool, is_success: bool, 
                          is_brute_force: bool, is_suspicious_user: bool) -> str:
        """Build incident description."""
        parts = []
        
        if service:
            parts.append(f"Service: {service.upper()}")
        
        if username:
            parts.append(f"User: {username}")
        
        if source_ip:
            parts.append(f"From: {source_ip}")
        
        if is_failure:
            parts.append("Status: FAILED")
        elif is_success:
            parts.append("Status: SUCCESS")
        
        if is_brute_force:
            parts.append("⚠️ Brute Force Attempt")
        
        if is_suspicious_user:
            parts.append("⚠️ Suspicious Username")
        
        if len(line) < 200:
            parts.append(f"Message: {line}")
        else:
            parts.append(f"Message: {line[:150]}...")
        
        return " | ".join(parts)

    def _determine_severity(self, is_failure: bool, is_brute_force: bool,
                          is_suspicious_user: bool, is_success: bool) -> str:
        """Determine severity of the incident."""
        if is_brute_force:
            return 'Critical'
        if is_suspicious_user and is_success:
            return 'Critical'
        if is_suspicious_user and is_failure:
            return 'High'
        if is_failure:
            return 'Medium'
        return 'Medium'

    def _determine_action(self, is_failure: bool, is_success: bool,
                         is_brute_force: bool, service: Optional[str]) -> str:
        """Determine action for the incident."""
        service_prefix = service.upper() if service else 'AUTH'
        
        if is_brute_force:
            return f"{service_prefix}_BRUTE_FORCE"
        elif is_failure:
            return f"{service_prefix}_FAILED"
        elif is_success:
            return f"{service_prefix}_SUCCESS"
        else:
            return f"{service_prefix}_EVENT"

    def _determine_title(self, service: Optional[str], username: Optional[str],
                        source_ip: Optional[str], is_failure: bool, 
                        is_success: bool, is_brute_force: bool) -> str:
        """Determine title for the incident."""
        parts = []
        
        if is_brute_force:
            parts.append("Brute Force Attack")
        elif is_failure:
            parts.append("Authentication Failure")
        elif is_success:
            parts.append("Authentication Success")
        
        if service:
            parts.append(f"({service.upper()})")
        
        if username:
            parts.append(f"User: {username}")
        
        if source_ip:
            parts.append(f"From: {source_ip}")
        
        return " - ".join(parts)

    def _extract_timestamp(self, line: str) -> datetime:
        """Extract timestamp from log line."""
        patterns = [
            r'(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z?)',
            r'([A-Za-z]{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})',
            r'([A-Za-z]{3}\s+\d{1,2}\s+\d{4}\s+\d{2}:\d{2}:\d{2})',
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
                        try:
                            return datetime.strptime(timestamp_str, '%b %d %Y %H:%M:%S')
                        except:
                            continue
        
        return datetime.now()

    def _extract_ip(self, line: str) -> Optional[str]:
        """Extract IP address from log line."""
        ip_pattern = r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'
        match = re.search(ip_pattern, line)
        if match:
            ip = match.group(0)
            if ip not in ['127.0.0.1', '0.0.0.0']:
                return ip
        return None

    def _extract_username(self, line: str) -> Optional[str]:
        """Extract username from log line."""
        patterns = [
            r'[Ff]or\s+(?:invalid\s+)?user\s+([^\s]+)',
            r'[Ff]or\s+([^\s]+)\s+from',
            r'[Ii]nvalid\s+user\s+([^\s]+)',
            r'user[=:]\s*([^\s,]+)',
            r'sudo:\s+([^\s]+)\s*:',
            r'su:\s*\(to\s+([^\s]+)\)',
            r'username[=:]\s*([^\s,]+)',
        ]
        
        for pattern in patterns:
            match = re.search(pattern, line, re.IGNORECASE)
            if match:
                username = match.group(1)
                username = username.strip('"\'.,;:')
                if username and username not in ['', 'from', 'for', 'to']:
                    return username
        
        return None

