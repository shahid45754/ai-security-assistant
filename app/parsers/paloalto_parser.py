import re
from datetime import datetime
from typing import Optional

from app.models.incident import Incident
from app.parsers.base_parser import BaseParser
from app.core.utils import sanitize_text


class PaloAltoParser(BaseParser):
    """Parser for Palo Alto firewall logs."""
    
    def parse(self, content: str) -> list[Incident]:
        """Parse Palo Alto log content."""
        incidents = []
        
        for line in content.splitlines():
            if not line.strip():
                continue
            
            incident = self._parse_line(line)
            if incident:
                incidents.append(incident)
                
        return incidents

    def _parse_line(self, line: str) -> Optional[Incident]:
        """Parse a single Palo Alto log line."""
        
        timestamp = self._extract_timestamp(line)
        source_ip = self._extract_ip(line)
        
        # Detect event type
        event_type = self._detect_event_type(line)
        
        if not event_type:
            # Try to detect from any line with GlobalProtect or Palo Alto
            if 'GlobalProtect' in line or 'Palo Alto' in line or 'PAN-OS' in line:
                event_type = 'GlobalProtect Event'
            else:
                return None
        
        # Build description
        description = f"Palo Alto: {event_type} - {line[:200]}"
        description = sanitize_text(description)
        
        # Determine action
        action = f"PaloAlto_{event_type.replace(' ', '_')}"
        
        # Extract username if present
        username = None
        user_match = re.search(r'user[=:]\s*([^\s,]+)', line, re.IGNORECASE)
        if user_match:
            username = user_match.group(1)
        if not username:
            user_match = re.search(r'for\s+user\s+([^\s]+)', line, re.IGNORECASE)
            if user_match:
                username = user_match.group(1)
        
        # Create incident for any Palo Alto event
        return Incident(
            title=f"Palo Alto: {event_type}",
            description=description[:500],
            source_ip=source_ip,
            destination_ip=None,
            username=username,
            protocol="firewall",
            port=None,
            action=action,
            log_source="paloalto",
            timestamp=timestamp,
        )

    def _detect_event_type(self, line: str) -> Optional[str]:
        """Detect event type from Palo Alto log."""
        line_lower = line.lower()
        
        # Check for GlobalProtect events
        if 'globalprotect' in line_lower:
            if 'authentication' in line_lower and 'failed' in line_lower:
                return 'GlobalProtect Authentication Failed'
            if 'connection' in line_lower and 'established' in line_lower:
                return 'GlobalProtect Connection Established'
            if 'connection' in line_lower and 'closed' in line_lower:
                return 'GlobalProtect Connection Closed'
            if 'user' in line_lower and 'logged' in line_lower:
                return 'GlobalProtect User Login'
            return 'GlobalProtect Event'
        
        # Check for firewall events
        if 'block' in line_lower or 'deny' in line_lower:
            return 'Blocked Traffic'
        if 'allow' in line_lower or 'permit' in line_lower:
            return 'Allowed Traffic'
        if 'threat' in line_lower:
            return 'Threat Detected'
        if 'vulnerability' in line_lower:
            return 'Vulnerability Detected'
        if 'spyware' in line_lower:
            return 'Spyware Detected'
        if 'virus' in line_lower:
            return 'Virus Detected'
        if 'url' in line_lower and 'blocked' in line_lower:
            return 'URL Blocked'
        
        # Check for authentication
        if 'authentication' in line_lower:
            if 'failed' in line_lower:
                return 'Authentication Failed'
            if 'success' in line_lower:
                return 'Authentication Success'
            return 'Authentication Event'
        
        # Check for Palo Alto specific patterns
        if 'pan-os' in line_lower or 'palo alto' in line_lower:
            return 'Palo Alto Event'
        
        return None

    def _extract_timestamp(self, line: str) -> datetime:
        """Extract timestamp from Palo Alto log."""
        patterns = [
            r'(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})',
            r'([A-Za-z]{3}\s+\d{1,2}\s+\d{4}\s+\d{2}:\d{2}:\d{2})',
            r'([A-Za-z]{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})',
        ]
        
        for pattern in patterns:
            match = re.search(pattern, line)
            if match:
                timestamp_str = match.group(1)
                try:
                    return datetime.strptime(timestamp_str, '%Y-%m-%d %H:%M:%S')
                except:
                    try:
                        return datetime.strptime(timestamp_str, '%b %d %Y %H:%M:%S')
                    except:
                        try:
                            return datetime.strptime(timestamp_str, '%b %d %H:%M:%S')
                        except:
                            continue
        
        return datetime.now()

    def _extract_ip(self, line: str) -> Optional[str]:
        """Extract IP address from Palo Alto log."""
        ip_pattern = r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'
        match = re.search(ip_pattern, line)
        if match:
            return match.group(0)
        return None
