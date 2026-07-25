import re
from datetime import datetime
from typing import Optional

from app.models.incident import Incident
from app.parsers.base_parser import BaseParser
from app.core.utils import sanitize_text


class ZeekParser(BaseParser):
    """Parser for Zeek (formerly Bro) network logs."""
    
    def parse(self, content: str) -> list[Incident]:
        """Parse Zeek log content."""
        incidents = []
        
        for line in content.splitlines():
            if not line.strip() or line.startswith('#'):
                continue
            
            incident = self._parse_line(line)
            if incident:
                incidents.append(incident)
                
        return incidents

    def _parse_line(self, line: str) -> Optional[Incident]:
        """Parse a single Zeek log line."""
        
        # Parse format: IP METHOD URL PROTOCOL STATUS_CODE
        parts = line.strip().split()
        
        if len(parts) < 4:
            return None
        
        # Extract fields
        source_ip = parts[0]
        method = parts[1].upper() if len(parts) > 1 else 'UNKNOWN'
        path = parts[2] if len(parts) > 2 else '/'
        protocol = parts[3] if len(parts) > 3 else 'HTTP/1.1'
        status_code = parts[4] if len(parts) > 4 else ''
        
        # Detect attack type
        attack_type = self._detect_attack(path, method, status_code)
        
        # If no attack type, skip
        if not attack_type:
            return None
        
        # Build description
        description = f"{method} {path} - Status: {status_code or 'Unknown'}"
        description = f"{attack_type} - {description}"
        description = sanitize_text(description)
        
        # Determine severity
        severity = 'High' if attack_type else 'Medium'
        
        # Create action
        action = f"Zeek_{attack_type.replace(' ', '_')}"
        
        return Incident(
            title=f"Zeek: {attack_type} - {path[:50]}",
            description=description[:500],
            source_ip=source_ip,
            destination_ip=None,
            username=None,
            protocol=protocol,
            port=80 if 'HTTP' in protocol else 443,
            action=action,
            log_source="zeek",
            timestamp=datetime.now(),
        )

    def _detect_attack(self, path: str, method: str, status_code: str) -> Optional[str]:
        """Detect attack type from path and method."""
        path_lower = path.lower()
        
        # Directory Traversal
        if any(x in path_lower for x in ['../', '/etc/passwd', '/etc/shadow', 'boot.ini']):
            return 'Directory Traversal'
        
        # SQL Injection
        if any(x in path_lower for x in ['union select', 'or 1=1', 'information_schema']):
            return 'SQL Injection'
        
        # XSS
        if any(x in path_lower for x in ['<script', 'alert(', 'onerror=']):
            return 'Cross Site Scripting'
        
        # Command Injection
        if any(x in path_lower for x in ['cmd=', 'exec=', 'system=']):
            return 'Command Injection'
        
        # Admin Access
        if any(x in path_lower for x in ['/admin', '/wp-admin', '/phpmyadmin']):
            return 'Admin Access'
        
        # Access Denied
        if status_code == '403':
            return 'Access Denied'
        
        # Scanning/Recon
        if status_code == '404':
            return 'Scanning Activity'
        
        return None
