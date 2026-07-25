import re
from datetime import datetime
from typing import Optional

from app.models.incident import Incident
from app.parsers.base_parser import BaseParser
from app.core.utils import sanitize_text


class FortinetParser(BaseParser):
    """Parser for Fortinet firewall logs."""
    
    def parse(self, content: str) -> list[Incident]:
        incidents = []
        
        for line in content.splitlines():
            if not line.strip():
                continue
            
            incident = self._parse_line(line)
            if incident:
                incidents.append(incident)
                
        return incidents

    def _parse_line(self, line: str) -> Optional[Incident]:
        # Extract fields from Fortinet format
        timestamp = self._extract_timestamp(line)
        source_ip = self._extract_ip(line)
        
        # Detect attack type
        attack_type = self._detect_attack(line)
        severity = self._detect_severity(line)
        
        if not attack_type:
            return None
        
        # Build description
        description = f"Fortinet: {attack_type} - {line[:200]}"
        description = sanitize_text(description)
        
        # Determine action
        action = f"Fortinet_{attack_type.replace(' ', '_')}"
        
        return Incident(
            title=f"Fortinet: {attack_type}",
            description=description[:500],
            source_ip=source_ip,
            destination_ip=None,
            username=None,
            protocol="firewall",
            port=None,
            action=action,
            log_source="fortinet",
            timestamp=timestamp,
        )

    def _detect_attack(self, line: str) -> Optional[str]:
        line_lower = line.lower()
        
        if 'sql injection' in line_lower or 'sqli' in line_lower:
            return 'SQL Injection'
        if 'xss' in line_lower or 'cross-site' in line_lower:
            return 'XSS Attack'
        if 'ssh' in line_lower and 'brute' in line_lower:
            return 'SSH Brute Force'
        if 'rce' in line_lower or 'remote code' in line_lower:
            return 'RCE Attempt'
        if 'dns' in line_lower and 'tunneling' in line_lower:
            return 'DNS Tunneling'
        if 'blocked' in line_lower and 'attack' in line_lower:
            return 'Attack Blocked'
        if 'path traversal' in line_lower or 'directory traversal' in line_lower:
            return 'Path Traversal'
        if 'command injection' in line_lower:
            return 'Command Injection'
        
        return None

    def _detect_severity(self, line: str) -> str:
        line_lower = line.lower()
        
        if 'critical' in line_lower:
            return 'Critical'
        if 'high' in line_lower:
            return 'High'
        if 'medium' in line_lower:
            return 'Medium'
        if 'low' in line_lower:
            return 'Low'
        
        if 'blocked' in line_lower:
            return 'High'
        
        return 'Medium'

    def _extract_timestamp(self, line: str) -> datetime:
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
