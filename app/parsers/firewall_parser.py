import re
from datetime import datetime
from typing import Optional

from app.models.incident import Incident
from app.parsers.base_parser import BaseParser
from app.core.utils import sanitize_text


class FirewallParser(BaseParser):
    """Parser for generic firewall logs."""
    
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
        timestamp = self._extract_timestamp(line)
        source_ip = self._extract_ip(line)
        
        # Detect action
        action = None
        if 'block' in line.lower() or 'deny' in line.lower():
            action = 'BLOCKED'
        elif 'allow' in line.lower() or 'permit' in line.lower():
            action = 'ALLOWED'
        elif 'drop' in line.lower():
            action = 'DROPPED'
        elif 'reject' in line.lower():
            action = 'REJECTED'
        
        if not action:
            return None
        
        description = f"Firewall: Traffic {action} - {line[:200]}"
        description = sanitize_text(description)
        
        severity = 'High' if action in ['BLOCKED', 'DROPPED', 'REJECTED'] else 'Low'
        
        return Incident(
            title=f"Firewall: Traffic {action}",
            description=description[:500],
            source_ip=source_ip,
            destination_ip=None,
            username=None,
            protocol="firewall",
            port=None,
            action=f"Firewall_{action}",
            log_source="firewall",
            timestamp=timestamp,
        )

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
