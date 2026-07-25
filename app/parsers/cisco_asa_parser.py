import re
from datetime import datetime
from typing import Optional

from app.models.incident import Incident
from app.parsers.base_parser import BaseParser
from app.core.utils import sanitize_text


class CiscoASAParser(BaseParser):
    """Parser for Cisco ASA firewall logs."""
    
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
        
        # Detect ASA event type
        event_type = self._detect_event_type(line)
        
        if not event_type:
            return None
        
        # Build description
        description = f"Cisco ASA: {event_type} - {line[:200]}"
        description = sanitize_text(description)
        
        # Determine action
        action = f"ASA_{event_type.replace(' ', '_')}"
        
        # Create incident for any suspicious event
        return Incident(
            title=f"Cisco ASA: {event_type}",
            description=description[:500],
            source_ip=source_ip,
            destination_ip=None,
            username=None,
            protocol="firewall",
            port=None,
            action=action,
            log_source="cisco_asa",
            timestamp=timestamp,
        )

    def _detect_event_type(self, line: str) -> Optional[str]:
        line_lower = line.lower()
        
        # Check for Deny events
        if 'deny' in line_lower:
            if 'tcp' in line_lower:
                return 'Denied TCP Traffic'
            elif 'udp' in line_lower:
                return 'Denied UDP Traffic'
            elif 'icmp' in line_lower:
                return 'Denied ICMP Traffic'
            return 'Denied Traffic'
        
        # Check for reverse path check
        if 'reverse path' in line_lower or 'rp check' in line_lower:
            return 'Reverse Path Check Failed'
        
        # Check for failover
        if 'failover' in line_lower:
            return 'Failover Event'
        
        # Check for unauthorized
        if 'unauthorized' in line_lower:
            return 'Unauthorized Access'
        
        # Check for forbidden
        if 'forbidden' in line_lower:
            return 'Forbidden Access'
        
        # Check for built connection
        if 'built' in line_lower and 'connection' in line_lower:
            return 'Connection Built'
        
        # Check for teardown
        if 'teardown' in line_lower and 'connection' in line_lower:
            return 'Connection Teardown'
        
        # Check for user login
        if 'user' in line_lower and 'logged' in line_lower:
            return 'User Login'
        
        # Check for no matching connection
        if 'no matching connection' in line_lower:
            return 'No Matching Connection'
        
        # Default for any ASA log
        if '%asa-' in line_lower:
            # Extract the message number
            msg_match = re.search(r'%ASA-(\d+)-(\d+)', line_lower)
            if msg_match:
                return f'ASA Event {msg_match.group(1)}-{msg_match.group(2)}'
            return 'ASA Event'
        
        return None

    def _extract_timestamp(self, line: str) -> datetime:
        patterns = [
            r'([A-Za-z]{3}\s+\d{1,2}\s+\d{4}\s+\d{2}:\d{2}:\d{2})',
            r'([A-Za-z]{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})',
            r'(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})',
        ]
        
        for pattern in patterns:
            match = re.search(pattern, line)
            if match:
                timestamp_str = match.group(1)
                try:
                    return datetime.strptime(timestamp_str, '%b %d %Y %H:%M:%S')
                except:
                    try:
                        return datetime.strptime(timestamp_str, '%b %d %H:%M:%S')
                    except:
                        try:
                            return datetime.strptime(timestamp_str, '%Y-%m-%d %H:%M:%S')
                        except:
                            continue
        
        return datetime.now()

    def _extract_ip(self, line: str) -> Optional[str]:
        ip_pattern = r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'
        match = re.search(ip_pattern, line)
        if match:
            return match.group(0)
        return None
