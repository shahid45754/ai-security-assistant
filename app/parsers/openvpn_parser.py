import re
from datetime import datetime
from typing import Optional

from app.models.incident import Incident
from app.parsers.base_parser import BaseParser
from app.core.utils import sanitize_text


class OpenVPNParser(BaseParser):
    """Parser for OpenVPN logs."""
    
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
        username = self._extract_username(line)
        
        event_type = self._detect_event_type(line)
        severity = self._detect_severity(line)
        
        if not event_type:
            return None
        
        description = f"OpenVPN: {event_type}"
        if username:
            description += f" - User: {username}"
        if source_ip:
            description += f" - From: {source_ip}"
        description += f" - {line[:100]}"
        
        description = sanitize_text(description)
        
        if severity in ['High', 'Critical'] or 'failed' in event_type.lower():
            return Incident(
                title=f"OpenVPN: {event_type}",
                description=description[:500],
                source_ip=source_ip,
                destination_ip=None,
                username=username,
                protocol="openvpn",
                port=None,
                action=f"OpenVPN_{event_type.replace(' ', '_')}",
                log_source="openvpn",
                timestamp=timestamp,
            )
        
        return None

    def _detect_event_type(self, line: str) -> Optional[str]:
        line_lower = line.lower()
        
        if 'authentication failed' in line_lower or 'auth failed' in line_lower:
            return 'Authentication Failed'
        if 'connection refused' in line_lower:
            return 'Connection Refused'
        if 'connection established' in line_lower or 'client connected' in line_lower:
            return 'Connection Established'
        if 'connection closed' in line_lower or 'client disconnected' in line_lower:
            return 'Connection Closed'
        if 'certificate' in line_lower:
            if 'expired' in line_lower:
                return 'Certificate Expired'
            if 'revoked' in line_lower:
                return 'Certificate Revoked'
            return 'Certificate Error'
        if 'timeout' in line_lower:
            return 'Connection Timeout'
        if 'replay' in line_lower:
            return 'Replay Attack Detected'
        
        return None

    def _detect_severity(self, line: str) -> str:
        line_lower = line.lower()
        
        if 'authentication failed' in line_lower or 'auth failed' in line_lower:
            return 'High'
        if 'certificate' in line_lower and ('expired' in line_lower or 'revoked' in line_lower):
            return 'High'
        if 'replay' in line_lower:
            return 'Critical'
        if 'error' in line_lower:
            return 'High'
        if 'warning' in line_lower:
            return 'Medium'
        
        return 'Low'

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
