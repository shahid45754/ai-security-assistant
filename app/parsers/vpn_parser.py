import re
from datetime import datetime
from typing import Optional

from app.models.incident import Incident
from app.parsers.base_parser import BaseParser
from app.core.utils import sanitize_text


class VPNParser(BaseParser):
    """Parser for VPN logs."""
    
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
        
        # Extract fields
        user_match = re.search(r'user[=:]\s*([^\s]+)', line, re.IGNORECASE)
        username = user_match.group(1) if user_match else None
        
        ip_match = re.search(r'ip[=:]\s*([^\s]+)', line, re.IGNORECASE)
        source_ip = ip_match.group(1) if ip_match else None
        
        status = 'UNKNOWN'
        if 'FAILED' in line or 'failed' in line:
            status = 'FAILED'
        elif 'SUCCESS' in line or 'success' in line:
            status = 'SUCCESS'
        
        # Detect attack type
        if status == 'FAILED' and 'LOGIN' in line:
            attack_type = 'VPN Login Failure'
            
            # Check for brute force pattern
            if 'multiple' in line.lower() or 'repeated' in line.lower():
                attack_type = 'VPN Brute Force'
        elif status == 'SUCCESS' and 'LOGIN' in line:
            attack_type = 'VPN Login Success'
        else:
            return None
        
        description = f"VPN: {attack_type}"
        if username:
            description += f" - User: {username}"
        if source_ip:
            description += f" - From: {source_ip}"
        description += f" - Status: {status}"
        
        description = sanitize_text(description)
        
        severity = 'Critical' if 'Brute Force' in attack_type else 'High' if status == 'FAILED' else 'Medium'
        
        return Incident(
            title=f"VPN: {attack_type}",
            description=description[:500],
            source_ip=source_ip,
            destination_ip=None,
            username=username,
            protocol="vpn",
            port=None,
            action=f"VPN_{attack_type.replace(' ', '_')}",
            log_source="vpn",
            timestamp=timestamp,
        )

    def _extract_timestamp(self, line: str) -> datetime:
        patterns = [
            r'(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})',
            r'(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z?)',
            r'([A-Za-z]{3}\s+\d{1,2}\s+\d{4}\s+\d{2}:\d{2}:\d{2})',
            r'([A-Za-z]{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})',
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
                        return datetime.strptime(timestamp_str, '%b %d %Y %H:%M:%S')
                    except:
                        try:
                            return datetime.strptime(timestamp_str, '%b %d %H:%M:%S')
                        except:
                            continue
        
        return datetime.now()
