import re
from datetime import datetime
from typing import Optional

from app.models.incident import Incident
from app.parsers.base_parser import BaseParser
from app.core.utils import sanitize_text


class DNSParser(BaseParser):
    """Parser for DNS logs."""
    
    SUSPICIOUS_DOMAINS = [
        'malware', 'phishing', 'c2', 'command', 'control',
        'botnet', 'exploit', 'ransom', 'trojan', 'virus',
        '.onion', '.tor', '.bit', '.top', '.xyz',
    ]

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
        
        # Extract query
        query_match = re.search(r'query[=:]\s*([^\s,]+)', line, re.IGNORECASE)
        query = query_match.group(1) if query_match else None
        
        # Check for suspicious domain
        is_suspicious = False
        if query:
            query_lower = query.lower()
            for sus in self.SUSPICIOUS_DOMAINS:
                if sus in query_lower:
                    is_suspicious = True
                    break
        
        if not is_suspicious:
            return None
        
        description = f"DNS: Suspicious Query - {query or 'Unknown'}"
        if source_ip:
            description += f" - From: {source_ip}"
        
        description = sanitize_text(description)
        
        return Incident(
            title=f"DNS: Suspicious Query Detected",
            description=description[:500],
            source_ip=source_ip,
            destination_ip=None,
            username=None,
            protocol="dns",
            port=53,
            action="DNS_Suspicious_Query",
            log_source="dns",
            timestamp=timestamp,
        )

    def _extract_timestamp(self, line: str) -> datetime:
        patterns = [
            r'(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})',
            r'(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z?)',
            r'([A-Za-z]{3}\s+\d{1,2}\s+\d{4}\s+\d{2}:\d{2}:\d{2})',
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
                        continue
        
        return datetime.now()
