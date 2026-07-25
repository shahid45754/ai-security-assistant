import re
from datetime import datetime
from typing import Optional

from app.models.incident import Incident
from app.parsers.base_parser import BaseParser
from app.core.utils import sanitize_text


class SyslogParser(BaseParser):
    """Parser for generic syslog messages."""
    
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
        
        # Detect severity
        severity = 'Medium'
        if 'error' in line.lower() or 'critical' in line.lower():
            severity = 'High'
        elif 'warning' in line.lower():
            severity = 'Medium'
        elif 'info' in line.lower():
            severity = 'Low'
        
        # Check for suspicious keywords
        suspicious_keywords = ['attack', 'malware', 'virus', 'trojan', 'ransom', 'exploit', 'unauthorized']
        is_suspicious = False
        for keyword in suspicious_keywords:
            if keyword in line.lower():
                is_suspicious = True
                break
        
        if not is_suspicious:
            return None
        
        description = f"Syslog: {line[:300]}"
        description = sanitize_text(description)
        
        return Incident(
            title=f"Syslog: Suspicious Event Detected",
            description=description[:500],
            source_ip=source_ip,
            destination_ip=None,
            username=None,
            protocol="syslog",
            port=None,
            action="Syslog_Suspicious",
            log_source="syslog",
            timestamp=timestamp,
        )

    def _extract_timestamp(self, line: str) -> datetime:
        patterns = [
            r'([A-Za-z]{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})',
            r'(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})',
            r'([A-Za-z]{3}\s+\d{1,2}\s+\d{4}\s+\d{2}:\d{2}:\d{2})',
        ]
        
        for pattern in patterns:
            match = re.search(pattern, line)
            if match:
                timestamp_str = match.group(1)
                try:
                    return datetime.strptime(timestamp_str, '%b %d %H:%M:%S')
                except:
                    try:
                        return datetime.strptime(timestamp_str, '%Y-%m-%d %H:%M:%S')
                    except:
                        try:
                            return datetime.strptime(timestamp_str, '%b %d %Y %H:%M:%S')
                        except:
                            continue
        
        return datetime.now()
