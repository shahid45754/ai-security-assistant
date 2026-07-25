import re
from datetime import datetime
from typing import Optional

from app.models.incident import Incident
from app.parsers.base_parser import BaseParser
from app.core.utils import sanitize_text


class SysmonParser(BaseParser):
    """Parser for Windows Sysmon logs."""
    
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
        
        # Extract process name
        process_match = re.search(r'Image[=:]\s*([^\s,]+)', line, re.IGNORECASE)
        process = process_match.group(1) if process_match else None
        
        # Extract command line
        cmdline_match = re.search(r'CommandLine[=:]\s*(.+?)(?:\s+(?:User|PID|ProcessId|$))', line, re.IGNORECASE)
        cmdline = cmdline_match.group(1) if cmdline_match else None
        
        # Detect suspicious activity
        is_suspicious = False
        attack_type = None
        
        if process:
            process_lower = process.lower()
            if 'powershell' in process_lower:
                if cmdline and ('-enc' in cmdline.lower() or '-encodedcommand' in cmdline.lower()):
                    attack_type = 'PowerShell Abuse'
                    is_suspicious = True
            elif 'mimikatz' in process_lower:
                attack_type = 'Credential Dumping'
                is_suspicious = True
            elif 'nc' in process_lower or 'netcat' in process_lower:
                attack_type = 'Network Tool Execution'
                is_suspicious = True
            elif 'wmic' in process_lower:
                attack_type = 'WMIC Execution'
                is_suspicious = True
            elif 'schtasks' in process_lower:
                attack_type = 'Scheduled Task Creation'
                is_suspicious = True
        
        if not is_suspicious:
            return None
        
        description = f"Sysmon: {attack_type or 'Suspicious Activity'}"
        if process:
            description += f" - Process: {process}"
        if cmdline:
            description += f" - Command: {cmdline[:100]}"
        
        description = sanitize_text(description)
        
        return Incident(
            title=f"Sysmon: {attack_type or 'Suspicious Activity'}",
            description=description[:500],
            source_ip=source_ip,
            destination_ip=None,
            username=None,
            protocol="sysmon",
            port=None,
            action=f"Sysmon_{attack_type.replace(' ', '_') if attack_type else 'Suspicious'}",
            log_source="sysmon",
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
