import re
from datetime import datetime
from typing import Optional

from app.models.incident import Incident
from app.parsers.base_parser import BaseParser
from app.core.utils import sanitize_text


class OsqueryParser(BaseParser):
    """Parser for Osquery logs."""
    
    SUSPICIOUS_PROCESSES = {
        'mimikatz': 'Credential Dumping Tool',
        'nc': 'Netcat - Network Tool',
        'ncat': 'Netcat - Network Tool',
        'powershell': 'PowerShell',
        'cmd': 'Command Prompt',
        'wmic': 'WMIC - Often used for lateral movement',
        'wscript': 'Windows Script Host',
        'cscript': 'Windows Script Host',
        'schtasks': 'Scheduled Tasks',
        'net': 'Net Command',
        'whoami': 'User Enumeration',
        'ipconfig': 'Network Reconnaissance',
        'ping': 'Network Reconnaissance',
        'nslookup': 'DNS Reconnaissance',
        'netstat': 'Network Monitoring',
        'tasklist': 'Process Enumeration',
        'systeminfo': 'System Enumeration',
        'rundll32': 'DLL Execution',
        'regsvr32': 'DLL Registration',
        'mshta': 'Microsoft HTML Application',
        'curl': 'Data Transfer Tool',
        'wget': 'Data Transfer Tool',
        'python': 'Python',
        'bash': 'Bash Shell',
        'sh': 'Shell',
    }

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
        process_match = re.search(r'process_name[=:]\s*([^\s,]+)', line, re.IGNORECASE)
        if not process_match:
            return None
        
        process_name = process_match.group(1)
        pid_match = re.search(r'pid[=:]\s*(\d+)', line, re.IGNORECASE)
        pid = pid_match.group(1) if pid_match else None
        user_match = re.search(r'user[=:]\s*([^\s,]+)', line, re.IGNORECASE)
        user = user_match.group(1) if user_match else None
        
        process_lower = process_name.lower()
        process_base = process_lower
        for ext in ['.exe', '.com', '.scr', '.bat', '.cmd', '.ps1', '.sh', '.py']:
            if process_base.endswith(ext):
                process_base = process_base[:-len(ext)]
                break
        
        threat_type = None
        if process_base in self.SUSPICIOUS_PROCESSES:
            threat_type = self.SUSPICIOUS_PROCESSES[process_base]
        
        if not threat_type:
            if 'mimikatz' in process_lower:
                threat_type = 'Credential Dumping'
            elif 'nc' in process_lower and ('-e' in process_lower or '-c' in process_lower):
                threat_type = 'Reverse Shell'
            elif 'powershell' in process_lower:
                if '-enc' in process_lower or '-encodedcommand' in process_lower:
                    threat_type = 'PowerShell Abuse'
                elif 'bypass' in process_lower:
                    threat_type = 'PowerShell Bypass'
            else:
                return None
        
        description = f"Osquery: {threat_type} - Process: {process_name}"
        if pid:
            description += f" (PID: {pid})"
        if user:
            description += f" - User: {user}"
        
        description = sanitize_text(description)
        
        severity = 'Critical' if threat_type in ['Credential Dumping', 'Reverse Shell'] else 'High'
        
        return Incident(
            title=f"Osquery: {threat_type} - {process_name}",
            description=description[:500],
            source_ip=None,
            destination_ip=None,
            username=user,
            protocol="osquery",
            port=None,
            action=f"Process_{process_name}",
            log_source="osquery",
            timestamp=datetime.now(),
        )
