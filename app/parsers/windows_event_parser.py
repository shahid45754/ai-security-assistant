import re
from datetime import datetime
from typing import Optional

from app.models.incident import Incident
from app.parsers.base_parser import BaseParser
from app.core.utils import sanitize_text


class WindowsEventParser(BaseParser):
    """Parser for Windows Event Logs."""
    
    # Common Windows Event IDs and their descriptions
    EVENT_IDS = {
        '4624': 'Successful Logon',
        '4625': 'Failed Logon',
        '4634': 'Logoff',
        '4648': 'Explicit Credential Logon',
        '4672': 'Special Privileges Assigned',
        '4688': 'Process Creation',
        '4689': 'Process Termination',
        '4697': 'Service Installation',
        '4698': 'Scheduled Task Creation',
        '4720': 'User Account Created',
        '4722': 'User Account Enabled',
        '4725': 'User Account Disabled',
        '4726': 'User Account Deleted',
        '4728': 'User Added to Global Group',
        '4729': 'User Removed from Global Group',
        '4732': 'User Added to Local Group',
        '4733': 'User Removed from Local Group',
        '4740': 'Account Lockout',
        '4767': 'Account Unlocked',
        '4776': 'Credential Validation',
        '4906': 'Security Log Stopped',
        '4907': 'Audit Settings Changed',
        '4912': 'Audit Policy Changed',
        '4946': 'Firewall Rule Added',
        '4947': 'Firewall Rule Modified',
        '4948': 'Firewall Rule Deleted',
        '5025': 'Firewall Service Stopped',
        '5140': 'Network Share Accessed',
        '5152': 'Firewall Blocked',
        '5154': 'Firewall Allowed',
        '5156': 'Firewall Connection',
        '5157': 'Firewall Blocked',
        '5379': 'Credential Manager Access',
        '4769': 'Kerberos Service Ticket Requested',
    }

    def parse(self, content: str) -> list[Incident]:
        """Parse Windows Event log content."""
        incidents = []
        
        for line in content.splitlines():
            if not line.strip():
                continue
            
            incident = self._parse_line(line)
            if incident:
                incidents.append(incident)
                
        return incidents

    def _parse_line(self, line: str) -> Optional[Incident]:
        """Parse a single Windows event log line."""
        
        # Parse format: EventID=4625 Account=root IP=192.168.1.70 Status=FAILED
        event_id_match = re.search(r'EventID[=:]\s*(\d+)', line, re.IGNORECASE)
        account_match = re.search(r'Account[=:]\s*([^\s]+)', line, re.IGNORECASE)
        ip_match = re.search(r'IP[=:]\s*([^\s]+)', line, re.IGNORECASE)
        status_match = re.search(r'Status[=:]\s*([^\s]+)', line, re.IGNORECASE)
        
        if event_id_match:
            event_id = event_id_match.group(1)
        else:
            # Try to find standalone event ID
            for word in line.split():
                if word.isdigit() and len(word) == 4 and word.startswith('4'):
                    event_id = word
                    break
            else:
                return None
        
        username = account_match.group(1) if account_match else None
        source_ip = ip_match.group(1) if ip_match else None
        status = status_match.group(1) if status_match else None
        
        # Get event description
        event_name = self.EVENT_IDS.get(event_id, f'Event {event_id}')
        description = f"{event_name} - Account: {username or 'Unknown'}, IP: {source_ip or 'Unknown'}, Status: {status or 'Unknown'}"
        description = sanitize_text(description)
        
        # Determine severity
        severity = self._get_severity(event_id, status)
        
        # Determine action
        action = f"Event_{event_id}"
        
        return Incident(
            title=f"Windows Event {event_id} - {event_name}",
            description=description[:500],
            source_ip=source_ip,
            destination_ip=None,
            username=username,
            protocol="windows",
            port=None,
            action=action,
            log_source="windows",
            timestamp=datetime.now(),
        )

    def _get_severity(self, event_id: str, status: Optional[str]) -> str:
        """Get severity based on event ID."""
        severity_map = {
            '4625': 'High',
            '4648': 'High',
            '4672': 'High',
            '4697': 'High',
            '4698': 'High',
            '4720': 'High',
            '4740': 'Medium',
            '4776': 'High',
            '4906': 'Critical',
            '4907': 'Critical',
            '4912': 'Critical',
            '5025': 'High',
            '5152': 'High',
            '5157': 'High',
        }
        
        if status and status.upper() == 'FAILED':
            return 'High'
        
        return severity_map.get(event_id, 'Medium')
