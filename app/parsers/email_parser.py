import re
from datetime import datetime
from typing import Optional

from app.models.incident import Incident
from app.parsers.base_parser import BaseParser
from app.core.utils import sanitize_text


class EmailParser(BaseParser):
    """Parser for email logs."""
    
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
        from_match = re.search(r'From:\s*([^\s]+)', line, re.IGNORECASE)
        to_match = re.search(r'To:\s*([^\s]+)', line, re.IGNORECASE)
        subject_match = re.search(r'Subject:\s*([^,\n]+)', line, re.IGNORECASE)
        attachment_match = re.search(r'Attachment:\s*([^\s,]+)', line, re.IGNORECASE)
        
        spf_match = re.search(r'SPF:\s*(\S+)', line, re.IGNORECASE)
        dkim_match = re.search(r'DKIM:\s*(\S+)', line, re.IGNORECASE)
        dmarc_match = re.search(r'DMARC:\s*(\S+)', line, re.IGNORECASE)
        
        from_addr = from_match.group(1) if from_match else None
        to_addr = to_match.group(1) if to_match else None
        subject = subject_match.group(1) if subject_match else None
        attachment = attachment_match.group(1) if attachment_match else None
        
        spf = spf_match.group(1) if spf_match else None
        dkim = dkim_match.group(1) if dkim_match else None
        dmarc = dmarc_match.group(1) if dmarc_match else None
        
        # Check for threats
        threat_type = []
        auth_failures = 0
        
        if spf and spf.upper() in ['FAIL', 'FAILED', 'SOFTFAIL']:
            auth_failures += 1
            threat_type.append('SPF Failure')
        if dkim and dkim.upper() in ['FAIL', 'FAILED']:
            auth_failures += 1
            threat_type.append('DKIM Failure')
        if dmarc and dmarc.upper() in ['FAIL', 'FAILED']:
            auth_failures += 1
            threat_type.append('DMARC Failure')
        
        if subject:
            suspicious_subjects = ['password', 'reset', 'urgent', 'verify', 'account', 'invoice', 'payment']
            for sus in suspicious_subjects:
                if sus in subject.lower():
                    threat_type.append('Suspicious Subject')
                    break
        
        if attachment:
            suspicious_extensions = ['.exe', '.scr', '.bat', '.com', '.vbs', '.js', '.jar', '.msi']
            for ext in suspicious_extensions:
                if attachment.lower().endswith(ext):
                    threat_type.append('Suspicious Attachment')
                    break
        
        if not threat_type:
            return None
        
        description = f"Email: {', '.join(threat_type)}"
        if from_addr:
            description += f" - From: {from_addr}"
        if to_addr:
            description += f" - To: {to_addr}"
        if subject:
            description += f" - Subject: {subject}"
        if attachment:
            description += f" - Attachment: {attachment}"
        
        description = sanitize_text(description)
        
        severity = 'Critical' if auth_failures >= 2 or 'Suspicious Attachment' in threat_type else 'High'
        
        return Incident(
            title=f"Email Threat: {', '.join(threat_type)}",
            description=description[:500],
            source_ip=None,
            destination_ip=None,
            username=from_addr,
            protocol="email",
            port=None,
            action=f"Email_{'|'.join(threat_type)}",
            log_source="email",
            timestamp=datetime.now(),
        )
