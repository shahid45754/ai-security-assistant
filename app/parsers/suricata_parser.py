
import json
import re
from datetime import datetime
from typing import Optional

from app.models.incident import Incident
from app.parsers.base_parser import BaseParser
from app.core.utils import sanitize_text


class SuricataParser(BaseParser):
    """Parser for Suricata IDS/IPS logs."""
    
    def parse(self, content: str) -> list[Incident]:
        """Parse Suricata log content."""
        incidents = []
        
        for line in content.splitlines():
            if not line.strip():
                continue
            
            incident = self._parse_line(line)
            if incident:
                incidents.append(incident)
                
        return incidents

    def _parse_line(self, line: str) -> Optional[Incident]:
        """Parse a single Suricata log line."""
        
        # Try JSON format first
        if line.strip().startswith('{'):
            return self._parse_json_line(line)
        
        # Try legacy format
        return self._parse_legacy_line(line)

    def _parse_json_line(self, line: str) -> Optional[Incident]:
        """Parse Suricata JSON format."""
        try:
            data = json.loads(line)
        except:
            return None
        
        # Check if this is an alert
        if 'alert' not in data:
            return None
        
        alert = data.get('alert', {})
        if isinstance(alert, str):
            return None
        
        # Extract fields
        timestamp_str = data.get('timestamp', '')
        try:
            timestamp = datetime.fromisoformat(timestamp_str.replace('Z', '+00:00'))
        except:
            timestamp = datetime.now()
        
        source_ip = data.get('src_ip', data.get('source_ip', ''))
        dest_ip = data.get('dest_ip', data.get('destination_ip', ''))
        signature = alert.get('signature', 'Unknown Alert')
        category = alert.get('category', '')
        severity_value = alert.get('severity', 3)
        
        severity_map = {1: 'Critical', 2: 'High', 3: 'Medium'}
        severity = severity_map.get(severity_value, 'Medium')
        
        # Build description
        description = f"Suricata Alert: {signature}"
        if category:
            description += f" - Category: {category}"
        
        description = sanitize_text(description)
        
        return Incident(
            title=f"Suricata: {signature[:50]}",
            description=description[:500],
            source_ip=source_ip,
            destination_ip=dest_ip,
            username=None,
            protocol=data.get('proto', ''),
            port=None,
            action=f"Alert_{category.replace(' ', '_') if category else 'Unknown'}",
            log_source="suricata",
            timestamp=timestamp,
        )

    def _parse_legacy_line(self, line: str) -> Optional[Incident]:
        """Parse legacy Suricata format."""
        # Format: [time] [severity] [signature] [source] -> [destination]
        sig_match = re.search(r'\[\*\*\]\s+([^\[]+)\s+\[\*\*\]', line)
        if not sig_match:
            return None
        
        signature = sig_match.group(1).strip()
        
        # Extract classification
        class_match = re.search(r'Classification:\s*([^\]]+)', line)
        category = class_match.group(1).strip() if class_match else 'Unknown'
        
        # Extract priority
        priority_match = re.search(r'Priority:\s*(\d+)', line)
        priority = int(priority_match.group(1)) if priority_match else 3
        
        severity_map = {1: 'Critical', 2: 'High', 3: 'Medium'}
        severity = severity_map.get(priority, 'Medium')
        
        # Extract IPs
        ip_match = re.search(r'(\d+\.\d+\.\d+\.\d+)\s+->\s+(\d+\.\d+\.\d+\.\d+)', line)
        if ip_match:
            source_ip = ip_match.group(1)
            dest_ip = ip_match.group(2)
        else:
            source_ip = None
            dest_ip = None
        
        # Build description
        description = f"Suricata Alert: {signature} - Category: {category}"
        description = sanitize_text(description)
        
        return Incident(
            title=f"Suricata: {signature[:50]}",
            description=description[:500],
            source_ip=source_ip,
            destination_ip=dest_ip,
            username=None,
            protocol="",
            port=None,
            action=f"Alert_{category.replace(' ', '_') if category else 'Unknown'}",
            log_source="suricata",
            timestamp=datetime.now(),
        )

