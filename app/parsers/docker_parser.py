
import re
from datetime import datetime
from typing import Optional

from app.models.incident import Incident
from app.parsers.base_parser import BaseParser
from app.core.utils import sanitize_text


class DockerParser(BaseParser):
    """Parser for Docker container logs."""
    
    def parse(self, content: str) -> list[Incident]:
        """Parse Docker log content."""
        incidents = []
        
        for line in content.splitlines():
            if not line.strip():
                continue
            
            incident = self._parse_line(line)
            if incident:
                incidents.append(incident)
                
        return incidents

    def _parse_line(self, line: str) -> Optional[Incident]:
        """Parse a single Docker log line."""
        
        # Extract timestamp
        timestamp = self._extract_timestamp(line)
        
        # Extract container info
        container = self._extract_container(line)
        
        # Detect event type
        event_type = self._detect_event_type(line)
        
        if not event_type:
            return None
        
        # Detect severity
        severity = self._detect_severity(line)
        
        # Extract IP if present
        source_ip = self._extract_ip(line)
        
        # Build description
        description = f"Docker Event: {event_type}"
        if container:
            description += f" (container: {container})"
        
        description = sanitize_text(description)
        
        # Only create incident for suspicious events
        suspicious_events = [
            'Container Escape Attempt',
            'Privileged Container',
            'Docker Socket Access',
            'Unauthorized Access'
        ]
        
        if any(event in event_type for event in suspicious_events) or severity == 'Critical':
            return Incident(
                title=f"Docker: {event_type}",
                description=description[:500],
                source_ip=source_ip,
                destination_ip=None,
                username=None,
                protocol="docker",
                port=None,
                action=f"Docker_{event_type.replace(' ', '_')}",
                log_source="docker",
                timestamp=timestamp,
            )
        
        return None

    def _extract_timestamp(self, line: str) -> datetime:
        """Extract timestamp from log line."""
        patterns = [
            r'(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z?)',
            r'(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})',
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

    def _extract_container(self, line: str) -> Optional[str]:
        """Extract container name or ID."""
        patterns = [
            r'container[=:]\s*([a-zA-Z0-9_-]+)',
            r'container\s+([a-zA-Z0-9_-]+)',
            r'([a-zA-Z0-9]{12,})',
        ]
        
        for pattern in patterns:
            match = re.search(pattern, line, re.IGNORECASE)
            if match:
                return match.group(1)
        return None

    def _detect_event_type(self, line: str) -> Optional[str]:
        """Detect the event type."""
        line_lower = line.lower()
        
        # Escape attempts (high priority)
        if 'escape' in line_lower or 'breakout' in line_lower:
            return 'Container Escape Attempt'
        if 'docker.sock' in line_lower or '/var/run/docker.sock' in line_lower:
            return 'Docker Socket Access'
        if 'privileged' in line_lower and ('run' in line_lower or 'start' in line_lower):
            return 'Privileged Container'
        
        # Common Docker events
        if 'started' in line_lower and 'container' in line_lower:
            return 'Container Started'
        if 'stopped' in line_lower and 'container' in line_lower:
            return 'Container Stopped'
        if 'restarted' in line_lower and 'container' in line_lower:
            return 'Container Restarted'
        if 'killed' in line_lower and 'container' in line_lower:
            return 'Container Killed'
        if 'created' in line_lower and 'container' in line_lower:
            return 'Container Created'
        if 'exec' in line_lower and 'container' in line_lower:
            return 'Container Exec'
        if 'attach' in line_lower and 'container' in line_lower:
            return 'Container Attach'
        if 'volume' in line_lower and 'mount' in line_lower:
            return 'Volume Mount'
        if 'network' in line_lower and 'connect' in line_lower:
            return 'Network Connect'
        
        # Error events
        if 'error' in line_lower:
            return 'Docker Error'
        if 'warning' in line_lower:
            return 'Docker Warning'
        
        return None

    def _detect_severity(self, line: str) -> str:
        """Detect severity of the event."""
        line_lower = line.lower()
        
        if any(keyword in line_lower for keyword in ['escape', 'breakout', 'privileged']):
            return 'Critical'
        if any(keyword in line_lower for keyword in ['error', 'failed', 'unauthorized']):
            return 'High'
        if any(keyword in line_lower for keyword in ['warning']):
            return 'Medium'
        
