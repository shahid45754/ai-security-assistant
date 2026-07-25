
from abc import ABC, abstractmethod
from typing import List

from app.models.incident import Incident


class BaseParser(ABC):
    """Base parser class that all log parsers must inherit from."""
    
    @abstractmethod
    def parse(self, content: str) -> List[Incident]:
        """
        Parse log content and return a list of incidents.
        
        Args:
            content: Raw log content as a string
            
        Returns:
            List of Incident objects
        """
        pass
    
    def _extract_timestamp(self, line: str) -> str:
        """
        Extract timestamp from a log line.
        Override this method in child classes for specific formats.
        """
        return ""
    
    def _extract_ip(self, line: str) -> str:
        """
        Extract IP address from a log line using regex.
        """
        import re
        ip_pattern = r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'
        match = re.search(ip_pattern, line)
        return match.group(0) if match else None
    
    def _extract_username(self, line: str) -> str:
        """
        Extract username from a log line.
        """
        import re
        patterns = [
            r'user[=:]\s*([^\s,]+)',
            r'username[=:]\s*([^\s,]+)',
            r'account[=:]\s*([^\s,]+)',
        ]
        for pattern in patterns:
            match = re.search(pattern, line, re.IGNORECASE)
            if match:
                return match.group(1)
        return None
