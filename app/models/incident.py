from datetime import datetime
from typing import Optional
from pydantic import BaseModel


class Incident(BaseModel):
    """Represents a security incident parsed from logs."""
    
    title: str
    description: str
    source_ip: Optional[str] = None
    destination_ip: Optional[str] = None
    username: Optional[str] = None
    protocol: Optional[str] = None
    port: Optional[int] = None
    action: Optional[str] = None
    log_source: str
    timestamp: datetime
    
    def searchable_text(self) -> str:
        """Generate searchable text from incident fields."""
        parts = [
            self.title,
            self.description,
        ]
        
        if self.log_source:
            parts.append(self.log_source)
        
        if self.action:
            parts.append(self.action)
        
        if self.username:
            parts.append(self.username)
        
        if self.source_ip:
            parts.append(self.source_ip)
        
        if self.destination_ip:
            parts.append(self.destination_ip)
        
        if self.protocol:
            parts.append(self.protocol)
        
        if self.port:
            parts.append(f"Port {self.port}")
        
        return " ".join(str(part) for part in parts if part)
