
from typing import List, Optional, Dict, Any
from datetime import datetime
from pydantic import BaseModel, Field


class AttackInfo(BaseModel):
    """Attack information model."""
    name: str
    severity: str
    confidence: float
    mitre_attack: List[str] = Field(default_factory=list)


class IncidentSummary(BaseModel):
    """Summary of an incident for statistics."""
    source_ip: Optional[str] = None
    destination_ip: Optional[str] = None
    username: Optional[str] = None
    attack_type: str
    severity: str
    confidence: float
    timestamp: Optional[datetime] = None


class IncidentAnalysis(BaseModel):
    """Analysis result for an incident."""
    # Primary fields
    attack_type: str = Field(description="The type of attack")
    severity: str = Field(description="Severity level: Critical, High, Medium, Low")
    confidence: float = Field(description="Confidence score from 0.0 to 1.0")
    description: str = Field(description="Brief description of the incident")
    
    # Additional fields
    affected_assets: List[str] = Field(default_factory=list, description="List of affected assets")
    recommendations: List[str] = Field(default_factory=list, description="Recommended actions")
    mitre_attack: List[str] = Field(default_factory=list, description="MITRE ATT&CK technique IDs")
    timeline: List[Dict[str, Any]] = Field(default_factory=list, description="Timeline of events")
    business_impact: str = Field(default="", description="Business impact assessment")
    investigation_steps: List[str] = Field(default_factory=list, description="Steps for investigation")
    analyst_notes: str = Field(default="", description="Additional notes for the analyst")
    
    @property
    def attack(self) -> 'AttackInfo':
        """Return attack info for compatibility with correlation engine."""
        return AttackInfo(
            name=self.attack_type,
            severity=self.severity,
            confidence=self.confidence,
            mitre_attack=self.mitre_attack
        )
    
    @property
    def summary(self) -> 'IncidentSummary':
        """Return summary for statistics."""
        # Get first affected asset as source_ip
        source_ip = self.affected_assets[0] if self.affected_assets and self.affected_assets[0] != "Unknown" else None
        destination_ip = self.affected_assets[1] if len(self.affected_assets) > 1 and self.affected_assets[1] != "Unknown" else None
        
        # Get timestamp from timeline
        timestamp = None
        if self.timeline and self.timeline[0].get('time'):
            try:
                timestamp = datetime.fromisoformat(self.timeline[0]['time'].replace('Z', '+00:00'))
            except:
                pass
        
        return IncidentSummary(
            source_ip=source_ip,
            destination_ip=destination_ip,
            username=None,
            attack_type=self.attack_type,
            severity=self.severity,
            confidence=self.confidence,
            timestamp=timestamp
        )

