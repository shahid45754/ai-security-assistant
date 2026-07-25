from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field


class SOCVerdict(BaseModel):
    """SOC Verdict model for incident assessment."""
    
    verdict: str = Field(description="Overall assessment of the incident")
    threat_level: str = Field(description="Threat level: Critical, High, Medium, Low")
    priority: str = Field(description="Priority: P1, P2, P3, P4")
    confidence: float = Field(description="Confidence score from 0.0 to 1.0")
    next_action: List[str] = Field(default_factory=list, description="Immediate actions to take")
    long_term_actions: Optional[List[str]] = Field(default_factory=list, description="Long-term recommendations")
    affected_assets: Optional[List[str]] = Field(default_factory=list, description="Affected assets")
    timeline: Optional[List[Dict[str, Any]]] = Field(default_factory=list, description="Timeline of events")
    recommendations: Optional[List[str]] = Field(default_factory=list, description="Additional recommendations")
    
    @property
    def severity(self) -> str:
        """Alias for threat_level for compatibility."""
        return self.threat_level
    
    @property
    def level(self) -> str:
        """Alias for threat_level for compatibility."""
        return self.threat_level
    
    @property
    def risk_level(self) -> str:
        """Alias for threat_level for compatibility."""
        return self.threat_level
    
    @property
    def summary(self) -> str:
        """Get a summary of the verdict."""
        return f"Verdict: {self.verdict} (Threat Level: {self.threat_level}, Priority: {self.priority})"
    
    @property
    def is_critical(self) -> bool:
        """Check if the verdict is critical."""
        return self.threat_level.lower() == "critical"
    
    @property
    def is_high(self) -> bool:
        """Check if the verdict is high."""
        return self.threat_level.lower() == "high"
    
    @property
    def is_medium(self) -> bool:
        """Check if the verdict is medium."""
        return self.threat_level.lower() == "medium"
    
    @property
    def is_low(self) -> bool:
        """Check if the verdict is low."""
        return self.threat_level.lower() == "low"
    
    def get_priority_description(self) -> str:
        """Get description of the priority level."""
        priority_desc = {
            "P1": "Critical - Immediate action required",
            "P2": "High - Action required within 24 hours",
            "P3": "Medium - Action required within 72 hours",
            "P4": "Low - Action required within 1 week",
        }
        return priority_desc.get(self.priority, "Unknown priority")
    
    def get_threat_description(self) -> str:
        """Get description of the threat level."""
        threat_desc = {
            "Critical": "Immediate threat to organization",
            "High": "Significant threat requiring immediate attention",
            "Medium": "Moderate threat requiring investigation",
            "Low": "Minor threat requiring monitoring",
        }
        return threat_desc.get(self.threat_level, "Unknown threat level")

