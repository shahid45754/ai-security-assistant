
from datetime import datetime
from typing import List, Optional
from pydantic import BaseModel , Field


class CampaignReport(BaseModel):
    """Correlated campaign report model."""
    
    attack_type: str
    source_ip: Optional[str] = None
    target_accounts: List[str] = Field(default_factory=list)
    failed_attempts: int
    first_seen: datetime
    last_seen: datetime
    duration_seconds: float
    unique_accounts: int
    attempts_per_minute: float
    risk: str
    confidence: float
    recommendations: List[str] = Field(default_factory=list)
    
    @property
    def severity(self) -> str:
        """Alias for risk for compatibility."""
        return self.risk
    
    @property
    def attack_name(self) -> str:
        """Alias for attack_type for compatibility."""
        return self.attack_type
