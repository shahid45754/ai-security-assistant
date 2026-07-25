from typing import List
from pydantic import BaseModel


class ExecutiveSummary(BaseModel):
    summary: str
    business_risk: str
    priority_actions: List[str]
    overall_confidence: float
