from typing import List, Dict, Any
from datetime import datetime

from app.models.campaign import CampaignReport


class ExecutiveSummaryService:
    """Service for generating executive summaries."""
    
    @classmethod
    def generate(cls, campaigns: List[CampaignReport], statistics: Dict[str, Any]) -> Dict[str, Any]:
        """
        Generate an executive summary from campaigns and statistics.
        """
        if not campaigns:
            return {
                "summary": "No security incidents were detected during the analysis period.",
                "business_risk": "Low",
                "priority_actions": ["Continue monitoring", "Review security controls"],
                "overall_confidence": 1.0
            }
        
        # Calculate overall risk
        risk_levels = [c.risk for c in campaigns]
        if "Critical" in risk_levels:
            overall_risk = "Critical"
        elif "High" in risk_levels:
            overall_risk = "High"
        elif "Medium" in risk_levels:
            overall_risk = "Medium"
        else:
            overall_risk = "Low"
        
        # Calculate average confidence
        avg_confidence = sum(c.confidence for c in campaigns) / len(campaigns)
        
        # Get top attack types
        attack_types = {}
        for c in campaigns:
            attack_types[c.attack_type] = attack_types.get(c.attack_type, 0) + c.failed_attempts
        
        top_attacks = sorted(attack_types.items(), key=lambda x: x[1], reverse=True)[:3]
        
        # Build summary
        summary = f"Analysis detected {len(campaigns)} correlated attack campaign(s) "
        summary += f"involving {', '.join([f'{count} {attack}' for attack, count in top_attacks])}. "
        summary += f"Overall severity assessed as {overall_risk}."
        
        # Priority actions
        priority_actions = ["Review and investigate all detected campaigns"]
        
        if overall_risk in ["Critical", "High"]:
            priority_actions.append("Immediately contain and mitigate active threats")
            priority_actions.append("Notify incident response team")
        
        priority_actions.append("Implement recommended security controls")
        priority_actions.append("Update threat intelligence feeds")
        
        return {
            "summary": summary,
            "business_risk": f"{overall_risk} risk to business operations",
            "priority_actions": priority_actions[:5],
            "overall_confidence": round(avg_confidence, 2)
        }
