from typing import List, Dict, Any
from collections import defaultdict

from app.models.campaign import CampaignReport
from app.models.response import IncidentAnalysis


class StatisticsService:
    """Service for building statistics from reports and campaigns."""
    
    @classmethod
    def build(cls, reports: List[IncidentAnalysis], campaigns: List[CampaignReport]) -> Dict[str, Any]:
        """
        Build statistics from reports and campaigns.
        """
        stats = {
            "total_incidents": len(reports),
            "total_campaigns": len(campaigns),
            "severity_distribution": cls._get_severity_distribution(reports),
            "attack_type_distribution": cls._get_attack_type_distribution(reports),
            "top_source_ips": cls._get_top_source_ips(reports),
            "top_attack_types": cls._get_top_attack_types(reports),
            "campaign_summary": cls._get_campaign_summary(campaigns),
            "average_confidence": cls._get_average_confidence(reports),
        }
        
        return stats
    
    @classmethod
    def _get_severity_distribution(cls, reports: List[IncidentAnalysis]) -> Dict[str, int]:
        """Get distribution of severity levels."""
        distribution = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
        for report in reports:
            severity = report.severity if report.severity else "Medium"
            if severity in distribution:
                distribution[severity] += 1
            else:
                distribution["Medium"] += 1
        return distribution
    
    @classmethod
    def _get_attack_type_distribution(cls, reports: List[IncidentAnalysis]) -> Dict[str, int]:
        """Get distribution of attack types."""
        distribution = defaultdict(int)
        for report in reports:
            attack_type = report.attack_type if report.attack_type else "Unknown"
            distribution[attack_type] += 1
        return dict(distribution)
    
    @classmethod
    def _get_top_source_ips(cls, reports: List[IncidentAnalysis], limit: int = 5) -> List[Dict[str, Any]]:
        """Get top source IPs from reports."""
        ip_counter = defaultdict(int)
        for report in reports:
            if hasattr(report, 'summary') and report.summary and report.summary.source_ip:
                ip_counter[report.summary.source_ip] += 1
            else:
                for asset in report.affected_assets:
                    if asset and asset != "Unknown":
                        ip_counter[asset] += 1
        
        sorted_ips = sorted(ip_counter.items(), key=lambda x: x[1], reverse=True)[:limit]
        
        result = []
        for ip, count in sorted_ips:
            count_int = int(count) if isinstance(count, (int, float)) else 0
            result.append({
                "ip": ip,
                "count": count_int
            })
        
        return result
    
    @classmethod
    def _get_top_attack_types(cls, reports: List[IncidentAnalysis], limit: int = 5) -> List[Dict[str, Any]]:
        """Get top attack types from reports."""
        type_counter = defaultdict(int)
        for report in reports:
            attack_type = report.attack_type if report.attack_type else "Unknown"
            type_counter[attack_type] += 1
        
        sorted_types = sorted(type_counter.items(), key=lambda x: x[1], reverse=True)[:limit]
        
        result = []
        for attack_type, count in sorted_types:
            count_int = int(count) if isinstance(count, (int, float)) else 0
            result.append({
                "attack_type": attack_type,
                "count": count_int
            })
        
        return result
    
    @classmethod
    def _get_campaign_summary(cls, campaigns: List[CampaignReport]) -> Dict[str, Any]:
        """Get summary of campaigns."""
        if not campaigns:
            return {
                "total": 0,
                "average_duration": 0.0,
                "average_attempts": 0.0,
                "average_confidence": 0.0,
            }
        
        total_duration = sum(c.duration_seconds for c in campaigns)
        total_attempts = sum(c.failed_attempts for c in campaigns)
        total_confidence = sum(c.confidence for c in campaigns)
        
        return {
            "total": len(campaigns),
            "average_duration": round(total_duration / len(campaigns), 2),
            "average_attempts": round(total_attempts / len(campaigns), 2),
            "average_confidence": round(total_confidence / len(campaigns), 2),
        }
    
    @classmethod
    def _get_average_confidence(cls, reports: List[IncidentAnalysis]) -> float:
        """Get average confidence from reports."""
        if not reports:
            return 0.0
        total_confidence = sum(r.confidence for r in reports)
        return round(total_confidence / len(reports), 2)
