from typing import List, Dict, Any, Optional
from collections import defaultdict
from datetime import datetime

from app.models.campaign import CampaignReport
from app.models.response import IncidentAnalysis


class CorrelationEngine:
    """Engine for correlating incidents into campaigns."""
    
    def correlate(self, reports: List[IncidentAnalysis]) -> List[CampaignReport]:
        """
        Correlate incident reports into campaigns based on common attack types.
        """
        if not reports:
            return []
        
        # Group reports by attack type
        grouped = defaultdict(list)
        for report in reports:
            attack_key = report.attack_type.lower() if report.attack_type else "unknown"
            grouped[attack_key].append(report)
        
        campaigns = []
        for attack_type, group in grouped.items():
            campaign = self._create_campaign(attack_type, group)
            campaigns.append(campaign)
        
        return campaigns
    
    def _create_campaign(self, attack_type: str, reports: List[IncidentAnalysis]) -> CampaignReport:
        """Create a campaign from a group of reports."""
        # Sort reports by timestamp (if available)
        sorted_reports = sorted(
            reports,
            key=lambda r: r.timeline[0].get('time') if r.timeline and r.timeline[0].get('time') else '',
            reverse=False
        )
        
        # Get first and last seen timestamps
        first_seen = datetime.now()
        last_seen = datetime.now()
        
        if sorted_reports:
            first_report = sorted_reports[0]
            last_report = sorted_reports[-1]
            
            # Try to get timestamps from timeline
            if first_report.timeline and first_report.timeline[0].get('time'):
                try:
                    first_seen = datetime.fromisoformat(first_report.timeline[0]['time'].replace('Z', '+00:00'))
                except:
                    pass
            
            if last_report.timeline and last_report.timeline[0].get('time'):
                try:
                    last_seen = datetime.fromisoformat(last_report.timeline[0]['time'].replace('Z', '+00:00'))
                except:
                    pass
        
        # Calculate duration
        duration_seconds = (last_seen - first_seen).total_seconds()
        
        # Get unique source IPs and accounts
        unique_ips = set()
        target_accounts = set()
        
        for report in reports:
            for asset in report.affected_assets:
                if asset and asset != "Unknown":
                    unique_ips.add(asset)
            if report.attack_type:
                target_accounts.add(report.attack_type)
        
        source_ip = list(unique_ips)[0] if unique_ips else None
        
        # Calculate attempts per minute
        failed_attempts = len(reports)
        attempts_per_minute = failed_attempts / (duration_seconds / 60) if duration_seconds > 0 else 0.0
        
        # Determine severity (highest in the group)
        severity_levels = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1}
        max_severity = "Low"
        max_score = 0
        for report in reports:
            score = severity_levels.get(report.severity, 0)
            if score > max_score:
                max_score = score
                max_severity = report.severity
        
        # Calculate average confidence
        avg_confidence = sum(r.confidence for r in reports) / len(reports) if reports else 0.0
        
        # Collect all recommendations
        all_recommendations = []
        for report in reports:
            all_recommendations.extend(report.recommendations)
        
        # Get unique recommendations
        unique_recommendations = list(dict.fromkeys(all_recommendations))[:5]
        
        return CampaignReport(
            attack_type=attack_type.title(),
            source_ip=source_ip,
            target_accounts=list(target_accounts)[:10],
            failed_attempts=len(reports),
            first_seen=first_seen,
            last_seen=last_seen,
            duration_seconds=round(duration_seconds, 2),
            unique_accounts=len(target_accounts),
            attempts_per_minute=round(attempts_per_minute, 2),
            risk=max_severity,
            confidence=round(avg_confidence, 2),
            recommendations=unique_recommendations
        )
