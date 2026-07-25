from typing import List, Dict, Any
from datetime import datetime

from app.models.response import IncidentAnalysis


class TimelineBuilder:
    """Service for building incident timelines."""
    
    @classmethod
    def build(cls, reports: List[IncidentAnalysis]) -> List[Dict[str, Any]]:
        """
        Build a timeline from reports.
        """
        if not reports:
            return []
        
        # Sort reports by timestamp from timeline
        def get_timestamp(report: IncidentAnalysis) -> datetime:
            """Get timestamp from report."""
            if report.timeline and report.timeline[0].get('time'):
                try:
                    return datetime.fromisoformat(report.timeline[0]['time'].replace('Z', '+00:00'))
                except:
                    pass
            return datetime.now()
        
        sorted_reports = sorted(reports, key=get_timestamp)
        
        timeline = []
        for report in sorted_reports:
            # Get timestamp
            timestamp = get_timestamp(report)
            
            # Build event entry
            event = {
                "timestamp": timestamp.isoformat(),
                "attack_type": report.attack_type,
                "severity": report.severity,
                "description": report.description[:200] if report.description else "Incident detected",
                "source_ip": report.affected_assets[0] if report.affected_assets and report.affected_assets[0] != "Unknown" else None,
                "confidence": report.confidence,
            }
            timeline.append(event)
        
        return timeline
