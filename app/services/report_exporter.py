
import json
from datetime import datetime
from pathlib import Path
from typing import List, Any

from app.models.campaign import CampaignReport


class ReportExporter:
    """Service for exporting reports in various formats."""
    
    @classmethod
    def export_json(cls, campaigns: List[CampaignReport], output_path: Path) -> str:
        """
        Export campaigns as JSON.
        """
        data = []
        for c in campaigns:
            data.append({
                "attack_type": c.attack_type,
                "source_ip": c.source_ip,
                "target_accounts": c.target_accounts,
                "failed_attempts": c.failed_attempts,
                "first_seen": c.first_seen.isoformat() if c.first_seen else None,
                "last_seen": c.last_seen.isoformat() if c.last_seen else None,
                "duration_seconds": c.duration_seconds,
                "unique_accounts": c.unique_accounts,
                "attempts_per_minute": c.attempts_per_minute,
                "risk": c.risk,
                "confidence": c.confidence,
                "recommendations": c.recommendations,
            })
        
        Path(output_path).write_text(json.dumps(data, indent=2))
        return str(output_path)
    
    @classmethod
    def export_markdown(cls, campaigns: List[CampaignReport], output_path: Path) -> str:
        """
        Export campaigns as Markdown.
        """
        lines = [
            "# Security Incident Report",
            "",
            f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            "",
            "## Campaign Overview",
            "",
            "| Campaign | Attack Type | Risk | Confidence | Attempts |",
            "|----------|-------------|------|------------|----------|",
        ]
        
        for i, c in enumerate(campaigns, 1):
            lines.append(f"| {i} | {c.attack_type} | {c.risk} | {c.confidence:.2f} | {c.failed_attempts} |")
        
        lines.append("")
        lines.append("## Campaign Details")
        lines.append("")
        
        for i, c in enumerate(campaigns, 1):
            lines.append(f"### Campaign {i}: {c.attack_type}")
            lines.append("")
            lines.append(f"- **Source IP:** {c.source_ip or 'Unknown'}")
            lines.append(f"- **Risk Level:** {c.risk}")
            lines.append(f"- **Confidence:** {c.confidence:.2f}")
            lines.append(f"- **Failed Attempts:** {c.failed_attempts}")
            lines.append(f"- **Duration:** {c.duration_seconds:.0f} seconds")
            lines.append(f"- **Unique Accounts:** {c.unique_accounts}")
            lines.append(f"- **Attempts/Minute:** {c.attempts_per_minute:.2f}")
            lines.append("")
            if c.recommendations:
                lines.append("**Recommendations:**")
                for rec in c.recommendations:
                    lines.append(f"- {rec}")
                lines.append("")
        
        Path(output_path).write_text("\n".join(lines))
        return str(output_path)
