import os
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable
from reportlab.lib.enums import TA_CENTER, TA_LEFT

from app.models.campaign import CampaignReport
from app.models.response import IncidentAnalysis


class PDFReport:
    """Service for generating PDF reports."""

    @classmethod
    def export(
        cls,
        reports: List[IncidentAnalysis],
        campaigns: List[CampaignReport],
        statistics: dict,
        summary: dict,
        soc_verdict: dict,
        output_path: Optional[Path] = None,
    ) -> Path:
        """Generate a PDF report from analysis results."""
        
        output_path = Path(output_path) if output_path else Path("report.pdf")
        output_path.parent.mkdir(parents=True, exist_ok=True)
        
        # Create the PDF document
        doc = SimpleDocTemplate(
            str(output_path),
            pagesize=A4,
            rightMargin=72,
            leftMargin=72,
            topMargin=72,
            bottomMargin=72,
        )
        
        # Styles
        styles = getSampleStyleSheet()
        title_style = ParagraphStyle(
            'CustomTitle',
            parent=styles['Heading1'],
            fontSize=24,
            textColor=colors.HexColor('#1a1a2e'),
            spaceAfter=30,
            alignment=TA_CENTER
        )
        heading2_style = ParagraphStyle(
            'Heading2',
            parent=styles['Heading2'],
            fontSize=16,
            textColor=colors.HexColor('#2c3e50'),
            spaceAfter=12,
            spaceBefore=20
        )
        heading3_style = ParagraphStyle(
            'Heading3',
            parent=styles['Heading3'],
            fontSize=14,
            textColor=colors.HexColor('#34495e'),
            spaceAfter=8,
            spaceBefore=12
        )
        body_style = ParagraphStyle(
            'BodyText',
            parent=styles['Normal'],
            fontSize=10,
            leading=14,
            spaceAfter=6
        )
        risk_style = ParagraphStyle(
            'RiskText',
            parent=styles['Normal'],
            fontSize=12,
            leading=16,
            spaceAfter=8,
            textColor=colors.HexColor('#c0392b')
        )
        verdict_style = ParagraphStyle(
            'VerdictText',
            parent=styles['Normal'],
            fontSize=11,
            leading=15,
            spaceAfter=8,
            backColor=colors.HexColor('#f8f9fa'),
            borderPadding=10,
        )
        
        story = []
        
        # Report ID and timestamp
        report_id = str(uuid.uuid4())[:8].upper()
        generated_at = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
        
        # Title
        story.append(Paragraph(f"AI Security Incident Report", title_style))
        story.append(Paragraph(f"Report ID: {report_id}", body_style))
        story.append(Paragraph(f"Generated: {generated_at}", body_style))
        story.append(Spacer(1, 20))
        
        # SOC Verdict
        if soc_verdict:
            story.append(Paragraph("SOC Verdict", heading2_style))
            threat_level = soc_verdict.get('threat_level', 'Unknown')
            verdict_text = soc_verdict.get('verdict', 'No verdict provided.')
            priority = soc_verdict.get('priority', 'Not specified')
            confidence = soc_verdict.get('confidence', 0)
            
            story.append(Paragraph(f"<b>Threat Level:</b> {threat_level}", body_style))
            story.append(Paragraph(f"<b>Priority:</b> {priority}", body_style))
            story.append(Paragraph(f"<b>Confidence:</b> {confidence * 100:.0f}%", body_style))
            story.append(Paragraph(f"<b>Verdict:</b> {verdict_text}", verdict_style))
            
            next_actions = soc_verdict.get('next_action', [])
            if next_actions:
                story.append(Paragraph("<b>Immediate Actions:</b>", body_style))
                for action in next_actions[:5]:
                    story.append(Paragraph(f"• {action}", body_style))
            story.append(Spacer(1, 15))
        
        # Executive Summary
        story.append(Paragraph("Executive Summary", heading2_style))
        summary_text = summary.get('summary', 'No executive summary available.')
        story.append(Paragraph(summary_text, body_style))
        
        business_risk = summary.get('business_risk', 'Not assessed.')
        story.append(Paragraph(f"<b>Business Risk:</b> {business_risk}", risk_style))
        
        overall_confidence = summary.get('overall_confidence')
        if overall_confidence:
            story.append(Paragraph(f"<b>AI Confidence:</b> {overall_confidence * 100:.0f}%", body_style))
        
        priority_actions = summary.get('priority_actions', [])
        if priority_actions:
            story.append(Paragraph("<b>Priority Actions:</b>", body_style))
            for action in priority_actions[:5]:
                story.append(Paragraph(f"• {action}", body_style))
        
        story.append(Spacer(1, 15))
        
        # Statistics Dashboard
        story.append(Paragraph("Statistics Dashboard", heading2_style))
        total_incidents = statistics.get('total_incidents', 0)
        total_campaigns = statistics.get('total_campaigns', 0)
        severity_dist = statistics.get('severity_distribution', {})
        
        story.append(Paragraph(f"<b>Total Incidents:</b> {total_incidents}", body_style))
        story.append(Paragraph(f"<b>Total Campaigns:</b> {total_campaigns}", body_style))
        
        if severity_dist:
            story.append(Paragraph("<b>Severity Distribution:</b>", body_style))
            for level, count in severity_dist.items():
                color = "red" if level.lower() == "critical" else "orange" if level.lower() == "high" else "green"
                story.append(Paragraph(f"• {level}: {count}", body_style))
        
        story.append(Spacer(1, 15))
        
        # Campaign Overview
        if campaigns:
            story.append(Paragraph("Campaign Overview", heading2_style))
            for idx, campaign in enumerate(campaigns, start=1):
                story.append(Paragraph(f"<b>Campaign {idx}: {campaign.attack_type}</b>", heading3_style))
                story.append(Paragraph(f"Risk: {campaign.risk}", body_style))
                story.append(Paragraph(f"Confidence: {campaign.confidence:.2f}", body_style))
                story.append(Paragraph(f"Attempts: {campaign.failed_attempts}", body_style))
                if campaign.source_ip:
                    story.append(Paragraph(f"Source IP: {campaign.source_ip}", body_style))
                if campaign.recommendations:
                    story.append(Paragraph("<b>Recommendations:</b>", body_style))
                    for rec in campaign.recommendations[:3]:
                        story.append(Paragraph(f"• {rec}", body_style))
                story.append(Spacer(1, 10))
            story.append(Spacer(1, 15))
        
        # Individual Incident Analysis
        if reports:
            story.append(Paragraph("Incident Analysis", heading2_style))
            for idx, report in enumerate(reports, start=1):
                story.append(Paragraph(f"<b>Incident {idx}: {report.attack_type}</b>", heading3_style))
                story.append(Paragraph(f"Severity: {report.severity}", body_style))
                story.append(Paragraph(f"Confidence: {report.confidence:.2f}", body_style))
                story.append(Paragraph(f"Description: {report.description}", body_style))
                
                if hasattr(report, 'business_impact') and report.business_impact:
                    story.append(Paragraph(f"<b>Business Impact:</b> {report.business_impact}", body_style))
                
                if hasattr(report, 'investigation_steps') and report.investigation_steps:
                    story.append(Paragraph("<b>Investigation Steps:</b>", body_style))
                    for step in report.investigation_steps[:5]:
                        story.append(Paragraph(f"• {step}", body_style))
                
                if hasattr(report, 'analyst_notes') and report.analyst_notes:
                    story.append(Paragraph(f"<b>Analyst Notes:</b> {report.analyst_notes}", body_style))
                
                if hasattr(report, 'recommendations') and report.recommendations:
                    story.append(Paragraph("<b>Recommendations:</b>", body_style))
                    for rec in report.recommendations[:3]:
                        story.append(Paragraph(f"• {rec}", body_style))
                
                if hasattr(report, 'mitre_attack') and report.mitre_attack:
                    story.append(Paragraph(f"<b>MITRE ATT&CK:</b> {', '.join(report.mitre_attack)}", body_style))
                
                story.append(Spacer(1, 10))
                story.append(HRFlowable(width="100%", thickness=1, color=colors.lightgrey))
                story.append(Spacer(1, 10))
        
        # Build the PDF
        doc.build(story)
        
        print(f"\nPDF report saved to:\n{output_path.resolve()}")
        return output_path
