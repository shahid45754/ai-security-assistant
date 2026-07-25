import html
import math
import os
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Dict, Any, Optional

from app.models.campaign import CampaignReport
from app.models.response import IncidentAnalysis
from app.services.attack_graph import AttackGraph
from app.services.kill_chain import KillChainService


class HTMLReport:
    """Service for generating HTML reports."""

    OUTPUT = Path(__file__).resolve().parent.parent / "reports" / "report.html"

    SEVERITY_WEIGHTS = {
        "critical": 100,
        "high": 75,
        "medium": 45,
        "low": 20,
    }

    DONUT_PALETTE = [
        "#c0392b", "#2c3e50", "#d68910", "#8e44ad",
        "#16a085", "#2980b9", "#7f8c8d", "#e67e22",
    ]

    @staticmethod
    def _esc(value) -> str:
        """HTML-escape any value before it's interpolated into the report."""
        return html.escape(str(value), quote=True)

    @classmethod
    def _bar_chart(cls, data: List[Dict[str, Any]], color: str = "#222", width: int = 600) -> str:
        """Generate an SVG bar chart from data."""
        if not data:
            return '<p>No data available.</p>'
        
        chart_data = []
        for item in data:
            label = item.get('ip') or item.get('attack_type') or item.get('severity') or 'Unknown'
            value = item.get('count', 0)
            try:
                value = float(value) if not isinstance(value, (int, float)) else value
            except:
                value = 0
            
            if value > 0:
                chart_data.append((label, value))
        
        if not chart_data:
            return '<p>No data available.</p>'

        max_value = max(count for _, count in chart_data) or 1
        row_height = 34
        label_width = 160
        bar_area = width - label_width - 60
        chart_height = row_height * len(chart_data)

        bars = ""
        for i, (label, value) in enumerate(chart_data):
            y = i * row_height
            bar_len = max((value / max_value) * bar_area, 2)
            safe_label = cls._esc(label)
            bars += f"""
            <text x="0" y="{y + row_height / 2 + 4}" font-size="12" fill="#333">{safe_label}</text>
            <rect x="{label_width}" y="{y + 6}" width="{bar_len:.1f}" height="{row_height - 14}" fill="{color}" rx="3"></rect>
            <text x="{label_width + bar_len + 8}" y="{y + row_height / 2 + 4}" font-size="12" fill="#333">{int(value)}</text>
            """

        return f"""
        <svg viewBox="0 0 {width} {chart_height}" width="100%" height="{chart_height}" xmlns="http://www.w3.org/2000/svg">
            {bars}
        </svg>
        """

    @classmethod
    def _donut_chart(cls, data: list[tuple[str, int]], size: int = 220) -> tuple[str, str]:
        """Returns (svg_markup, legend_html) for a donut chart."""
        if not data:
            return "<p>No data available.</p>", ""

        total = sum(count for _, count in data) or 1
        radius = size / 2 - 20
        circumference = 2 * math.pi * radius
        center = size / 2

        segments = ""
        legend = ""
        offset = 0.0
        for i, (label, count) in enumerate(data):
            color = cls.DONUT_PALETTE[i % len(cls.DONUT_PALETTE)]
            fraction = count / total
            dash = fraction * circumference
            segments += f"""
            <circle cx="{center}" cy="{center}" r="{radius}" fill="transparent"
                stroke="{color}" stroke-width="26"
                stroke-dasharray="{dash:.2f} {circumference:.2f}"
                stroke-dashoffset="{-offset:.2f}"
                transform="rotate(-90 {center} {center})" />
            """
            offset += dash
            pct = fraction * 100
            safe_label = cls._esc(label)
            legend += f"""
            <div class="donut-legend-item">
                <span class="donut-swatch" style="background:{color};"></span>
                {safe_label} &mdash; {count} ({pct:.0f}%)
            </div>
            """

        svg = f"""
        <svg viewBox="0 0 {size} {size}" width="{size}" height="{size}" xmlns="http://www.w3.org/2000/svg">
            <circle cx="{center}" cy="{center}" r="{radius}" fill="transparent" stroke="#eee" stroke-width="26" />
            {segments}
            <text x="{center}" y="{center - 4}" text-anchor="middle" font-size="22" font-weight="bold" fill="#222">{total}</text>
            <text x="{center}" y="{center + 16}" text-anchor="middle" font-size="11" fill="#777">TOTAL</text>
        </svg>
        """
        return svg, legend

    @staticmethod
    def _risk_gauge(score: float, width: int = 320) -> str:
        """Semi-circular gauge, 0-100, with color bands and a needle."""
        score = max(0.0, min(100.0, score))
        height = width / 2 + 40
        cx = width / 2
        cy = width / 2 + 10
        r = width / 2 - 20

        bands = [
            (0, 40, "#2a8a2a"),
            (40, 65, "#e0a800"),
            (65, 85, "#e08a00"),
            (85, 100, "#b30000"),
        ]

        def point(angle_deg: float, radius: float) -> tuple[float, float]:
            angle_rad = math.radians(angle_deg)
            return cx + radius * math.cos(angle_rad), cy - radius * math.sin(angle_rad)

        arcs = ""
        for start, end, color in bands:
            start_angle = 180 - (start / 100) * 180
            end_angle = 180 - (end / 100) * 180
            x1, y1 = point(start_angle, r)
            x2, y2 = point(end_angle, r)
            large_arc = 1 if (start_angle - end_angle) > 180 else 0
            arcs += f'<path d="M {x1:.1f} {y1:.1f} A {r} {r} 0 {large_arc} 1 {x2:.1f} {y2:.1f}" stroke="{color}" stroke-width="22" fill="none" stroke-linecap="butt" />'

        needle_angle = 180 - (score / 100) * 180
        needle_x, needle_y = point(needle_angle, r - 15)

        if score >= 85:
            label, label_color = "Critical Risk", "#b30000"
        elif score >= 65:
            label, label_color = "High Risk", "#e08a00"
        elif score >= 40:
            label, label_color = "Moderate Risk", "#e0a800"
        else:
            label, label_color = "Low Risk", "#2a8a2a"

        return f"""
        <svg viewBox="0 0 {width} {height}" width="{width}" height="{height}" xmlns="http://www.w3.org/2000/svg">
            {arcs}
            <line x1="{cx}" y1="{cy}" x2="{needle_x:.1f}" y2="{needle_y:.1f}" stroke="#222" stroke-width="4" stroke-linecap="round" />
            <circle cx="{cx}" cy="{cy}" r="7" fill="#222" />
            <text x="{cx}" y="{cy - r / 2}" text-anchor="middle" font-size="30" font-weight="bold" fill="#222">{score:.0f}</text>
            <text x="{cx}" y="{cy - r / 2 + 22}" text-anchor="middle" font-size="13" font-weight="bold" fill="{label_color}">{label}</text>
        </svg>
        """

    @classmethod
    def _generate_kill_chain(cls, reports: List[IncidentAnalysis]) -> str:
        """Generate Cyber Kill Chain visualization."""
        if not reports:
            return '<div class="card"><h2>Cyber Kill Chain</h2><p>No data available to map to kill chain.</p></div>'
        
        stage_counts = KillChainService.map_reports(reports)
        total_incidents = len(reports)
        
        kill_chain_html = '<div class="kc-flow">'
        
        for i, stage in enumerate(KillChainService.KILL_CHAIN_STAGES):
            count = stage_counts.get(stage, 0)
            active_class = "kc-active" if count > 0 else "kc-inactive"
            percentage = (count / total_incidents * 100) if total_incidents > 0 else 0
            
            description = KillChainService.get_stage_description(stage)
            
            kill_chain_html += f"""
            <div class="kc-box {active_class}" title="{description}">
                <span class="kc-stage-num">{i + 1}</span>
                <span class="kc-stage-name">{stage}</span>
                <span class="kc-stage-count">{count} incident{'s' if count != 1 else ''}</span>
                <span class="kc-stage-percentage">{percentage:.0f}%</span>
            </div>
            """
            
            if i < len(KillChainService.KILL_CHAIN_STAGES) - 1:
                kill_chain_html += '<div class="kc-arrow">&#8594;</div>'
        
        kill_chain_html += '</div>'
        
        return f"""
        <div class="card" id="kill-chain">
            <h2>Cyber Kill Chain</h2>
            <p class="section-note">Incidents mapped to Lockheed Martin's Cyber Kill Chain stages. Highlighted stages indicate observed activity.</p>
            {kill_chain_html}
            <div class="kill-chain-legend">
                <span class="kc-legend-item kc-active">● Active Stage</span>
                <span class="kc-legend-item kc-inactive">○ Inactive Stage</span>
            </div>
        </div>
        """

    @classmethod
    def _generate_attack_graph(cls, reports: List[IncidentAnalysis]) -> str:
        """Generate Attack Graph visualization."""
        if not reports:
            return '<div class="card"><h2>Attack Graph</h2><p>No data available to build attack graph.</p></div>'
        
        return AttackGraph.build(reports)

    @classmethod
    def export(
        cls,
        reports: List[IncidentAnalysis],
        campaigns: List[CampaignReport],
        statistics: dict,
        summary: dict,
        timeline: list[dict] | None = None,
        soc_verdict: dict | None = None,
        output_path: Path | None = None,
    ) -> Path:

        target_path = Path(output_path) if output_path else cls.OUTPUT
        target_path.parent.mkdir(parents=True, exist_ok=True)

        timeline = timeline or []
        report_id = str(uuid.uuid4())[:8].upper()
        generated_at = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

        # SOC Verdict section
        verdict_section = ""
        if soc_verdict:
            threat_level = str(soc_verdict.get("threat_level", "Unknown"))
            threat_level_class = threat_level.lower()
            verdict_text = cls._esc(soc_verdict.get("verdict", "No verdict provided."))
            priority_text = cls._esc(soc_verdict.get("priority", "Not specified."))
            verdict_confidence = soc_verdict.get("confidence")
            next_actions = soc_verdict.get("next_action", [])

            next_actions_html = "".join(
                f"<li>{cls._esc(action)}</li>" for action in next_actions
            ) or "<li>No immediate actions specified.</li>"

            verdict_confidence_html = (
                f"""
                <div class="verdict-confidence">
                    <div class="verdict-confidence-bar">
                        <div class="verdict-confidence-fill" style="width:{verdict_confidence * 100:.0f}%;"></div>
                    </div>
                    <span>{verdict_confidence * 100:.0f}% confidence</span>
                </div>
                """
                if isinstance(verdict_confidence, (int, float))
                else ""
            )

            verdict_section = f"""
            <div class="verdict-banner verdict-{threat_level_class}">
                <div class="verdict-top">
                    <span class="verdict-badge verdict-badge-{threat_level_class}">{cls._esc(threat_level)} THREAT</span>
                    <span class="verdict-priority">Priority: {priority_text}</span>
                </div>
                <p class="verdict-text">{verdict_text}</p>
                {verdict_confidence_html}
                <p class="verdict-actions-label"><strong>Immediate SOC Actions</strong></p>
                <ul class="verdict-actions">
                    {next_actions_html}
                </ul>
            </div>
            """

        # Executive summary
        summary_text = cls._esc(summary.get("summary", "No executive summary available."))
        business_risk_text = cls._esc(summary.get("business_risk", "Not assessed."))
        priority_actions = summary.get("priority_actions", [])
        overall_confidence = summary.get("overall_confidence")

        priority_actions_html = "".join(
            f"<li>{cls._esc(action)}</li>" for action in priority_actions
        ) or "<li>No priority actions provided.</li>"

        confidence_html = (
            f"<p><strong>Overall AI Confidence:</strong> {overall_confidence * 100:.0f}%</p>"
            if isinstance(overall_confidence, (int, float))
            else ""
        )

        severity_distribution = statistics.get("severity_distribution", {})
        severity_lookup = {str(k).lower(): v for k, v in severity_distribution.items()}

        dashboard_html = f"""
        <div class="dashboard">
            <div class="stat-box">
                <span class="stat-number">{statistics.get("total_incidents", 0)}</span>
                <span class="stat-label">Incidents</span>
            </div>
            <div class="stat-box">
                <span class="stat-number">{statistics.get("total_campaigns", 0)}</span>
                <span class="stat-label">Campaigns</span>
            </div>
            <div class="stat-box critical">
                <span class="stat-number">{severity_lookup.get("critical", 0)}</span>
                <span class="stat-label">Critical</span>
            </div>
            <div class="stat-box high">
                <span class="stat-number">{severity_lookup.get("high", 0)}</span>
                <span class="stat-label">High</span>
            </div>
            <div class="stat-box medium">
                <span class="stat-number">{severity_lookup.get("medium", 0)}</span>
                <span class="stat-label">Medium</span>
            </div>
            <div class="stat-box low">
                <span class="stat-number">{severity_lookup.get("low", 0)}</span>
                <span class="stat-label">Low</span>
            </div>
        </div>
        """

        top_attack = statistics.get("top_attack_types", [])
        if not top_attack:
            attack_dist = statistics.get("attack_type_distribution", {})
            top_attack = [{"attack_type": k, "count": v} for k, v in attack_dist.items()][:5]

        top_source_ips = statistics.get("top_source_ips", [])
        if not top_source_ips:
            top_source_ips = [{"ip": "No data", "count": 0}]

        severity_data = [{"severity": k, "count": v} for k, v in severity_distribution.items()]

        severity_chart_svg = cls._bar_chart(severity_data, color="#c0392b")
        top_attack_chart_svg = cls._bar_chart(top_attack, color="#2c3e50")
        top_ip_chart_svg = cls._bar_chart(top_source_ips, color="#34495e")

        charts_section = f"""
        <div class="card" id="charts">
            <h2>Visual Breakdown</h2>
            <h3>Severity Distribution</h3>
            <div class="chart">{severity_chart_svg}</div>
            <h3>Top Attack Types</h3>
            <div class="chart">{top_attack_chart_svg}</div>
            <h3>Top Source IPs</h3>
            <div class="chart">{top_ip_chart_svg}</div>
        </div>
        """

        attack_counts: dict[str, int] = {}
        for campaign in campaigns:
            attack_counts[campaign.attack_type] = attack_counts.get(campaign.attack_type, 0) + campaign.failed_attempts
        attack_distribution_data = sorted(attack_counts.items(), key=lambda x: -x[1])

        donut_svg, donut_legend = cls._donut_chart(attack_distribution_data)

        weighted_sum = sum(
            severity_lookup.get(level, 0) * weight
            for level, weight in cls.SEVERITY_WEIGHTS.items()
        )
        total_severity_count = sum(severity_lookup.values()) or 1
        risk_score = weighted_sum / total_severity_count

        risk_gauge_svg = cls._risk_gauge(risk_score)

        attack_and_risk_section = f"""
        <div class="card" id="attack-distribution">
            <h2>Attack Distribution &amp; Risk Score</h2>
            <div class="split-panel">
                <div class="split-half">
                    <h3>Attack Type Distribution</h3>
                    <div class="donut-wrap">
                        {donut_svg}
                        <div class="donut-legend">{donut_legend}</div>
                    </div>
                </div>
                <div class="split-half">
                    <h3>Overall Risk Score</h3>
                    <div class="gauge-wrap">
                        {risk_gauge_svg}
                    </div>
                    <p class="section-note">Weighted from severity distribution (Critical=100, High=75, Medium=45, Low=20).</p>
                </div>
            </div>
        </div>
        """

        # ===== GENERATE KILL CHAIN =====
        kill_chain_section = cls._generate_kill_chain(reports)

        # ===== GENERATE ATTACK GRAPH =====
        attack_graph_section = cls._generate_attack_graph(reports)

        # Timeline
        timeline_rows = ""
        for event in timeline:
            severity_class = cls._esc(str(event.get("severity", "")).lower())
            timeline_rows += f"""
            <tr>
                <td>{cls._esc(event.get("timestamp", ""))}</td>
                <td>{cls._esc(event.get("attack_type", ""))}</td>
                <td class="{severity_class}">{cls._esc(event.get("severity", ""))}</td>
                <td>{cls._esc(event.get("source_ip", ""))}</td>
                <td>{cls._esc(event.get("protocol", ""))}</td>
                <td>{cls._esc(event.get("action", ""))}</td>
            </tr>
            """

        timeline_section = ""
        if timeline_rows:
            timeline_section = f"""
            <div class="card" id="timeline">
                <h2>Attack Timeline</h2>
                <table>
                    <thead>
                        <tr><th>Time</th><th>Attack</th><th>Severity</th><th>Source IP</th><th>Protocol</th><th>Action</th></tr>
                    </thead>
                    <tbody>{timeline_rows}</tbody>
                </table>
            </div>
            """

        # IOCs
        source_ips = set()
        for report in reports:
            for asset in report.affected_assets:
                if asset and asset != "Unknown":
                    source_ips.add(asset)

        ioc_groups = [
            ("Source IP", "ip-src", sorted(source_ips)),
            ("MITRE Technique", "mitre", []),
        ]

        total_iocs = sum(len(values) for _, _, values in ioc_groups)

        ioc_stat_cards = "".join(
            f"""
            <div class="stat-box ioc-stat">
                <span class="stat-number">{len(values)}</span>
                <span class="stat-label">{cls._esc(label)}{'s' if len(values) != 1 and label != 'MITRE Technique' else ''}</span>
            </div>
            """
            for label, _, values in ioc_groups
        )

        def ioc_rows(ioc_type: str, badge_class: str, values: list[str]) -> str:
            if not values:
                return ""
            return "".join(
                f"""
                <tr>
                    <td><span class="ioc-badge {badge_class}">{cls._esc(ioc_type)}</span></td>
                    <td><code>{cls._esc(value)}</code></td>
                </tr>
                """
                for value in values
            )

        ioc_table_rows = "".join(
            ioc_rows(label, badge_class, values) for label, badge_class, values in ioc_groups
        )

        ioc_section = ""
        if total_iocs:
            ioc_section = f"""
            <div class="card" id="iocs">
                <h2>Indicators of Compromise (IOC Dashboard)</h2>
                <div class="dashboard">
                    <div class="stat-box ioc-total">
                        <span class="stat-number">{total_iocs}</span>
                        <span class="stat-label">Total IOCs</span>
                    </div>
                    {ioc_stat_cards}
                </div>
                <table>
                    <thead><tr><th>Type</th><th>Value</th></tr></thead>
                    <tbody>{ioc_table_rows}</tbody>
                </table>
            </div>
            """

        # Campaign rows
        campaign_rows = ""
        for index, campaign in enumerate(campaigns, start=1):
            campaign_rows += f"""
            <tr>
                <td>Campaign {index}</td>
                <td>{cls._esc(campaign.attack_type)}</td>
                <td class="{cls._esc(campaign.risk.lower())}">{cls._esc(campaign.risk)}</td>
                <td>{cls._esc(campaign.source_ip)}</td>
                <td>{campaign.confidence:.2f}</td>
                <td>{campaign.failed_attempts}</td>
            </tr>
            """
        if not campaign_rows:
            campaign_rows = '<tr><td colspan="6">No campaigns detected.</td></tr>'

        # AI Cards
        ai_cards = ""
        for index, report in enumerate(reports, start=1):
            steps = "".join(f"<li>{cls._esc(step)}</li>" for step in report.investigation_steps)
            ai_cards += f"""
            <div class="card">
                <h2>AI Investigation &mdash; Incident {index}</h2>
                <h3>{cls._esc(report.attack_type)}</h3>
                <p><strong>Business Impact</strong></p>
                <p>{cls._esc(report.business_impact)}</p>
                <p><strong>Investigation Steps</strong></p>
                <ul>{steps}</ul>
                <p><strong>Analyst Notes</strong></p>
                <p>{cls._esc(report.analyst_notes)}</p>
                <p><strong>AI Confidence:</strong> {report.confidence:.2f}</p>
            </div>
            """

        # MITRE Cards
        mitre_cards = ""
        for report in reports:
            if report.mitre_attack:
                mitre_cards += f"""
                <div class="card">
                    <h2>MITRE ATT&amp;CK</h2>
                    <table>
                        <tr><th>Technique ID</th><td>{cls._esc(', '.join(report.mitre_attack))}</td></tr>
                        <tr><th>Attack Type</th><td>{cls._esc(report.attack_type)}</td></tr>
                    </table>
                </div>
                """

        html_out = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>AI Security Incident Report &mdash; {report_id}</title>
<style>
* {{ box-sizing: border-box; }}
body {{ font-family: -apple-system, Segoe UI, Arial, sans-serif; background:#f4f4f4; color:#333; padding:30px; max-width:1200px; margin:0 auto; }}
header.report-header {{ display:flex; justify-content:space-between; align-items:flex-end; border-bottom:3px solid #222; padding-bottom:15px; margin-bottom:25px; }}
header.report-header h1 {{ margin:0; color:#222; }}
.meta {{ text-align:right; font-size:13px; color:#666; }}
h1, h2, h3 {{ color:#222; }}
.section-note {{ font-size:13px; color:#777; margin-top:-5px; }}
.card {{ background:white; border-radius:10px; padding:20px; margin-bottom:25px; box-shadow:0 2px 10px rgba(0,0,0,.08); }}
.dashboard {{ display:flex; gap:15px; flex-wrap:wrap; margin:15px 0 25px 0; }}
.stat-box {{ flex:1; min-width:110px; background:#fafafa; border:1px solid #e2e2e2; border-radius:8px; padding:15px; text-align:center; }}
.stat-box .stat-number {{ display:block; font-size:26px; font-weight:bold; color:#222; }}
.stat-box .stat-label {{ display:block; font-size:12px; text-transform:uppercase; letter-spacing:.5px; color:#777; margin-top:4px; }}
.stat-box.critical .stat-number {{ color:#b30000; }}
.stat-box.high .stat-number {{ color:red; }}
.stat-box.medium .stat-number {{ color:orange; }}
.stat-box.low .stat-number {{ color:green; }}
.stat-box.ioc-total {{ background:#1c1c1c; border-color:#1c1c1c; }}
.stat-box.ioc-total .stat-number, .stat-box.ioc-total .stat-label {{ color:white; }}
.stat-box.ioc-stat .stat-number {{ color:#2c3e50; }}
.chart {{ margin:10px 0 25px 0; }}
code {{ background:#f0f0f0; padding:2px 6px; border-radius:4px; font-size:13px; }}
.risk-banner {{ background:#fff4f4; border-left:5px solid #b30000; padding:12px 18px; border-radius:6px; margin:15px 0; }}

.verdict-banner {{ border-radius:10px; padding:22px 26px; margin-bottom:25px; box-shadow:0 3px 14px rgba(0,0,0,.12); border:2px solid transparent; }}
.verdict-top {{ display:flex; justify-content:space-between; align-items:center; flex-wrap:wrap; gap:10px; margin-bottom:12px; }}
.verdict-badge {{ display:inline-block; padding:6px 16px; border-radius:20px; font-size:13px; font-weight:bold; letter-spacing:.5px; color:white; }}
.verdict-priority {{ font-size:13px; color:#555; font-weight:bold; }}
.verdict-text {{ font-size:16px; line-height:1.5; margin:10px 0; color:#222; }}
.verdict-actions-label {{ margin-top:14px; margin-bottom:6px; }}
.verdict-actions {{ margin:0; }}
.verdict-confidence {{ display:flex; align-items:center; gap:10px; margin:10px 0; font-size:12px; color:#555; }}
.verdict-confidence-bar {{ flex:1; max-width:220px; height:8px; background:#eee; border-radius:4px; overflow:hidden; }}
.verdict-confidence-fill {{ height:100%; background:#222; }}

.verdict-critical {{ background:#fdecec; border-color:#b30000; }}
.verdict-badge-critical {{ background:#b30000; }}
.verdict-high {{ background:#fff2e8; border-color:#e08a00; }}
.verdict-badge-high {{ background:#e08a00; }}
.verdict-medium {{ background:#fffaf0; border-color:#e0a800; }}
.verdict-badge-medium {{ background:#e0a800; }}
.verdict-low {{ background:#f0f9f0; border-color:#2a8a2a; }}
.verdict-badge-low {{ background:#2a8a2a; }}
.verdict-unknown {{ background:#f5f5f5; border-color:#999; }}
.verdict-badge-unknown {{ background:#777; }}

.ioc-badge {{ display:inline-block; padding:3px 10px; border-radius:12px; font-size:11px; font-weight:bold; text-transform:uppercase; letter-spacing:.4px; color:white; }}
.ioc-badge.ip-src {{ background:#c0392b; }}
.ioc-badge.ip-dst {{ background:#8e44ad; }}
.ioc-badge.account {{ background:#d68910; }}
.ioc-badge.mitre {{ background:#2c3e50; }}

.kc-flow {{ display:flex; align-items:stretch; overflow-x:auto; padding:10px 0; gap:0; }}
.kc-box {{ min-width:130px; flex:1; border-radius:8px; padding:14px 10px; text-align:center; display:flex; flex-direction:column; gap:4px; border:2px solid #ddd; }}
.kc-box.kc-active {{ background:#fdecec; border-color:#c0392b; }}
.kc-box.kc-inactive {{ background:#fafafa; border-color:#e2e2e2; opacity:0.6; }}
.kc-stage-num {{ font-size:10px; color:#999; font-weight:bold; }}
.kc-stage-name {{ font-size:12px; font-weight:bold; color:#222; }}
.kc-stage-count {{ font-size:11px; color:#666; }}
.kc-stage-percentage {{ font-size:11px; color:#888; font-weight:bold; }}
.kc-box.kc-active .kc-stage-count {{ color:#b30000; font-weight:bold; }}
.kc-arrow {{ display:flex; align-items:center; justify-content:center; font-size:18px; color:#999; padding:0 6px; }}
.kill-chain-legend {{ margin-top:10px; display:flex; gap:20px; font-size:12px; justify-content:center; }}
.kc-legend-item.kc-active {{ color:#b30000; }}
.kc-legend-item.kc-inactive {{ color:#999; }}

.split-panel {{ display:flex; gap:30px; flex-wrap:wrap; }}
.split-half {{ flex:1; min-width:260px; text-align:center; }}
.donut-wrap {{ display:flex; flex-direction:column; align-items:center; gap:10px; }}
.donut-legend {{ text-align:left; font-size:13px; }}
.donut-legend-item {{ display:flex; align-items:center; gap:8px; margin:4px 0; }}
.donut-swatch {{ width:12px; height:12px; border-radius:3px; display:inline-block; }}
.gauge-wrap {{ display:flex; justify-content:center; }}

table {{ width:100%; border-collapse:collapse; margin-top:15px; }}
th, td {{ padding:12px; border:1px solid #ddd; text-align:left; }}
th {{ background:#222; color:white; }}
.high {{ color:red; font-weight:bold; }}
.medium {{ color:orange; font-weight:bold; }}
.low {{ color:green; font-weight:bold; }}
.critical {{ color:#b30000; font-weight:bold; }}
footer.report-footer {{ text-align:center; font-size:12px; color:#999; padding:25px 0 10px 0; border-top:1px solid #ddd; margin-top:20px; }}

@media print {{
    body {{ background:white; padding:0; max-width:none; }}
    .card {{ box-shadow:none; border:1px solid #ddd; break-inside:avoid; }}
    .kc-flow {{ overflow-x:visible; flex-wrap:wrap; }}
}}
</style>
</head>
<body>

<header class="report-header">
    <h1>AI Security Incident Report</h1>
    <div class="meta">
        <div>Report ID: {report_id}</div>
        <div>Generated: {generated_at}</div>
    </div>
</header>

{verdict_section}

<div class="card">
<h2>Executive Summary</h2>
<p>{summary_text}</p>
<div class="risk-banner"><strong>Business Risk:</strong> {business_risk_text}</div>
{confidence_html}
<p><strong>Priority Actions</strong></p>
<ul>{priority_actions_html}</ul>
{dashboard_html}
</div>

{attack_and_risk_section}
{charts_section}
{kill_chain_section}
{attack_graph_section}
{timeline_section}
{ioc_section}

<div class="card">
<h2>Campaign Overview</h2>
<table>
<thead><tr><th>Campaign</th><th>Attack Type</th><th>Risk</th><th>Source IP</th><th>Confidence</th><th>Attempts</th></tr></thead>
<tbody>{campaign_rows}</tbody>
</table>
</div>

{ai_cards}
{mitre_cards}

<footer class="report-footer">
    AI Security Incident Assistant &mdash; Report {report_id} &mdash; Generated {generated_at} &mdash; Confidential
</footer>

</body>
</html>
"""

        with open(target_path, "w", encoding="utf-8") as file:
            file.write(html_out)
            file.flush()
            os.fsync(file.fileno())

        print(f"\nHTML report saved to:\n{target_path.resolve()}")
        return target_path
