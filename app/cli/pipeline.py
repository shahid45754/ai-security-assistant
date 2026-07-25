import json
import sys
import traceback
from pathlib import Path
from typing import Union, Optional

from app.parsers.parser_factory import ParserFactory
from app.services.analyzer import AnalyzerService
from app.services.correlation_engine import CorrelationEngine
from app.services.statistics import StatisticsService
from app.services.timeline_builder import TimelineBuilder
from app.services.report_exporter import ReportExporter
from app.services.html_report import HTMLReport
from app.services.pdf_report import PDFReport
from app.agents.executive_summary_agent import executive_summary_agent
from app.agents.soc_verdict_agent import soc_verdict_agent

from app.cli.ai import (
    run_agent_with_fallback,
    fallback_executive_summary,
    fallback_soc_verdict,
)

# Anchor the reports directory to this file's own location
REPORTS_DIR = Path(__file__).resolve().parent.parent.parent / "app" / "reports"


def _select_parser(log_path: Path):
    """
    Automatically detect the correct parser.
    """
    try:
        # First, try to detect by content
        parser = ParserFactory.get_parser(log_path)
        print(f"✅ Selected parser: {parser.__class__.__name__}")
        return parser
    except ValueError as error:
        # Get supported parsers from ParserFactory
        supported = ", ".join(sorted(ParserFactory._PARSERS.keys()))
        print(f"❌ Parser detection failed: {error}")
        
        # Try fallback: detect by file content directly
        try:
            content = log_path.read_text(encoding='utf-8', errors='ignore')
            
            # Check for CloudTrail JSON
            if content.strip().startswith('{') and 'Records' in content:
                from app.parsers.cloudtrail_parser import CloudTrailParser
                print("✅ Fallback: Auto-detected CloudTrail from content")
                return CloudTrailParser()
            
            # Check for Windows event format
            if 'EventID=' in content or 'Event ID' in content:
                from app.parsers.windows_event_parser import WindowsEventParser
                print("✅ Fallback: Auto-detected Windows from content")
                return WindowsEventParser()
            
            # Check for SSH logs
            if 'ssh' in content.lower() or 'sshd' in content.lower():
                from app.parsers.ssh_parser import SSHParser
                print("✅ Fallback: Auto-detected SSH from content")
                return SSHParser()
            
            # Check for Apache logs
            if '"GET ' in content or '"POST ' in content or '"PUT ' in content:
                from app.parsers.apache_parser import ApacheParser
                print("✅ Fallback: Auto-detected Apache from content")
                return ApacheParser()
            
            # Check for Docker logs
            if 'docker' in content.lower() and 'container' in content.lower():
                from app.parsers.docker_parser import DockerParser
                print("✅ Fallback: Auto-detected Docker from content")
                return DockerParser()
            
            # Check for Kubernetes logs
            if 'kube-apiserver' in content.lower() or 'kubelet' in content.lower():
                from app.parsers.kubernetes_parser import KubernetesParser
                print("✅ Fallback: Auto-detected Kubernetes from content")
                return KubernetesParser()
                
        except Exception as e:
            print(f"⚠️ Fallback detection error: {e}")
        
        raise ValueError(
            f"{error}\n\nSupported parser types:\n{supported}"
        ) from error
    except Exception as e:
        print(f"❌ Unexpected error in parser selection: {e}")
        traceback.print_exc()
        raise


def _parse_log_file(log_path: Path, parser):
    """Parse the log file with error handling."""
    try:
        log_content = log_path.read_text(encoding="utf-8", errors="ignore")
        if not log_content.strip():
            print(f"⚠️ Log file is empty: {log_path}")
            return []
        
        print(f"📄 Log file size: {len(log_content)} characters")
        print(f"📄 First 200 chars: {log_content[:200]}...")
        
        incidents = parser.parse(log_content)
        print(f"📊 Parsed {len(incidents)} incident(s)")
        return incidents
    except Exception as e:
        print(f"❌ Error parsing log file: {e}")
        traceback.print_exc()
        raise


async def run_analysis(log_file: Union[str, Path], parser_type: Optional[str] = None) -> dict:
    """
    End-to-end incident analysis pipeline.

    Args:
        log_file: Path to the log file
        parser_type: Optional explicit parser type to use (e.g., 'docker', 'ssh', etc.)
    """
    log_path = Path(log_file)
    print(f"\n{'='*60}")
    print(f"🚀 Starting analysis for: {log_path.name}")
    print(f"{'='*60}")

    # Check if file exists
    if not log_path.exists():
        print(f"❌ File not found: {log_path}")
        return {
            "status": "file_not_found",
            "log_path": str(log_path),
            "error": f"File not found: {log_path}"
        }

    print(f"📁 File exists: {log_path}")
    print(f"📄 File size: {log_path.stat().st_size} bytes")

    try:
        # Select parser - either explicit or auto-detect
        if parser_type:
            # Use explicitly specified parser
            parser_type_lower = parser_type.lower()
            parser_class = ParserFactory._PARSERS.get(parser_type_lower)
            if parser_class is None:
                supported = ", ".join(sorted(ParserFactory._PARSERS.keys()))
                return {
                    "status": "error",
                    "log_path": str(log_path),
                    "error": f"Parser type '{parser_type}' not found. Supported: {supported}",
                }
            parser = parser_class()
            print(f"🎯 Using explicit parser: {parser_type_lower}")
        else:
            # Auto-detect parser
            parser = _select_parser(log_path)
        
        # Parse the log file
        incidents = _parse_log_file(log_path, parser)
        
        if not incidents:
            print("ℹ️ No incidents were parsed from this log file.")
            return {
                "status": "no_incidents",
                "log_path": str(log_path),
                "incidents": [],
                "message": "No incidents were parsed from this log file."
            }

        # Initialize analyzer
        analyzer = AnalyzerService()
        reports = []
        skipped = []

        # Process each incident
        for index, incident in enumerate(incidents, start=1):
            print("\n" + "=" * 80)
            print(f"📋 Incident {index}")
            try:
                print(incident.model_dump())
            except:
                print(str(incident))

            try:
                report = await analyzer.analyze(incident)
                if report is None:
                    print("⚠️ Analyzer returned: None")
                    skipped.append((index, "Analyzer returned None"))
                else:
                    print("✅ Analyzer successfully created report.")
                    reports.append(report)
            except ValueError as error:
                print(f"❌ ValueError: {error}")
                skipped.append((index, str(error)))
            except Exception as error:
                print(f"❌ Exception: {type(error).__name__}: {error}")
                traceback.print_exc()
                skipped.append(
                    (index, f"AI analysis failed ({type(error).__name__}: {error})")
                )
            print("=" * 80)

        # Check if we have any reports
        if not reports:
            print("❌ No reports were generated.")
            return {
                "status": "no_reports",
                "log_path": str(log_path),
                "incidents": incidents,
                "skipped": skipped,
                "message": "No reports were generated from the incidents."
            }

        # Correlation
        print(f"\n🔗 Correlating {len(reports)} reports...")
        engine = CorrelationEngine()
        campaigns = engine.correlate(reports)
        print(f"📊 Found {len(campaigns)} campaign(s)")

        # Statistics
        print("📊 Building statistics...")
        stats = StatisticsService.build(reports, campaigns)
        
        # Timeline
        print("⏱️ Building timeline...")
        timeline = TimelineBuilder.build(reports)

        # Prepare campaigns for AI
        campaigns_lean = [
            {
                "attack_type": c.attack_type,
                "source_ip": c.source_ip,
                "risk": c.risk,
                "confidence": c.confidence,
                "failed_attempts": c.failed_attempts,
            }
            for c in campaigns
        ]
        campaigns_json = json.dumps(campaigns_lean, indent=2)

        # Generate executive summary
        print("📝 Generating executive summary...")
        summary, summary_from_ai = await run_agent_with_fallback(
            executive_summary_agent.run(
                f"Summarize these {len(campaigns)} correlated attack campaigns:\n"
                f"{campaigns_json}\n\n/no_think"
            ),
            fallback_executive_summary(campaigns, stats),
            "Executive Summary Agent",
        )

        # Generate SOC verdict
        print("⚖️ Generating SOC verdict...")
        verdict_payload = {
            "campaigns": campaigns_lean,
            "statistics": {
                "total_incidents": stats.get("total_incidents", 0),
                "total_campaigns": stats.get("total_campaigns", 0),
                "severity_distribution": stats.get("severity_distribution", {}),
            },
            "summary": summary.model_dump(mode="json"),
        }

        soc_verdict, verdict_from_ai = await run_agent_with_fallback(
            soc_verdict_agent.run(json.dumps(verdict_payload, indent=2) + "\n\n/no_think"),
            fallback_soc_verdict(campaigns, stats),
            "SOC Verdict Agent",
        )

        # Export Reports
        print(f"📁 Exporting reports to: {REPORTS_DIR}")
        REPORTS_DIR.mkdir(parents=True, exist_ok=True)
        report_name = f"{log_path.stem}_report"

        json_report = ReportExporter.export_json(
            campaigns,
            output_path=REPORTS_DIR / f"{report_name}.json",
        )

        markdown_report = ReportExporter.export_markdown(
            campaigns,
            output_path=REPORTS_DIR / f"{report_name}.md",
        )

        html_report = HTMLReport.export(
            reports=reports,
            campaigns=campaigns,
            statistics=stats,
            summary=summary.model_dump(),
            timeline=timeline,
            soc_verdict=soc_verdict.model_dump(),
            output_path=REPORTS_DIR / f"{report_name}.html",
        )

        pdf_report = PDFReport.export(
            reports=reports,
            campaigns=campaigns,
            statistics=stats,
            summary=summary.model_dump(),
            soc_verdict=soc_verdict.model_dump(),
            output_path=REPORTS_DIR / f"{report_name}.pdf",
        )

        print(f"\n{'='*60}")
        print("✅ Analysis completed successfully!")
        print(f"📊 Reports: {len(reports)}, Campaigns: {len(campaigns)}")
        print(f"📁 Reports saved to: {REPORTS_DIR}")
        print(f"{'='*60}")

        return {
            "status": "ok",
            "log_path": str(log_path),
            "incidents": incidents,
            "reports": reports,
            "skipped": skipped,
            "campaigns": campaigns,
            "campaigns_lean": campaigns_lean,
            "stats": stats,
            "timeline": timeline,
            "summary": summary,
            "summary_from_ai": summary_from_ai,
            "soc_verdict": soc_verdict,
            "verdict_from_ai": verdict_from_ai,
            "exports": {
                "json": json_report,
                "markdown": markdown_report,
                "html": html_report,
                "pdf": pdf_report,
            },
        }

    except Exception as e:
        error_msg = f"Analysis failed: {str(e)}\n{traceback.format_exc()}"
        print(f"❌ {error_msg}")
        return {
            "status": "error",
            "log_path": str(log_path),
            "error": str(e),
            "traceback": traceback.format_exc()
        }
