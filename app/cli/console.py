

import sys
import asyncio
from pathlib import Path

from app.cli.pipeline import run_analysis


async def run_console():
    """Run the CLI console."""
    if len(sys.argv) < 2:
        print("=" * 60)
        print("🔒 Security Incident Assistant - CLI")
        print("=" * 60)
        print("Usage: python run.py <log_file>")
        print("Example: python run.py app/sample_logs/apache/apache.log")
        print("")
        print("Supported log types:")
        print("  - Apache, Nginx, SSH, Windows Events")
        print("  - Docker, Kubernetes, CloudTrail")
        print("  - Suricata, Zeek, VPN, Proxy")
        print("  - And more...")
        print("=" * 60)
        sys.exit(1)
    
    log_file = sys.argv[1]
    log_path = Path(log_file)
    
    if not log_path.exists():
        print(f"❌ Error: File not found: {log_file}")
        sys.exit(1)
    
    result = await run_analysis(log_path)
    
    if result.get('status') == 'ok':
        print(f"\n{'='*60}")
        print("✅ Analysis completed successfully!")
        print(f"{'='*60}")
        print(f"📊 Incidents: {len(result.get('incidents', []))}")
        print(f"📊 Reports: {len(result.get('reports', []))}")
        print(f"📊 Campaigns: {len(result.get('campaigns', []))}")
        
        exports = result.get('exports', {})
        if exports:
            print(f"\n📁 Reports saved:")
            for key, path in exports.items():
                print(f"   - {key.upper()}: {path}")
        
        print(f"{'='*60}")
    else:
        print(f"\n❌ Analysis failed: {result.get('error', 'Unknown error')}")
        if 'traceback' in result:
            print(f"\n📋 Traceback:\n{result['traceback']}")
        sys.exit(1)


if __name__ == "__main__":
    asyncio.run(run_console())
