from typing import List, Dict, Any
from collections import defaultdict

from app.models.response import IncidentAnalysis


class AttackGraph:
    """Service for building attack graphs from reports."""
    
    @classmethod
    def build(cls, reports: List[IncidentAnalysis]) -> str:
        """
        Build an attack graph visualization from reports.
        """
        if not reports:
            return '<div class="card"><h2>Attack Graph</h2><p>No data available to build attack graph.</p></div>'
        
        graph_data = cls._build_graph_data(reports)
        
        if not graph_data or not graph_data.get('source_to_targets'):
            return '<div class="card"><h2>Attack Graph</h2><p>No connections found between incidents.</p></div>'
        
        return cls._render_graph(graph_data)
    
    @classmethod
    def _build_graph_data(cls, reports: List[IncidentAnalysis]) -> Dict[str, Any]:
        """Build attack graph data from reports."""
        source_to_targets = defaultdict(list)
        
        for report in reports:
            # Get source IP from affected assets
            source_ip = None
            if report.affected_assets and report.affected_assets[0] != "Unknown":
                source_ip = report.affected_assets[0]
            
            attack_type = report.attack_type if hasattr(report, 'attack_type') else 'Unknown'
            severity = report.severity if hasattr(report, 'severity') else 'Medium'
            
            if source_ip and attack_type:
                target = f"{attack_type}"
                source_to_targets[source_ip].append({
                    'target': target,
                    'attack_type': attack_type,
                    'severity': severity
                })
        
        return {
            'source_to_targets': dict(source_to_targets)
        }
    
    @classmethod
    def _render_graph(cls, graph_data: Dict[str, Any]) -> str:
        """Render attack graph as HTML."""
        source_to_targets = graph_data.get('source_to_targets', {})
        
        if not source_to_targets:
            return '<div class="card"><h2>Attack Graph</h2><p>No connections found between incidents.</p></div>'
        
        # Add CSS for attack graph
        flow_html = '''
        <style>
        .ag-flow {
            display: flex;
            flex-direction: column;
            gap: 18px;
            margin-top: 15px;
        }
        .ag-source-row {
            display: flex;
            align-items: center;
            gap: 14px;
            background: #f8f9fa;
            border: 1px solid #e2e2e2;
            border-radius: 10px;
            padding: 16px 20px;
            flex-wrap: wrap;
        }
        .ag-ip-node {
            background: #2c3e50;
            color: white;
            font-weight: bold;
            font-size: 14px;
            padding: 10px 18px;
            border-radius: 8px;
            white-space: nowrap;
            display: flex;
            align-items: center;
            gap: 8px;
        }
        .ag-ip-node .ip-icon {
            font-size: 18px;
        }
        .ag-arrow-main {
            font-size: 24px;
            color: #6c5ce7;
            font-weight: bold;
        }
        .ag-edge-list {
            display: flex;
            flex-direction: column;
            gap: 8px;
            flex: 1;
        }
        .ag-edge {
            display: flex;
            align-items: center;
            gap: 10px;
            flex-wrap: wrap;
            padding: 8px 12px;
            background: white;
            border-radius: 6px;
            border: 1px solid #eef1f5;
        }
        .ag-attack-node {
            background: #fdecec;
            color: #b30000;
            font-weight: bold;
            font-size: 13px;
            padding: 6px 14px;
            border-radius: 6px;
            border: 1px solid #f3caca;
            display: flex;
            align-items: center;
            gap: 6px;
        }
        .ag-target-node {
            background: #eef3fb;
            color: #2c3e50;
            font-weight: bold;
            font-size: 13px;
            padding: 6px 14px;
            border-radius: 6px;
            border: 1px solid #cfe0f5;
            display: flex;
            align-items: center;
            gap: 6px;
        }
        .ag-arrow {
            font-size: 18px;
            color: #999;
        }
        .ag-severity {
            font-size: 11px;
            padding: 2px 10px;
            border-radius: 12px;
            font-weight: bold;
        }
        .ag-severity-critical { background: #dc3545; color: white; }
        .ag-severity-high { background: #fd7e14; color: white; }
        .ag-severity-medium { background: #ffc107; color: #333; }
        .ag-severity-low { background: #28a745; color: white; }
        </style>
        '''
        
        flow_html += '<div class="ag-flow">'
        
        for source_ip, targets in source_to_targets.items():
            severity_class = "ag-severity-high"
            for t in targets:
                sev = t.get('severity', 'Medium').lower()
                if sev == 'critical':
                    severity_class = "ag-severity-critical"
                elif sev == 'high':
                    severity_class = "ag-severity-high"
                elif sev == 'medium':
                    severity_class = "ag-severity-medium"
                elif sev == 'low':
                    severity_class = "ag-severity-low"
            
            flow_html += f'''
            <div class="ag-source-row">
                <div class="ag-ip-node">
                    <span class="ip-icon">🔴</span> {source_ip}
                </div>
                <span class="ag-arrow-main">⟶</span>
                <div class="ag-edge-list">
            '''
            
            for target in targets:
                attack_type = target.get('attack_type', 'Unknown')
                target_ip = target.get('target', 'Unknown')
                severity = target.get('severity', 'Medium')
                sev_class = f"ag-severity-{severity.lower()}"
                
                flow_html += f'''
                <div class="ag-edge">
                    <span class="ag-attack-node">⚡ {attack_type}</span>
                    <span class="ag-arrow">⟶</span>
                    <span class="ag-target-node">🎯 {target_ip}</span>
                    <span class="ag-severity {sev_class}">{severity}</span>
                </div>
                '''
            
            flow_html += '</div></div>'
        
        flow_html += '</div>'
        
        return f'''
        <div class="card" id="attack-graph">
            <h2>Attack Graph</h2>
            <p class="section-note">Visual representation of attack flow from source IPs through attack types.</p>
            {flow_html}
        </div>
        '''
