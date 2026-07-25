import json
import asyncio
from typing import Optional, Dict, Any
from datetime import datetime

from app.models.incident import Incident
from app.models.response import IncidentAnalysis
from app.agents.security_agent import security_agent
from app.core.utils import sanitize_text, sanitize_for_json, remove_control_chars


class AnalyzerService:
    """Service for analyzing incidents using AI agents."""
    
    async def analyze(self, incident: Incident) -> Optional[IncidentAnalysis]:
        """
        Analyze an incident using the security agent.
        """
        try:
            # ===== SANITIZE INCIDENT DATA =====
            # Sanitize all string fields in the incident
            if incident.title:
                incident.title = sanitize_text(incident.title)
            if incident.description:
                incident.description = sanitize_text(incident.description)
            if incident.source_ip:
                incident.source_ip = sanitize_text(incident.source_ip)
            if incident.destination_ip:
                incident.destination_ip = sanitize_text(incident.destination_ip)
            if incident.username:
                incident.username = sanitize_text(incident.username)
            if incident.action:
                incident.action = sanitize_text(incident.action)
            if incident.protocol:
                incident.protocol = sanitize_text(incident.protocol)
            
            # ===== PREPARE DATA FOR AGENT =====
            # Create a clean dict with sanitized data
            incident_data = {
                "title": incident.title or "Unknown",
                "description": incident.description or "No description",
                "source_ip": incident.source_ip or "Unknown",
                "destination_ip": incident.destination_ip or "Unknown",
                "username": incident.username or "Unknown",
                "protocol": incident.protocol or "Unknown",
                "port": incident.port,
                "action": incident.action or "Unknown",
                "log_source": incident.log_source,
                "timestamp": incident.timestamp.isoformat() if incident.timestamp else datetime.now().isoformat(),
            }
            
            # Sanitize the entire dict
            incident_data = sanitize_for_json(incident_data)
            
            # ===== SANITIZE THE PROMPT =====
            # Convert to JSON string with proper escaping
            json_str = json.dumps(incident_data, ensure_ascii=False, default=str)
            # Remove any remaining control characters
            json_str = remove_control_chars(json_str)
            
            # Create a clean prompt
            prompt = f"""
Analyze this security incident and provide a structured analysis:

Incident Data:
{json_str}

Provide the analysis with these exact fields:
- attack_type: The type of attack (e.g., "Directory Traversal", "SQL Injection", "XSS", "Brute Force", "Access Denied")
- severity: The severity level (Critical, High, Medium, Low)
- confidence: Confidence score (0.0 to 1.0) based on the evidence
- description: Brief description of the incident
- affected_assets: List of affected assets (IPs, systems, etc.)
- recommendations: List of recommended actions (3-5 items)
- mitre_attack: MITRE ATT&CK technique IDs (list)
- timeline: List of timeline events with time and description
- business_impact: Business impact assessment (1-2 sentences)
- investigation_steps: Steps for investigation (3-5 items)
- analyst_notes: Additional notes for the analyst (1-2 sentences)
"""
            
            # Sanitize the prompt
            prompt = sanitize_text(prompt)
            prompt = remove_control_chars(prompt)
            
            # ===== RUN THE AGENT =====
            try:
                # Run the agent with the sanitized prompt
                # Try async first
                try:
                    result = await security_agent.run(prompt)
                except TypeError:
                    # If run is not async, use sync
                    result = security_agent.run_sync(prompt)
                
                # Sanitize the result
                if hasattr(result, 'output'):
                    if isinstance(result.output, dict):
                        result.output = sanitize_for_json(result.output)
                    elif isinstance(result.output, str):
                        result.output = sanitize_text(result.output)
                
                return result.output
                
            except Exception as e:
                print(f"⚠️ Agent analysis failed: {e}")
                # Return a fallback analysis
                return self._create_fallback_analysis(incident)
                
        except Exception as e:
            print(f"❌ Analysis error: {e}")
            import traceback
            traceback.print_exc()
            return self._create_fallback_analysis(incident)
    
    def _create_fallback_analysis(self, incident: Incident) -> IncidentAnalysis:
        """Create a fallback analysis when the agent fails."""
        from app.models.response import IncidentAnalysis
        
        # Determine attack type from title or action
        attack_type = "Unknown"
        title_lower = incident.title.lower() if incident.title else ""
        description_lower = incident.description.lower() if incident.description else ""
        
        if "directory traversal" in title_lower or "directory traversal" in description_lower:
            attack_type = "Directory Traversal"
        elif "cross site scripting" in title_lower or "xss" in title_lower or "xss" in description_lower:
            attack_type = "Cross Site Scripting (XSS)"
        elif "sql injection" in title_lower or "sql" in title_lower and "injection" in description_lower:
            attack_type = "SQL Injection"
        elif "brute force" in title_lower or "brute force" in description_lower:
            attack_type = "Brute Force"
        elif "403" in title_lower or "forbidden" in title_lower:
            attack_type = "Access Denied"
        elif "404" in title_lower or "not found" in title_lower:
            attack_type = "Resource Not Found"
        elif incident.action:
            attack_type = incident.action.replace("Apache_", "").replace("_", " ")
        
        # Determine severity
        severity = "Medium"
        if "critical" in title_lower or "critical" in description_lower:
            severity = "Critical"
        elif "high" in title_lower or "high" in description_lower:
            severity = "High"
        elif "low" in title_lower or "low" in description_lower:
            severity = "Low"
        
        # Build recommendations based on attack type
        recommendations = [
            "Review the incident details in the logs",
            "Check for similar patterns from the same source IP",
            "Implement appropriate security controls"
        ]
        
        if "Directory Traversal" in attack_type:
            recommendations = [
                "Implement input validation for file paths",
                "Use allowlists for allowed file paths",
                "Restrict file system access permissions",
                "Monitor for similar traversal attempts",
                "Consider using a Web Application Firewall"
            ]
        elif "XSS" in attack_type or "Cross Site Scripting" in attack_type:
            recommendations = [
                "Implement output encoding for user input",
                "Use Content Security Policy (CSP) headers",
                "Validate and sanitize all user input",
                "Use HTTP-only cookies for sensitive data",
                "Consider using a Web Application Firewall"
            ]
        elif "SQL Injection" in attack_type:
            recommendations = [
                "Use parameterized queries or prepared statements",
                "Implement input sanitization",
                "Use an application firewall",
                "Review database access logs",
                "Consider using an ORM framework"
            ]
        elif "Brute Force" in attack_type:
            recommendations = [
                "Implement account lockout policies",
                "Enable MFA for user accounts",
                "Use rate limiting on login endpoints",
                "Monitor for failed login patterns",
                "Block the source IP if needed"
            ]
        
        # Build business impact
        business_impact = (
            f"The {attack_type} attack could potentially lead to "
            f"unauthorized access, data exposure, or system compromise. "
            f"Immediate investigation and mitigation are recommended."
        )
        
        # Build investigation steps
        investigation_steps = [
            f"Verify the source IP: {incident.source_ip or 'Unknown'}",
            "Review relevant logs for similar patterns",
            "Check if any data was exfiltrated or modified",
            "Confirm if the attack was successful",
            "Implement necessary security controls"
        ]
        
        # Build analyst notes
        analyst_notes = (
            f"Incident detected at {incident.timestamp.strftime('%Y-%m-%d %H:%M:%S') if incident.timestamp else 'Unknown time'}. "
            f"Attack type identified as {attack_type} with {severity} severity. "
            f"Source IP: {incident.source_ip or 'Unknown'}. "
            f"Action: {incident.action or 'Unknown'}."
        )
        
        # Build timeline
        timeline = [{
            "time": incident.timestamp.isoformat() if incident.timestamp else datetime.now().isoformat(),
            "event": incident.description[:200] if incident.description else "Incident detected"
        }]
        
        # Get MITRE techniques
        mitre_attack = ["T1190"]  # Default: Exploit Public-Facing Application
        if "Directory Traversal" in attack_type:
            mitre_attack = ["T1006"]  # Directory Traversal
        elif "XSS" in attack_type or "Cross Site Scripting" in attack_type:
            mitre_attack = ["T1059"]  # Command and Scripting Interpreter
        elif "SQL Injection" in attack_type:
            mitre_attack = ["T1190"]  # Exploit Public-Facing Application
        elif "Brute Force" in attack_type:
            mitre_attack = ["T1110"]  # Brute Force
        
        return IncidentAnalysis(
            attack_type=attack_type,
            severity=severity,
            confidence=0.75,
            description=f"Analysis of {attack_type} incident from {incident.source_ip or 'unknown source'}",
            affected_assets=[incident.source_ip] if incident.source_ip else ["Unknown"],
            recommendations=recommendations[:5],
            mitre_attack=mitre_attack,
            timeline=timeline,
            business_impact=business_impact,
            investigation_steps=investigation_steps,
            analyst_notes=analyst_notes
        )
