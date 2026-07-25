from typing import List, Dict, Any

from app.models.response import IncidentAnalysis


class KillChainService:
    """Service for mapping incidents to Cyber Kill Chain stages."""
    
    KILL_CHAIN_STAGES = [
        "Reconnaissance",
        "Weaponization",
        "Delivery",
        "Exploitation",
        "Installation",
        "Command & Control",
        "Actions on Objectives",
    ]
    
    # Attack type to kill chain stage mapping
    ATTACK_TO_KILL_CHAIN = {
        # Reconnaissance
        'Admin Access': 'Reconnaissance',
        'Access Denied': 'Reconnaissance',
        'Scanning Activity': 'Reconnaissance',
        'Network Reconnaissance': 'Reconnaissance',
        'Brute Force': 'Reconnaissance',
        'Password Spraying': 'Reconnaissance',
        'Credential Stuffing': 'Reconnaissance',
        'Port Scan': 'Reconnaissance',
        
        # Weaponization
        'Malware': 'Weaponization',
        'Ransomware': 'Weaponization',
        'Exploit Attempt': 'Weaponization',
        
        # Delivery
        'Phishing': 'Delivery',
        'Phishing Email': 'Delivery',
        'Malicious File Upload': 'Delivery',
        'File Upload Abuse': 'Delivery',
        'Suspicious Email Attachment': 'Delivery',
        
        # Exploitation
        'Directory Traversal': 'Exploitation',
        'SQL Injection': 'Exploitation',
        'Cross Site Scripting': 'Exploitation',
        'Command Injection': 'Exploitation',
        'XSS': 'Exploitation',
        'Privilege Escalation': 'Exploitation',
        'RCE Attempt': 'Exploitation',
        'Remote Code Execution': 'Exploitation',
        'SSRF': 'Exploitation',
        'XXE': 'Exploitation',
        'SSTI': 'Exploitation',
        'Log4j': 'Exploitation',
        
        # Installation
        'Web Shell': 'Installation',
        'Reverse Shell': 'Installation',
        'Service Installation': 'Installation',
        'Scheduled Task Creation': 'Installation',
        'Scheduled Task Persistence': 'Installation',
        'PowerShell Abuse': 'Installation',
        
        # Command & Control
        'Command and Control': 'Command & Control',
        'DNS Tunneling': 'Command & Control',
        'Beaconing': 'Command & Control',
        'Botnet Activity': 'Command & Control',
        
        # Actions on Objectives
        'Data Exfiltration': 'Actions on Objectives',
        'Lateral Movement': 'Actions on Objectives',
        'Unauthorized Access': 'Actions on Objectives',
        'Credential Dumping': 'Actions on Objectives',
        'Kerberoasting': 'Actions on Objectives',
        'Pass the Hash': 'Actions on Objectives',
        'Golden Ticket': 'Actions on Objectives',
        'Business Email Compromise': 'Actions on Objectives',
        'Impossible Travel': 'Actions on Objectives',
        'Suspicious Login': 'Actions on Objectives',
    }
    
    @classmethod
    def map_incident(cls, incident: IncidentAnalysis) -> str:
        """Map an incident to a kill chain stage."""
        attack_type = incident.attack_type if hasattr(incident, 'attack_type') else ''
        return cls.ATTACK_TO_KILL_CHAIN.get(attack_type, 'Unknown')
    
    @classmethod
    def map_reports(cls, reports: List[IncidentAnalysis]) -> Dict[str, int]:
        """Map all reports to kill chain stages."""
        stage_counts = {stage: 0 for stage in cls.KILL_CHAIN_STAGES}
        stage_counts['Unknown'] = 0
        
        for report in reports:
            stage = cls.map_incident(report)
            if stage in stage_counts:
                stage_counts[stage] += 1
            else:
                stage_counts['Unknown'] += 1
        
        return stage_counts
    
    @classmethod
    def get_stage_description(cls, stage: str) -> str:
        """Get description for a kill chain stage."""
        descriptions = {
            'Reconnaissance': 'Attackers gather information about the target',
            'Weaponization': 'Attackers create malicious payloads',
            'Delivery': 'Attackers deliver the payload to the target',
            'Exploitation': 'Attackers exploit vulnerabilities',
            'Installation': 'Attackers install malware or backdoors',
            'Command & Control': 'Attackers establish C2 communication',
            'Actions on Objectives': 'Attackers achieve their objectives',
            'Unknown': 'Stage could not be determined',
        }
        return descriptions.get(stage, 'Unknown stage')
