import re
from typing import List, Set, Dict, Any
from ipaddress import ip_address, ip_network

from app.models.response import IncidentAnalysis


class IOCExtractor:
    """Service for extracting Indicators of Compromise."""
    
    @classmethod
    def extract(cls, reports: List[IncidentAnalysis]) -> Dict[str, List[str]]:
        """
        Extract IOCs from reports.
        """
        iocs = {
            "ip_addresses": [],
            "domains": [],
            "urls": [],
            "file_hashes": [],
            "email_addresses": [],
            "usernames": [],
        }
        
        for report in reports:
            # Extract IPs from affected assets
            for asset in report.affected_assets:
                if asset and asset != "Unknown":
                    if cls._is_ip(asset):
                        iocs["ip_addresses"].append(asset)
                    elif cls._is_domain(asset):
                        iocs["domains"].append(asset)
                    elif "@" in asset:
                        iocs["email_addresses"].append(asset)
            
            # Extract from description
            description = report.description or ""
            for ip in cls._extract_ips(description):
                if ip not in iocs["ip_addresses"]:
                    iocs["ip_addresses"].append(ip)
            
            for domain in cls._extract_domains(description):
                if domain not in iocs["domains"]:
                    iocs["domains"].append(domain)
        
        # Deduplicate
        for key in iocs:
            iocs[key] = list(set(iocs[key]))
        
        return iocs
    
    @staticmethod
    def _is_ip(value: str) -> bool:
        """Check if value is an IP address."""
        try:
            ip_address(value)
            return True
        except:
            return False
    
    @staticmethod
    def _is_domain(value: str) -> bool:
        """Check if value is a domain."""
        pattern = r'^[a-zA-Z0-9][a-zA-Z0-9-]{1,61}[a-zA-Z0-9]\.[a-zA-Z]{2,}$'
        return bool(re.match(pattern, value))
    
    @staticmethod
    def _extract_ips(text: str) -> List[str]:
        """Extract IP addresses from text."""
        pattern = r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'
        return re.findall(pattern, text)
    
    @staticmethod
    def _extract_domains(text: str) -> List[str]:
        """Extract domain names from text."""
        pattern = r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b'
        return re.findall(pattern, text)
