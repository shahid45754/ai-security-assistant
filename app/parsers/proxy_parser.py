import re
from datetime import datetime
from typing import Optional
from urllib.parse import urlparse

from app.models.incident import Incident
from app.parsers.base_parser import BaseParser
from app.core.utils import sanitize_text


class ProxyParser(BaseParser):
    """Parser for proxy server logs."""
    
    SUSPICIOUS_DOMAINS = {
        'evil-login': 'Phishing Domain',
        'malware': 'Malware Domain',
        'phishing': 'Phishing Domain',
        'c2': 'Command and Control',
        'command': 'Command and Control',
        'control': 'Command and Control',
        'botnet': 'Botnet Domain',
        'ransom': 'Ransomware Domain',
        'trojan': 'Trojan Domain',
    }
    
    SUSPICIOUS_EXTENSIONS = {
        '.exe': 'Executable File',
        '.scr': 'Screen Saver',
        '.bat': 'Batch File',
        '.com': 'Command File',
        '.pif': 'Program Information File',
        '.vbs': 'VBScript',
        '.js': 'JavaScript',
        '.jar': 'Java Archive',
        '.msi': 'Installer',
        '.docm': 'Word Macro',
        '.xlsm': 'Excel Macro',
        '.pptm': 'PowerPoint Macro',
        '.hta': 'HTML Application',
        '.ps1': 'PowerShell Script',
        '.py': 'Python Script',
        '.sh': 'Shell Script',
    }

    def parse(self, content: str) -> list[Incident]:
        incidents = []
        
        for line in content.splitlines():
            if not line.strip():
                continue
            
            incident = self._parse_line(line)
            if incident:
                incidents.append(incident)
                
        return incidents

    def _parse_line(self, line: str) -> Optional[Incident]:
        parts = line.strip().split()
        
        if len(parts) < 3:
            return None
        
        source_ip = parts[0]
        method = parts[1].upper() if len(parts) > 1 else 'GET'
        url = parts[2] if len(parts) > 2 else ''
        status_code = parts[3] if len(parts) > 3 else ''
        
        parsed_url = self._parse_url(url)
        attack_type = self._detect_attack(url, parsed_url, method)
        
        if not attack_type:
            return None
        
        description = f"Proxy: {attack_type} - {method} {url[:100]}"
        if status_code:
            description += f" - Status: {status_code}"
        
        description = sanitize_text(description)
        
        severity = 'Critical' if 'Malware' in attack_type or 'Command and Control' in attack_type else 'High'
        
        return Incident(
            title=f"Proxy: {attack_type} - {parsed_url['domain'] if parsed_url['domain'] else 'Unknown'}",
            description=description[:500],
            source_ip=source_ip,
            destination_ip=None,
            username=None,
            protocol="proxy",
            port=80 if method == 'GET' else 443,
            action=f"Proxy_{attack_type.replace(' ', '_')}",
            log_source="proxy",
            timestamp=datetime.now(),
        )

    def _parse_url(self, url: str) -> dict:
        result = {'scheme': '', 'domain': '', 'path': '', 'query': '', 'file': '', 'extension': '', 'full': url}
        
        if not url:
            return result
        
        try:
            parsed = urlparse(url)
            result['scheme'] = parsed.scheme
            result['domain'] = parsed.netloc
            result['path'] = parsed.path
            result['query'] = parsed.query
            
            if parsed.path:
                path_parts = parsed.path.split('/')
                if path_parts:
                    result['file'] = path_parts[-1]
                    if '.' in result['file']:
                        file_parts = result['file'].split('.')
                        if len(file_parts) > 1:
                            result['extension'] = '.' + file_parts[-1].lower()
        except:
            pass
        
        return result

    def _detect_attack(self, url: str, parsed_url: dict, method: str) -> Optional[str]:
        domain = parsed_url.get('domain', '').lower()
        path = parsed_url.get('path', '').lower()
        file = parsed_url.get('file', '').lower()
        extension = parsed_url.get('extension', '').lower()
        
        for suspicious, threat in self.SUSPICIOUS_DOMAINS.items():
            if suspicious in domain:
                return threat
        
        if extension and extension in self.SUSPICIOUS_EXTENSIONS:
            return f"Suspicious File Download ({self.SUSPICIOUS_EXTENSIONS[extension]})"
        
        suspicious_paths = ['/login', '/auth', '/verify', '/password', '/reset', '/admin', '/config']
        for sus_path in suspicious_paths:
            if sus_path in path:
                return 'Suspicious Path Access'
        
        return None
