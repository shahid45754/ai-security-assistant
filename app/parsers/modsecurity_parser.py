import re
from datetime import datetime
from typing import Optional

from app.models.incident import Incident
from app.parsers.base_parser import BaseParser
from app.core.utils import sanitize_text


class ModSecurityParser(BaseParser):
    """Parser for ModSecurity WAF logs."""
    
    ATTACK_PATTERNS = {
        'SQL Injection': {
            'patterns': [r'sql injection', r'union\s+select', r'or\s+1=1', r'information_schema', r"'--"],
            'severity': 'Critical',
            'mitre': 'T1190',
            'description': 'SQL Injection Attack',
            'action': 'ModSecurity_SQL_Injection'
        },
        'XSS': {
            'patterns': [r'xss', r'cross-site', r'<script', r'alert\(', r'onerror='],
            'severity': 'High',
            'mitre': 'T1059',
            'description': 'Cross-Site Scripting (XSS) Attack',
            'action': 'ModSecurity_XSS'
        },
        'Path Traversal': {
            'patterns': [r'path traversal', r'directory traversal', r'\.\./', r'/etc/passwd'],
            'severity': 'High',
            'mitre': 'T1006',
            'description': 'Path/Directory Traversal Attack',
            'action': 'ModSecurity_Path_Traversal'
        },
        'Command Injection': {
            'patterns': [r'command injection', r'cmd=', r'exec=', r'system='],
            'severity': 'Critical',
            'mitre': 'T1059',
            'description': 'Command Injection Attack',
            'action': 'ModSecurity_Command_Injection'
        },
        'Local File Inclusion': {
            'patterns': [r'lfi', r'local file', r'php://filter', r'php://input'],
            'severity': 'High',
            'mitre': 'T1006',
            'description': 'Local File Inclusion (LFI) Attack',
            'action': 'ModSecurity_LFI'
        },
        'Remote File Inclusion': {
            'patterns': [r'rfi', r'remote file', r'http://', r'https://', r'include='],
            'severity': 'Critical',
            'mitre': 'T1190',
            'description': 'Remote File Inclusion (RFI) Attack',
            'action': 'ModSecurity_RFI'
        },
        'Admin Access': {
            'patterns': [r'admin', r'config', r'backup', r'/admin/', r'/wp-admin/'],
            'severity': 'High',
            'mitre': 'T1078',
            'description': 'Unauthorized Admin Access Attempt',
            'action': 'ModSecurity_Admin_Access'
        },
        'RCE Attempt': {
            'patterns': [r'rce', r'remote code', r'eval\(', r'assert\('],
            'severity': 'Critical',
            'mitre': 'T1190',
            'description': 'Remote Code Execution (RCE) Attempt',
            'action': 'ModSecurity_RCE'
        },
        'SSRF': {
            'patterns': [r'ssrf', r'server side request', r'169.254.169.254', r'metadata'],
            'severity': 'Critical',
            'mitre': 'T1190',
            'description': 'Server-Side Request Forgery (SSRF)',
            'action': 'ModSecurity_SSRF'
        },
        'XXE': {
            'patterns': [r'xxe', r'xml external entity', r'<!entity', r'<!DOCTYPE'],
            'severity': 'High',
            'mitre': 'T1190',
            'description': 'XML External Entity (XXE) Attack',
            'action': 'ModSecurity_XXE'
        },
        'SSTI': {
            'patterns': [r'ssti', r'server side template', r'{{', r'}}', r'#{'],
            'severity': 'High',
            'mitre': 'T1190',
            'description': 'Server-Side Template Injection (SSTI)',
            'action': 'ModSecurity_SSTI'
        },
        'Log4j': {
            'patterns': [r'jndi', r'ldap', r'\$\{jndi', r'log4j'],
            'severity': 'Critical',
            'mitre': 'T1190',
            'description': 'Log4j Vulnerability Exploitation',
            'action': 'ModSecurity_Log4j'
        }
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
        timestamp = self._extract_timestamp(line)
        source_ip = self._extract_ip(line)
        
        attack_type = self._extract_attack_type(line)
        if not attack_type:
            attack_type = self._detect_attack_type(line)
        
        if not attack_type:
            return None
        
        attack_info = self.ATTACK_PATTERNS.get(attack_type, {})
        
        method_match = re.search(r'"(GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH)\s+([^"]+)"', line)
        method = method_match.group(1) if method_match else None
        url = method_match.group(2) if method_match else None
        
        status_match = re.search(r'"\s+(\d{3})\s+', line)
        status_code = status_match.group(1) if status_match else None
        
        description = f"ModSecurity: {attack_info.get('description', attack_type)}"
        if method and url:
            description += f" - {method} {url[:100]}"
        if status_code:
            description += f" - Status: {status_code}"
        if source_ip:
            description += f" - Source: {source_ip}"
        
        description = sanitize_text(description)
        
        severity = attack_info.get('severity', 'Medium')
        action = attack_info.get('action', f"ModSecurity_{attack_type.replace(' ', '_')}")
        
        return Incident(
            title=f"ModSecurity: {attack_type} Detected",
            description=description[:500],
            source_ip=source_ip,
            destination_ip=None,
            username=None,
            protocol="HTTP",
            port=443 if '443' in line else 80,
            action=action,
            log_source="modsecurity",
            timestamp=timestamp,
        )

    def _extract_timestamp(self, line: str) -> datetime:
        match = re.search(r'\[(\d{1,2})/([A-Za-z]{3})/(\d{4}):(\d{2}):(\d{2}):(\d{2})\s+[+-]\d{4}\]', line)
        if match:
            day, month, year, hour, minute, second = match.groups()
            month_map = {'Jan': 1, 'Feb': 2, 'Mar': 3, 'Apr': 4, 'May': 5, 'Jun': 6,
                        'Jul': 7, 'Aug': 8, 'Sep': 9, 'Oct': 10, 'Nov': 11, 'Dec': 12}
            try:
                return datetime(int(year), month_map[month], int(day), int(hour), int(minute), int(second))
            except:
                pass
        
        match = re.search(r'(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})', line)
        if match:
            try:
                return datetime.fromisoformat(match.group(1))
            except:
                pass
        
        return datetime.now()

    def _extract_ip(self, line: str) -> Optional[str]:
        match = re.search(r'\]\s+(\d+\.\d+\.\d+\.\d+)\s+\d+\s+\d+\.\d+\.\d+\.\d+', line)
        if match:
            return match.group(1)
        
        ip_match = re.search(r'\d+\.\d+\.\d+\.\d+', line)
        if ip_match:
            return ip_match.group(0)
        
        return None

    def _extract_attack_type(self, line: str) -> Optional[str]:
        match = re.search(r'ModSecurity:\s+([^"]+?)(?:\s+detected|$)', line, re.IGNORECASE)
        if match:
            attack = match.group(1).strip()
            for attack_name in self.ATTACK_PATTERNS:
                if attack_name.lower() in attack.lower():
                    return attack_name
        
        match = re.search(r'"\s*"([^"]+?)"\s*"ModSecurity', line)
        if match:
            attack = match.group(1).strip()
            for attack_name in self.ATTACK_PATTERNS:
                if attack_name.lower() in attack.lower():
                    return attack_name
        
        return None

    def _detect_attack_type(self, line: str) -> Optional[str]:
        line_lower = line.lower()
        
        for attack_name, attack_info in self.ATTACK_PATTERNS.items():
            for pattern in attack_info['patterns']:
                if re.search(pattern, line_lower, re.IGNORECASE):
                    return attack_name
        
        return None
