import re
from datetime import datetime
from typing import Optional

from app.models.incident import Incident
from app.parsers.base_parser import BaseParser
from app.core.utils import sanitize_text


class KubernetesParser(BaseParser):
    """Parser for Kubernetes logs (API server, kubelet, audit, Falco, etc.)."""
    
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
        source = self._extract_source(line)
        severity = self._extract_severity(line)
        user = self._extract_user(line)
        source_ip = self._extract_ip(line)
        namespace = self._extract_namespace(line)
        pod = self._extract_pod(line)
        action = self._extract_action(line)
        resource = self._extract_resource(line)
        attack_type = self._detect_attack(line)
        
        if not attack_type:
            return None
        
        description = f"Kubernetes: {attack_type}"
        if source:
            description += f" - Source: {source}"
        if user:
            description += f" - User: {user}"
        if namespace:
            description += f" - Namespace: {namespace}"
        if pod:
            description += f" - Pod: {pod}"
        if action:
            description += f" - Action: {action}"
        if resource:
            description += f" - Resource: {resource}"
        
        description = sanitize_text(description)
        
        severity_level = self._determine_severity(severity, attack_type)
        
        return Incident(
            title=f"Kubernetes: {attack_type}",
            description=description[:500],
            source_ip=source_ip,
            destination_ip=None,
            username=user,
            protocol="kubernetes",
            port=None,
            action=action or "Kubernetes_Event",
            log_source="kubernetes",
            timestamp=timestamp,
        )

    def _extract_timestamp(self, line: str) -> datetime:
        patterns = [
            r'(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z?)',
            r'(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})',
            r'([A-Za-z]{3}\s+\d{1,2}\s+\d{4}\s+\d{2}:\d{2}:\d{2})',
        ]
        
        for pattern in patterns:
            match = re.search(pattern, line)
            if match:
                timestamp_str = match.group(1)
                try:
                    if 'T' in timestamp_str:
                        return datetime.fromisoformat(timestamp_str.replace('Z', '+00:00'))
                    return datetime.strptime(timestamp_str, '%Y-%m-%d %H:%M:%S')
                except:
                    try:
                        return datetime.strptime(timestamp_str, '%b %d %Y %H:%M:%S')
                    except:
                        continue
        
        return datetime.now()

    def _extract_source(self, line: str) -> Optional[str]:
        sources = ['kube-apiserver', 'kubelet', 'audit', 'Falco', 'kube-controller', 'kube-scheduler']
        for source in sources:
            if source.lower() in line.lower():
                return source
        return None

    def _extract_severity(self, line: str) -> Optional[str]:
        severities = ['Critical', 'Error', 'Warning', 'Info']
        for sev in severities:
            if sev in line:
                return sev
        return None

    def _extract_user(self, line: str) -> Optional[str]:
        user_match = re.search(r'user[=:]\s*([^\s]+)', line, re.IGNORECASE)
        if user_match:
            return user_match.group(1)
        return None

    def _extract_namespace(self, line: str) -> Optional[str]:
        ns_match = re.search(r'namespace[=:]\s*([^\s,]+)', line, re.IGNORECASE)
        if ns_match:
            return ns_match.group(1)
        ns_match = re.search(r'pod[/]([^/]+)[/]', line)
        if ns_match:
            return ns_match.group(1)
        return None

    def _extract_pod(self, line: str) -> Optional[str]:
        pod_match = re.search(r'pod[/][^/]+[/]([^\s]+)', line)
        if pod_match:
            return pod_match.group(1)
        pod_match = re.search(r'pod[=:]\s*([^\s,]+)', line, re.IGNORECASE)
        if pod_match:
            return pod_match.group(1)
        return None

    def _extract_action(self, line: str) -> Optional[str]:
        verbs = ['create', 'delete', 'update', 'get', 'list', 'watch', 'patch']
        for verb in verbs:
            if f'verb={verb}' in line or f'verb: {verb}' in line:
                return verb.upper()
            if f' {verb} ' in line.lower():
                return verb.upper()
        return None

    def _extract_resource(self, line: str) -> Optional[str]:
        resources = ['pods', 'services', 'deployments', 'configmaps', 'secrets', 
                    'clusterrolebindings', 'rolebindings', 'namespaces', 'nodes']
        for resource in resources:
            if f'resource={resource}' in line or f'resource: {resource}' in line:
                return resource
            if f' {resource} ' in line.lower():
                return resource
        return None

    def _detect_attack(self, line: str) -> Optional[str]:
        line_lower = line.lower()
        
        if 'privileged' in line_lower and 'container' in line_lower:
            return 'Privileged Container'
        if 'hostpath' in line_lower:
            return 'HostPath Mount'
        if 'cluster-admin' in line_lower or 'clusterrolebindings' in line_lower:
            return 'Cluster Admin Abuse'
        if 'anonymous' in line_lower:
            return 'Anonymous Access'
        if 'unauthorized' in line_lower:
            return 'Unauthorized Access'
        if 'forbidden' in line_lower:
            return 'Forbidden Access'
        if 'malicious' in line_lower or 'backdoor' in line_lower:
            return 'Malicious Image Pull'
        if 'shell' in line_lower or 'terminal' in line_lower:
            return 'Container Shell Access'
        if 'secrets' in line_lower:
            return 'Secrets Access'
        if 'escape' in line_lower or 'breakout' in line_lower:
            return 'Container Escape'
        
        return None

    def _determine_severity(self, severity: Optional[str], attack_type: Optional[str]) -> str:
        if attack_type in ['Container Escape', 'Cluster Admin Abuse', 'Privileged Container']:
            return 'Critical'
        if attack_type in ['Anonymous Access', 'Unauthorized Access', 'Malicious Image Pull', 'Secrets Access']:
            return 'High'
        if attack_type in ['HostPath Mount', 'Container Shell Access', 'Forbidden Access']:
            return 'Medium'
        
        if severity:
            if severity == 'Critical':
                return 'Critical'
            if severity == 'Error':
                return 'High'
            if severity == 'Warning':
                return 'Medium'
        
        return 'Medium'
