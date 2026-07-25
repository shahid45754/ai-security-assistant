
import json
import re
from datetime import datetime
from typing import Optional, Dict, List, Any

from app.models.incident import Incident
from app.parsers.base_parser import BaseParser
from app.core.utils import sanitize_text


class AWSParser(BaseParser):
    """Parser for AWS logs (CloudWatch, VPC Flow, ELB, WAF, etc.)."""
    
    SUSPICIOUS_PATTERNS = {
        'access_denied': ['access denied', 'unauthorized', 'forbidden', 'permission denied'],
        'error': ['error', 'failed', 'failure', 'exception'],
        'blocked': ['blocked', 'denied', 'rejected', 'dropped'],
        'attack': ['attack', 'malicious', 'threat', 'exploit', 'intrusion'],
    }

    def parse(self, content: str) -> list[Incident]:
        incidents = []
        lines = content.split('\n')
        
        # Try JSON format first
        if content.strip().startswith('{'):
            incidents = self._parse_json_format(content)
            if incidents:
                return incidents
        
        # Try VPC Flow Logs
        if self._is_vpc_flow_log('\n'.join(lines[:10])):
            incidents = self._parse_vpc_flow_logs(lines)
            if incidents:
                return incidents
        
        # Try ELB Logs
        if self._is_elb_log('\n'.join(lines[:10])):
            incidents = self._parse_elb_logs(lines)
            if incidents:
                return incidents
        
        # Generic AWS log parsing
        incidents = self._parse_generic_aws_log(lines)
        return incidents

    def _parse_generic_aws_log(self, lines: list) -> list[Incident]:
        """Parse generic AWS log format."""
        incidents = []
        
        for line in lines:
            if not line.strip():
                continue
            
            # Extract timestamp
            timestamp = self._parse_timestamp(line)
            
            # Extract source IP
            source_ip = None
            ip_match = re.search(r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b', line)
            if ip_match:
                source_ip = ip_match.group(0)
            
            # Extract username
            username = None
            user_match = re.search(r'user\s+([^\s]+)', line, re.IGNORECASE)
            if user_match:
                username = user_match.group(1)
            if not username:
                user_match = re.search(r'for\s+user\s+([^\s]+)', line, re.IGNORECASE)
                if user_match:
                    username = user_match.group(1)
            
            # Detect service
            service = self._detect_service(line)
            
            # Check for suspicious patterns
            attack_type = None
            severity = 'Medium'
            
            line_lower = line.lower()
            
            # Check for access denied
            if any(x in line_lower for x in ['access denied', 'unauthorized', 'forbidden']):
                attack_type = 'Access Denied'
                severity = 'High'
            # Check for S3 bucket errors
            elif 's3' in line_lower and 'bucket' in line_lower:
                if 'error' in line_lower or 'denied' in line_lower:
                    attack_type = 'S3 Access Error'
                    severity = 'High'
                else:
                    attack_type = 'S3 Event'
                    severity = 'Medium'
            # Check for general errors
            elif 'error' in line_lower:
                attack_type = 'AWS Error'
                severity = 'High'
            # Check for blocked traffic
            elif any(x in line_lower for x in ['blocked', 'denied', 'rejected']):
                attack_type = 'Blocked Traffic'
                severity = 'High'
            # Check for general AWS events with suspicious keywords
            elif any(x in line_lower for x in ['attack', 'malicious', 'threat']):
                attack_type = 'Suspicious Activity'
                severity = 'High'
            
            # Also check if it's a GuardDuty finding
            if 'guardduty' in line_lower and 'finding' in line_lower:
                attack_type = 'GuardDuty Finding'
                severity = 'Critical'
            
            # If no attack type detected, skip
            if not attack_type:
                continue
            
            # Build description
            description = f"AWS {service.upper() if service else 'Event'}: {attack_type}"
            if source_ip:
                description += f" - Source: {source_ip}"
            if username:
                description += f" - User: {username}"
            description += f" - {line[:200]}"
            
            description = sanitize_text(description)
            
            incident = Incident(
                title=f"AWS: {attack_type}",
                description=description[:500],
                source_ip=source_ip,
                destination_ip=None,
                username=username,
                protocol="aws",
                port=None,
                action=f"AWS_{attack_type.replace(' ', '_')}",
                log_source="aws",
                timestamp=timestamp,
            )
            incidents.append(incident)
        
        return incidents

    def _detect_service(self, line: str) -> Optional[str]:
        """Detect AWS service from log line."""
        line_lower = line.lower()
        
        service_map = {
            's3': ['s3', 'bucket', 's3://'],
            'ec2': ['ec2', 'instance', 'ec2-'],
            'lambda': ['lambda', 'function'],
            'iam': ['iam', 'role', 'policy'],
            'guardduty': ['guardduty'],
            'cloudwatch': ['cloudwatch', 'alarm'],
            'vpc': ['vpc', 'subnet'],
            'elb': ['elb', 'load balancer'],
            'waf': ['waf', 'web acl'],
        }
        
        for service, patterns in service_map.items():
            for pattern in patterns:
                if pattern in line_lower:
                    return service
        return None

    def _parse_json_format(self, content: str) -> list[Incident]:
        incidents = []
        
        try:
            data = json.loads(content)
            if isinstance(data, dict):
                data = [data]
            
            for entry in data:
                incident = self._parse_json_entry(entry)
                if incident:
                    incidents.append(incident)
        except json.JSONDecodeError:
            for line in content.split('\n'):
                if not line.strip():
                    continue
                try:
                    entry = json.loads(line)
                    incident = self._parse_json_entry(entry)
                    if incident:
                        incidents.append(incident)
                except:
                    pass
        
        return incidents

    def _parse_json_entry(self, entry: Dict) -> Optional[Incident]:
        timestamp = self._parse_timestamp(
            entry.get('timestamp', '') or entry.get('time', '') or entry.get('@timestamp', '')
        )
        
        source_ip = (
            entry.get('src_ip') or 
            entry.get('source_ip') or 
            entry.get('client_ip') or 
            entry.get('remote_ip') or
            entry.get('ip')
        )
        
        username = (
            entry.get('user') or 
            entry.get('username') or 
            entry.get('identity', {}).get('userName') or
            entry.get('userIdentity', {}).get('userName')
        )
        
        action = entry.get('action') or entry.get('eventName') or entry.get('type')
        status = entry.get('status') or entry.get('result')
        message = entry.get('message') or entry.get('description')
        
        # Detect attack type
        attack_type = None
        severity = 'Medium'
        
        combined = f"{message} {action} {status}".lower()
        
        if 'denied' in combined or 'unauthorized' in combined:
            attack_type = 'Access Denied'
            severity = 'High'
        elif 'error' in combined:
            attack_type = 'AWS Error'
            severity = 'High'
        elif 'blocked' in combined:
            attack_type = 'Blocked Traffic'
            severity = 'High'
        elif 'guardduty' in combined and 'finding' in combined:
            attack_type = 'GuardDuty Finding'
            severity = 'Critical'
        
        if not attack_type:
            return None
        
        description = f"AWS Event: {attack_type}"
        if action:
            description += f" - Action: {action}"
        if status:
            description += f" - Status: {status}"
        if username:
            description += f" - User: {username}"
        if source_ip:
            description += f" - Source: {source_ip}"
        if message:
            description += f" - Message: {message[:200]}"
        
        description = sanitize_text(description)
        
        return Incident(
            title=f"AWS: {attack_type}",
            description=description[:500],
            source_ip=source_ip,
            destination_ip=None,
            username=username,
            protocol="aws",
            port=None,
            action=action or "AWS_Event",
            log_source="aws",
            timestamp=timestamp,
        )

    def _parse_vpc_flow_logs(self, lines: list) -> list[Incident]:
        incidents = []
        
        for line in lines:
            if not line.strip() or line.startswith('#'):
                continue
            
            parts = line.split()
            if len(parts) < 10:
                continue
            
            try:
                srcaddr = parts[3]
                dstaddr = parts[4]
                dstport = parts[6]
                protocol = parts[7]
                action = parts[12] if len(parts) > 12 else ''
                
                timestamp = datetime.now()
                
                if action == 'DENY' or action == 'REJECT':
                    description = f"VPC Flow: {srcaddr} -> {dstaddr} ({protocol}) - Action: {action}"
                    description = sanitize_text(description)
                    
                    incident = Incident(
                        title=f"AWS VPC: Blocked Traffic - {srcaddr}",
                        description=description[:500],
                        source_ip=srcaddr,
                        destination_ip=dstaddr,
                        username=None,
                        protocol=protocol,
                        port=int(dstport) if dstport.isdigit() else None,
                        action=f"VPC_{action}",
                        log_source="aws",
                        timestamp=timestamp,
                    )
                    incidents.append(incident)
                    
            except Exception as e:
                continue
        
        return incidents

    def _parse_elb_logs(self, lines: list) -> list[Incident]:
        incidents = []
        
        for line in lines:
            if not line.strip() or line.startswith('#'):
                continue
            
            parts = line.split()
            if len(parts) < 10:
                continue
            
            try:
                client_ip = parts[3]
                elb_status_code = parts[10]
                request_method = parts[14] if len(parts) > 14 else ''
                request_url = parts[15] if len(parts) > 15 else ''
                
                timestamp = datetime.now()
                
                attack_type = None
                if 'sql' in request_url.lower() or 'union' in request_url.lower():
                    attack_type = 'SQL Injection'
                elif '<script' in request_url.lower() or 'alert(' in request_url.lower():
                    attack_type = 'XSS'
                elif '../' in request_url.lower():
                    attack_type = 'Path Traversal'
                elif elb_status_code == '403':
                    attack_type = 'Forbidden Access'
                
                if attack_type or elb_status_code.startswith('4') or elb_status_code.startswith('5'):
                    description = f"ELB: {request_method} {request_url} - {elb_status_code}"
                    if attack_type:
                        description = f"{attack_type} - {description}"
                    description = sanitize_text(description)
                    
                    incident = Incident(
                        title=f"AWS ELB: {attack_type or 'Access'} - {elb_status_code}",
                        description=description[:500],
                        source_ip=client_ip,
                        destination_ip=None,
                        username=None,
                        protocol="HTTP",
                        port=80,
                        action=f"ELB_{request_method}_{elb_status_code}",
                        log_source="aws",
                        timestamp=timestamp,
                    )
                    incidents.append(incident)
                    
            except Exception as e:
                continue
        
        return incidents

    def _parse_timestamp(self, timestamp_str: str) -> datetime:
        if not timestamp_str:
            return datetime.now()
        
        try:
            if 'T' in timestamp_str:
                return datetime.fromisoformat(timestamp_str.replace('Z', '+00:00'))
            return datetime.strptime(timestamp_str, '%Y-%m-%d %H:%M:%S')
        except:
            return datetime.now()

    def _is_vpc_flow_log(self, content: str) -> bool:
        lines = content.split('\n')[:10]
        for line in lines:
            if not line.strip() or line.startswith('#'):
                continue
            parts = line.split()
            if len(parts) >= 10:
                ip_count = 0
                for part in parts:
                    if re.match(r'\d+\.\d+\.\d+\.\d+', part):
                        ip_count += 1
                if ip_count >= 2:
                    return True
        return False

    def _is_elb_log(self, content: str) -> bool:
        lines = content.split('\n')[:10]
        for line in lines:
            if not line.strip() or line.startswith('#'):
                continue
            parts = line.split()
            if len(parts) >= 10:
                if 'HTTP' in line or 'http' in line.lower():
                    return True
                if len(parts) >= 14:
                    return True
        return False

