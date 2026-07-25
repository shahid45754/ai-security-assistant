
import json
from datetime import datetime
from typing import Optional

from app.models.incident import Incident
from app.parsers.base_parser import BaseParser
from app.core.utils import sanitize_text


class CloudTrailParser(BaseParser):
    """Parser for AWS CloudTrail logs."""
    
    # Suspicious CloudTrail events
    SUSPICIOUS_EVENTS = {
        'ConsoleLogin': 'AWS Console Login',
        'CreateAccessKey': 'Access Key Created',
        'StopLogging': 'CloudTrail Logging Stopped',
        'DeleteTrail': 'CloudTrail Trail Deleted',
        'PutBucketPolicy': 'S3 Bucket Policy Modified',
        'DeleteBucketPolicy': 'S3 Bucket Policy Deleted',
        'AuthorizeSecurityGroupIngress': 'Security Group Ingress Rule Added',
        'AuthorizeSecurityGroupEgress': 'Security Group Egress Rule Added',
        'RevokeSecurityGroupIngress': 'Security Group Ingress Rule Removed',
        'RevokeSecurityGroupEgress': 'Security Group Egress Rule Removed',
        'CreateUser': 'IAM User Created',
        'DeleteUser': 'IAM User Deleted',
        'AttachUserPolicy': 'IAM Policy Attached to User',
        'AttachRolePolicy': 'IAM Policy Attached to Role',
        'UpdateAssumeRolePolicy': 'Assume Role Policy Updated',
    }

    def parse(self, content: str) -> list[Incident]:
        """Parse CloudTrail log content."""
        incidents = []
        
        try:
            data = json.loads(content)
            records = data.get('Records', [])
            
            for record in records:
                incident = self._parse_record(record)
                if incident:
                    incidents.append(incident)
        except json.JSONDecodeError:
            # Try parsing line by line
            for line in content.splitlines():
                if not line.strip():
                    continue
                try:
                    record = json.loads(line)
                    incident = self._parse_record(record)
                    if incident:
                        incidents.append(incident)
                except:
                    continue
        
        return incidents

    def _parse_record(self, record: dict) -> Optional[Incident]:
        """Parse a single CloudTrail record."""
        
        # Extract basic information
        event_name = record.get('eventName', '')
        event_source = record.get('eventSource', '')
        source_ip = record.get('sourceIPAddress')
        event_time = record.get('eventTime', '')
        
        # Extract user identity
        identity = record.get('userIdentity', {})
        username = (
            identity.get('userName') or
            identity.get('arn', '').split('/')[-1] or
            identity.get('principalId', '')
        )
        
        # Parse timestamp
        try:
            timestamp = datetime.fromisoformat(event_time.replace('Z', '+00:00'))
        except:
            timestamp = datetime.now()
        
        # Check if event is suspicious
        if event_name in self.SUSPICIOUS_EVENTS:
            attack_type = self.SUSPICIOUS_EVENTS[event_name]
            
            # Build description
            description = f"{attack_type} - Source: {source_ip or 'Unknown'}, User: {username or 'Unknown'}"
            
            # Extract additional details from requestParameters
            request_params = record.get('requestParameters', {})
            if request_params:
                description += f" - Params: {json.dumps(request_params)[:100]}"
            
            description = sanitize_text(description)
            
            # Determine severity
            severity = self._get_severity(event_name)
            
            return Incident(
                title=f"AWS CloudTrail: {attack_type}",
                description=description[:500],
                source_ip=source_ip,
                destination_ip=None,
                username=username,
                protocol="aws",
                port=None,
                action=event_name,
                log_source="cloudtrail",
                timestamp=timestamp,
            )
        
        return None

    def _get_severity(self, event_name: str) -> str:
        """Get severity for CloudTrail event."""
        critical_events = [
            'StopLogging', 'DeleteTrail', 'DeleteBucketPolicy',
            'AttachUserPolicy', 'AttachRolePolicy', 'UpdateAssumeRolePolicy'
        ]
        high_events = [
            'CreateAccessKey', 'PutBucketPolicy', 'AuthorizeSecurityGroupIngress',
            'CreateUser', 'DeleteUser'
        ]
        
        if event_name in critical_events:
            return 'Critical'
        elif event_name in high_events:
            return 'High'
        else:
            return 'Medium'
