import re
import json
from pathlib import Path
from typing import Type, Optional

from app.parsers.base_parser import BaseParser
from app.parsers.apache_parser import ApacheParser
from app.parsers.auth_parser import AuthParser
from app.parsers.aws_parser import AWSParser
from app.parsers.cisco_asa_parser import CiscoASAParser
from app.parsers.cloudtrail_parser import CloudTrailParser
from app.parsers.dns_parser import DNSParser
from app.parsers.docker_parser import DockerParser
from app.parsers.email_parser import EmailParser
from app.parsers.firewall_parser import FirewallParser
from app.parsers.fortinet_parser import FortinetParser
from app.parsers.kubernetes_parser import KubernetesParser
from app.parsers.modsecurity_parser import ModSecurityParser
from app.parsers.nginx_parser import NginxParser
from app.parsers.openvpn_parser import OpenVPNParser
from app.parsers.osquery_parser import OsqueryParser
from app.parsers.paloalto_parser import PaloAltoParser
from app.parsers.proxy_parser import ProxyParser
from app.parsers.ssh_parser import SSHParser
from app.parsers.suricata_parser import SuricataParser
from app.parsers.syslog_parser import SyslogParser
from app.parsers.sysmon_parser import SysmonParser
from app.parsers.vpn_parser import VPNParser
from app.parsers.windows_event_parser import WindowsEventParser
from app.parsers.zeek_parser import ZeekParser


class ParserFactory:
    """Factory for selecting the appropriate parser based on log content."""

    _PARSERS: dict[str, Type[BaseParser]] = {
        "apache": ApacheParser,
        "auth": AuthParser,
        "aws": AWSParser,
        "cisco_asa": CiscoASAParser,
        "cloudtrail": CloudTrailParser,
        "dns": DNSParser,
        "docker": DockerParser,
        "email": EmailParser,
        "firewall": FirewallParser,
        "fortinet": FortinetParser,
        "kubernetes": KubernetesParser,
        "modsecurity": ModSecurityParser,
        "nginx": NginxParser,
        "openvpn": OpenVPNParser,
        "osquery": OsqueryParser,
        "paloalto": PaloAltoParser,
        "proxy": ProxyParser,
        "ssh": SSHParser,
        "suricata": SuricataParser,
        "syslog": SyslogParser,
        "sysmon": SysmonParser,
        "vpn": VPNParser,
        "windows": WindowsEventParser,
        "zeek": ZeekParser,
    }

    @classmethod
    def get_parser(cls, log_path: Path) -> BaseParser:
        content = cls._read_file_content(log_path)
        
        parser = cls._detect_by_content(content)
        if parser:
            print(f"✅ Content detection: {parser.__class__.__name__}")
            return parser

        parser = cls._detect_by_extension(log_path, content)
        if parser:
            return parser

        parser = cls._detect_by_filename(log_path)
        if parser:
            return parser

        parser = cls._detect_by_directory(log_path)
        if parser:
            return parser

        parser = cls._detect_by_path(log_path)
        if parser:
            return parser

        raise ValueError(f"Unsupported parser type for: {log_path.name}")

    @classmethod
    def _read_file_content(cls, log_path: Path) -> str:
        try:
            with open(log_path, 'r', encoding='utf-8', errors='ignore') as f:
                return f.read(10000)
        except Exception:
            return ""

    @classmethod
    def _detect_by_content(cls, content: str):
        if not content or len(content.strip()) < 10:
            return None
        
        # ===== CHECK JSON FORMATS FIRST =====
        if content.strip().startswith('{'):
            if cls._is_cloudtrail(content):
                return CloudTrailParser()
            if cls._is_waf_json(content):
                return AWSParser()
        
        # ===== CHECK WEB LOGS (Apache/Nginx) =====
        if cls._is_apache(content):
            return ApacheParser()
        
        if cls._is_nginx(content):
            return NginxParser()
        
        # ===== CHECK OPENVPN =====
        if cls._is_openvpn(content):
            return OpenVPNParser()
        
        # ===== CHECK PALO ALTO =====
        if cls._is_paloalto(content):
            return PaloAltoParser()
        
        # ===== CHECK VPN (BEFORE AUTH) =====
        if cls._is_vpn(content):
            return VPNParser()
        
        # ===== CHECK EMAIL =====
        if cls._is_email(content):
            return EmailParser()
        
        # ===== CHECK SSH =====
        if cls._is_ssh(content):
            return SSHParser()
        
        # ===== CHECK AUTH (LAST AMONG AUTHENTICATION) =====
        if cls._is_auth(content):
            return AuthParser()
        
        # ===== CHECK WINDOWS =====
        if cls._is_windows(content):
            return WindowsEventParser()
        
        # ===== CHECK ZEEK =====
        if cls._is_zeek(content):
            return ZeekParser()
        
        # ===== CHECK SURICATA =====
        if cls._is_suricata(content):
            return SuricataParser()
        
        # ===== CHECK MODSECURITY =====
        if cls._is_modsecurity(content):
            return ModSecurityParser()
        
        # ===== CHECK CISCO ASA =====
        if cls._is_cisco_asa(content):
            return CiscoASAParser()
        
        # ===== CHECK FORTINET =====
        if cls._is_fortinet(content):
            return FortinetParser()
        
        # ===== CHECK FIREWALL =====
        if cls._is_firewall(content):
            return FirewallParser()
        
        # ===== CHECK AWS (VPC, ELB) =====
        if cls._is_vpc_flow(content):
            return AWSParser()
        
        if cls._is_elb_log(content):
            return AWSParser()
        
        # ===== CHECK DOCKER =====
        if cls._is_docker(content):
            return DockerParser()
        
        # ===== CHECK KUBERNETES =====
        if cls._is_kubernetes(content):
            return KubernetesParser()
        
        # ===== CHECK DNS =====
        if cls._is_dns(content):
            return DNSParser()
        
        # ===== CHECK PROXY =====
        if cls._is_proxy(content):
            return ProxyParser()
        
        # ===== CHECK OSQUERY =====
        if cls._is_osquery(content):
            return OsqueryParser()
        
        # ===== CHECK AWS GENERIC (LAST) =====
        if cls._is_aws_generic(content):
            return AWSParser()
        
        # ===== CHECK SYSLOG =====
        if cls._is_syslog(content):
            return SyslogParser()
        
        # ===== CHECK SYSMON =====
        if cls._is_sysmon(content):
            return SysmonParser()
        
        return None

    @classmethod
    def _detect_by_extension(cls, log_path: Path, content: str):
        if log_path.suffix.lower() == '.json':
            try:
                data = json.loads(content)
                if isinstance(data, dict):
                    if 'Records' in data:
                        print("✅ JSON detection: CloudTrailParser")
                        return CloudTrailParser()
                    if 'httpRequest' in data or 'action' in data and 'rule' in data:
                        print("✅ JSON detection: AWSParser (WAF)")
                        return AWSParser()
            except:
                pass
        return None

    @classmethod
    def _detect_by_filename(cls, log_path: Path):
        filename = log_path.name.lower()
        
        filename_map = {
            'cloudtrail': CloudTrailParser,
            'root_login': CloudTrailParser,
            'vpc': AWSParser,
            'flow': AWSParser,
            'elb': AWSParser,
            'alb': AWSParser,
            'nlb': AWSParser,
            'waf': AWSParser,
            'cloudfront': AWSParser,
            's3': AWSParser,
            'aws': AWSParser,
            'apache': ApacheParser,
            'nginx': NginxParser,
            'ssh': SSHParser,
            'sshd': SSHParser,
            'auth': AuthParser,
            'docker': DockerParser,
            'windows': WindowsEventParser,
            'event': WindowsEventParser,
            'zeek': ZeekParser,
            'suricata': SuricataParser,
            'modsecurity': ModSecurityParser,
            'vpn': VPNParser,
            'dns': DNSParser,
            'email': EmailParser,
            'mail': EmailParser,
            'phishing': EmailParser,
            'proxy': ProxyParser,
            'osquery': OsqueryParser,
            'firewall': FirewallParser,
            'fortinet': FortinetParser,
            'paloalto': PaloAltoParser,
            'cisco': CiscoASAParser,
            'asa': CiscoASAParser,
            'cisco_asa': CiscoASAParser,
            'openvpn': OpenVPNParser,
            'syslog': SyslogParser,
            'sysmon': SysmonParser,
            'kubernetes': KubernetesParser,
        }
        
        for key, parser_class in filename_map.items():
            if key in filename:
                print(f"✅ Filename detection: {key}")
                return parser_class()
        
        return None

    @classmethod
    def _detect_by_directory(cls, log_path: Path):
        parser_type = log_path.parent.name.lower()
        if parser_type in cls._PARSERS:
            print(f"📁 Directory detection: {parser_type}")
            return cls._PARSERS[parser_type]()
        return None

    @classmethod
    def _detect_by_path(cls, log_path: Path):
        path_str = str(log_path).lower()
        for key, parser_class in cls._PARSERS.items():
            if key in path_str:
                print(f"🔍 Path match: {key}")
                return parser_class()
        return None

    # ==================== DETECTION METHODS ====================

    @staticmethod
    def _is_cloudtrail(content: str) -> bool:
        try:
            data = json.loads(content)
            return isinstance(data, dict) and 'Records' in data and isinstance(data['Records'], list)
        except:
            return False

    @staticmethod
    def _is_waf_json(content: str) -> bool:
        try:
            data = json.loads(content)
            if isinstance(data, dict):
                if 'httpRequest' in data and 'action' in data:
                    return True
            return False
        except:
            return False

    @staticmethod
    def _is_vpn(content: str) -> bool:
        """Check if content is VPN log."""
        lines = content.split('\n')
        for line in lines[:20]:
            if not line.strip():
                continue
            line_lower = line.lower()
            # Check for VPN keyword
            if 'vpn' in line_lower:
                return True
            # Check for login format: VPN LOGIN FAILED/SUCCESS
            if 'login' in line_lower and ('failed' in line_lower or 'success' in line_lower):
                if 'user=' in line_lower and 'ip=' in line_lower:
                    return True
            # Check for key=value format with user and ip
            if 'user=' in line_lower and 'ip=' in line_lower:
                if 'login' in line_lower or 'vpn' in line_lower:
                    return True
        return False

    @staticmethod
    def _is_apache(content: str) -> bool:
        lines = content.split('\n')
        count = 0
        for line in lines[:20]:
            if not line.strip():
                continue
            
            if re.search(r'^\S+\s+-\s+-\s+\[[^\]]+\]\s+"(GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH)\s+', line):
                count += 1
                continue
            
            if re.search(r'^\[[^\]]+\]\s+\[[^:]+:[^\]]+\]\s+\[pid\s+\d+', line):
                count += 1
                continue
            
            if re.search(r'\[[0-9]{2}/[A-Za-z]{3}/[0-9]{4}:[0-9]{2}:[0-9]{2}:[0-9]{2}\s+[+-][0-9]{4}\]', line):
                if '"GET ' in line or '"POST ' in line or '"PUT ' in line:
                    count += 1
                    continue
        
        return count >= 2

    @staticmethod
    def _is_nginx(content: str) -> bool:
        lines = content.split('\n')
        count = 0
        for line in lines[:20]:
            if not line.strip():
                continue
            
            if re.search(r'^\S+\s+-\s+-\s+\[[^\]]+\]\s+"(GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH)\s+', line):
                count += 1
                continue
            
            if 'nginx' in line.lower() or 'nginx/' in line.lower():
                count += 1
                continue
        
        return count >= 1

    @staticmethod
    def _is_openvpn(content: str) -> bool:
        lines = content.split('\n')
        for line in lines[:20]:
            if not line.strip():
                continue
            if 'OpenVPN' in line or 'openvpn' in line.lower():
                return True
        return False

    @staticmethod
    def _is_paloalto(content: str) -> bool:
        lines = content.split('\n')
        for line in lines[:20]:
            if not line.strip():
                continue
            if 'GlobalProtect' in line or 'Palo Alto' in line or 'PAN-OS' in line:
                return True
            if 'globalprotect' in line.lower() or 'palo alto' in line.lower() or 'pan-os' in line.lower():
                return True
        return False

    @staticmethod
    def _is_cisco_asa(content: str) -> bool:
        lines = content.split('\n')
        for line in lines[:20]:
            if not line.strip():
                continue
            if '%ASA-' in line or 'cisco' in line.lower():
                return True
            if 'Deny' in line and ('tcp' in line.lower() or 'udp' in line.lower() or 'icmp' in line.lower()):
                return True
            if 'access-group' in line.lower() or 'access-list' in line.lower():
                return True
        return False

    @staticmethod
    def _is_vpc_flow(content: str) -> bool:
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

    @staticmethod
    def _is_elb_log(content: str) -> bool:
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

    @staticmethod
    def _is_windows(content: str) -> bool:
        lines = content.split('\n')
        for line in lines[:20]:
            if not line.strip():
                continue
            if 'EventID=' in line or 'Event ID' in line:
                return True
            if re.search(r'\b462[4-5]\b', line) or re.search(r'\b472[0-9]\b', line) or re.search(r'\b4740\b', line):
                return True
        return False

    @staticmethod
    def _is_ssh(content: str) -> bool:
        lines = content.split('\n')
        ssh_keywords = ['ssh', 'sshd', 'failed password', 'authentication failure', 'invalid user', 'accepted password']
        count = 0
        for line in lines[:20]:
            if not line.strip():
                continue
            line_lower = line.lower()
            for keyword in ssh_keywords:
                if keyword in line_lower:
                    count += 1
                    break
        return count >= 1

    @staticmethod
    def _is_auth(content: str) -> bool:
        lines = content.split('\n')
        auth_keywords = ['authentication', 'failed password', 'invalid user', 'sudo:', 'su:', 'login failed', 'pam_unix']
        count = 0
        for line in lines[:20]:
            if not line.strip():
                continue
            line_lower = line.lower()
            for keyword in auth_keywords:
                if keyword in line_lower:
                    count += 1
                    break
        return count >= 1

    @staticmethod
    def _is_docker(content: str) -> bool:
        lines = content.split('\n')
        docker_keywords = ['docker', 'container', 'privileged', 'escape', 'hostpath', 'docker.sock']
        count = 0
        for line in lines[:20]:
            if not line.strip():
                continue
            line_lower = line.lower()
            for keyword in docker_keywords:
                if keyword in line_lower:
                    count += 1
                    break
        return count >= 2

    @staticmethod
    def _is_kubernetes(content: str) -> bool:
        lines = content.split('\n')
        k8s_keywords = ['kube-apiserver', 'kubelet', 'pod', 'namespace', 'clusterrole', 'falco']
        count = 0
        for line in lines[:20]:
            if not line.strip():
                continue
            line_lower = line.lower()
            for keyword in k8s_keywords:
                if keyword in line_lower:
                    count += 1
                    break
        return count >= 2

    @staticmethod
    def _is_zeek(content: str) -> bool:
        lines = content.split('\n')
        for line in lines[:20]:
            if not line.strip():
                continue
            if '#fields' in line or '#types' in line:
                return True
            if re.search(r'\d+\.\d+\s+[A-Za-z0-9]+\s+\d+\.\d+\.\d+\.\d+\s+\d+\s+\d+\.\d+\.\d+\.\d+\s+\d+', line):
                return True
        return False

    @staticmethod
    def _is_suricata(content: str) -> bool:
        lines = content.split('\n')
        for line in lines[:20]:
            if not line.strip():
                continue
            if 'suricata' in line.lower() or 'alert' in line.lower():
                return True
            if re.search(r'\[\*\*\]\s+\[', line) and 'Classification:' in line:
                return True
            if line.strip().startswith('{') and '"alert"' in line.lower():
                return True
        return False

    @staticmethod
    def _is_modsecurity(content: str) -> bool:
        lines = content.split('\n')
        for line in lines[:20]:
            if not line.strip():
                continue
            if 'ModSecurity' in line or 'modsecurity' in line.lower():
                return True
            if 'ModSecurity:' in line:
                return True
        return False

    @staticmethod
    def _is_dns(content: str) -> bool:
        lines = content.split('\n')
        dns_keywords = ['dns', 'query', 'A ', 'AAAA ', 'MX ', 'CNAME ', 'PTR ', 'TXT ', 'NS ']
        count = 0
        for line in lines[:20]:
            if not line.strip():
                continue
            line_lower = line.lower()
            for keyword in dns_keywords:
                if keyword.lower() in line_lower:
                    count += 1
                    break
        return count >= 2

    @staticmethod
    def _is_email(content: str) -> bool:
        lines = content.split('\n')
        email_count = 0
        for line in lines[:20]:
            if not line.strip():
                continue
            if 'From:' in line and 'To:' in line:
                email_count += 1
            if 'SPF:' in line or 'DKIM:' in line or 'DMARC:' in line:
                email_count += 1
            if 'Subject:' in line:
                email_count += 1
            if 'Attachment:' in line or 'attachment' in line.lower():
                email_count += 1
            if '@' in line and ('From:' in line or 'To:' in line):
                email_count += 1
        return email_count >= 2

    @staticmethod
    def _is_proxy(content: str) -> bool:
        lines = content.split('\n')
        for line in lines[:20]:
            if not line.strip():
                continue
            if re.search(r'\d+\.\d+\.\d+\.\d+\s+(GET|POST|PUT|DELETE)\s+http', line):
                return True
        return False

    @staticmethod
    def _is_osquery(content: str) -> bool:
        lines = content.split('\n')
        for line in lines[:20]:
            if not line.strip():
                continue
            if 'process_name=' in line and 'pid=' in line:
                return True
        return False

    @staticmethod
    def _is_firewall(content: str) -> bool:
        lines = content.split('\n')
        for line in lines[:20]:
            if not line.strip():
                continue
            line_lower = line.lower()
            if 'firewall' in line_lower:
                return True
            if any(keyword in line_lower for keyword in ['block', 'allow', 'deny', 'drop', 'accept', 'reject']):
                if 'firewall' in line_lower or 'from' in line_lower:
                    return True
        return False

    @staticmethod
    def _is_fortinet(content: str) -> bool:
        lines = content.split('\n')
        for line in lines[:20]:
            if not line.strip():
                continue
            line_lower = line.lower()
            if 'log_id=' in line_lower and 'type=' in line_lower and 'subtype=' in line_lower:
                return True
            if 'log_id=' in line_lower and 'severity=' in line_lower:
                return True
            if 'srcip=' in line_lower and 'dstip=' in line_lower and 'action=' in line_lower:
                return True
        return False

    @staticmethod
    def _is_aws_generic(content: str) -> bool:
        lines = content.split('\n')
        aws_keywords = ['aws', 'ec2', 's3', 'lambda', 'iam', 'elb', 'vpc', 'cloudwatch', 'guardduty']
        count = 0
        for line in lines[:20]:
            if not line.strip():
                continue
            line_lower = line.lower()
            for keyword in aws_keywords:
                if keyword in line_lower:
                    count += 1
                    break
        return count >= 2

    @staticmethod
    def _is_syslog(content: str) -> bool:
        lines = content.split('\n')
        for line in lines[:20]:
            if not line.strip():
                continue
            if re.search(r'^[A-Za-z]{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}', line):
                return True
        return False

    @staticmethod
    def _is_sysmon(content: str) -> bool:
        lines = content.split('\n')
        for line in lines[:20]:
            if not line.strip():
                continue
            if 'Sysmon' in line or 'sysmon' in line.lower():
                return True
        return False
