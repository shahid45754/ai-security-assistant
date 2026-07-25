# Make sure you're in the project root
cd ~/Desktop/AI_Project/AI_PROJECTS/ai-security-incident-assistant

# Create all sample files in their directories
echo '192.168.1.10 - - [19/Jul/2026:10:15:30 +0000] "GET /index.php?id=1'\'' OR '\''1'\''='\''1 HTTP/1.1" 200 512 "-" "Mozilla/5.0"' > app/sample_logs/apache/apache.log

echo 'Jan 15 10:20:30 server sshd[1234]: Failed password for root from 192.168.1.100 port 54321 ssh2' > app/sample_logs/auth/auth.log

echo '2026-01-15 10:20:30 [ERROR] AWS S3 Bucket my-bucket access denied for user unknown from 45.12.44.18' > app/sample_logs/aws/aws.log

echo 'Feb 15 2026 10:20:30: %ASA-4-106023: Deny tcp src outside:192.168.50.10/54321 dst inside:10.0.0.5/80 by access-group "outside_access_in"' > app/sample_logs/cisco_asa/asa.log

echo '{"Records":[{"eventVersion":"1.08","userIdentity":{"type":"Root","principalId":"123456789012","arn":"arn:aws:iam::123456789012:root","accountId":"123456789012","userName":"root"},"eventTime":"2026-07-20T12:00:01Z","eventName":"ConsoleLogin","sourceIPAddress":"45.12.44.18","userAgent":"Mozilla/5.0"}]}' > app/sample_logs/cloudtrail/root_login.json

echo '2026-01-15 10:20:30 query=malware.example.com from 192.168.1.10' > app/sample_logs/dns/dns.log

echo '2026-07-20T10:20:01Z docker[12345]: container 6a7b8c9d started in privileged mode' > app/sample_logs/docker/docker.log

echo 'From: attacker@example.com To: employee@company.com Subject: Urgent Password Reset Attachment: invoice.exe SPF: FAIL DKIM: FAIL DMARC: FAIL' > app/sample_logs/email/email.log

echo '2026-01-15 10:20:30 firewall: Blocked inbound connection from 45.12.44.18 to 10.0.0.5 port 22' > app/sample_logs/firewall/firewall.log

echo '2026-02-15 10:20:30 log_id=0001010011 type=traffic subtype=attack severity=critical srcip=192.168.50.10 dstip=10.0.0.5 service=HTTP action=blocked msg="SQL Injection attempt detected"' > app/sample_logs/fortinet/fortinet.log

echo '2026-07-20T10:20:01Z kube-apiserver Warning FailedCreate pod/default/nginx-123 Error creating: pods "nginx-123" is forbidden' > app/sample_logs/kubernetes/kubernetes.log

echo '[15/Feb/2026:10:20:30 +0000] 192.168.50.10 54321 10.0.0.5 80 "GET /admin/login.php?user=admin'\''-- HTTP/1.1" 403 512 "Mozilla/5.0" "-" "SQL Injection" "ModSecurity: SQL Injection Attack detected"' > app/sample_logs/modsecurity/modsecurity.log

echo '192.168.1.10 - - [19/Jul/2026:10:15:30 +0000] "GET /index.php?id=1'\'' OR '\''1'\''='\''1 HTTP/1.1" 200 512 "-" "Mozilla/5.0"' > app/sample_logs/nginx/nginx.log

echo '2026-01-15 10:20:30 OpenVPN Authentication failed for user admin from 192.168.1.100' > app/sample_logs/openvpn/openvpn.log

echo 'process_name=mimikatz.exe pid=1001 user=Administrator' > app/sample_logs/osquery/osquery.log

echo '2026-01-15 10:20:30 GlobalProtect Authentication failed for user admin from 192.168.1.100' > app/sample_logs/paloalto/paloalto.log

echo '192.168.1.25 GET http://evil-login.example/login HTTP/1.1 403' > app/sample_logs/proxy/proxy.log

echo 'Jan 15 10:20:30 server sshd[1234]: Failed password for root from 192.168.1.100 port 54321 ssh2' > app/sample_logs/ssh/ssh.log

echo '{"timestamp":"2026-01-15T10:20:30.123456Z","alert":{"signature":"ET SCAN Suspicious User-Agent","category":"Attempted Information Leak","severity":2},"src_ip":"45.12.44.18","dest_ip":"10.0.0.5","proto":"TCP"}' > app/sample_logs/suricata/suricata.log

echo 'Jan 15 10:20:30 server kernel: [12345.678] ATTACK detected from 45.12.44.18' > app/sample_logs/syslog/syslog.log

echo '2026-01-15 10:20:30 Sysmon Process Creation Image=C:\\Users\\admin\\mimikatz.exe CommandLine=mimikatz.exe' > app/sample_logs/sysmon/sysmon.log

echo 'VPN LOGIN FAILED user=admin ip=192.168.50.10' > app/sample_logs/vpn/vpn.log

echo 'EventID=4625 Account=root IP=192.168.1.70 Status=FAILED' > app/sample_logs/windows/windows.log

echo '192.168.1.10 GET /../../etc/passwd HTTP/1.1 404' > app/sample_logs/zeek/zeek.log
