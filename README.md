# 🔒 AI Security Incident Assistant

[![Python Version](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://python.org)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Ollama](https://img.shields.io/badge/Ollama-Supported-orange.svg)](https://ollama.ai)
[![Flask](https://img.shields.io/badge/Flask-2.3.0-red.svg)](https://flask.palletsprojects.com)
[![GitHub stars](https://img.shields.io/github/stars/shahid45754/ai-security-assistant.svg)](https://github.com/shahid45754/ai-security-assistant/stargazers)
[![GitHub issues](https://img.shields.io/github/issues/shahid45754/ai-security-assistant.svg)](https://github.com/shahid45754/ai-security-assistant/issues)

**An intelligent security incident analysis platform that uses AI to parse, analyze, and correlate security logs from multiple sources.**

---

## 📋 Table of Contents

- [Overview](#overview)
- [Features](#features)
- [Supported Log Types](#supported-log-types)
- [Attack Detection](#attack-detection)
- [Architecture](#architecture)
- [Installation](#installation)
- [Usage](#usage)
- [Report Outputs](#report-outputs)
- [Technologies Used](#technologies-used)
- [Project Structure](#project-structure)
- [Screenshots](#screenshots)
- [Contributing](#contributing)
- [License](#license)

---

## 🎯 Overview

The **AI Security Incident Assistant** is a comprehensive security analysis tool that automatically detects attacks, generates detailed reports, and provides actionable insights for security teams. It supports 24+ log formats and uses local AI for analysis.

### Key Capabilities

| Capability | Description |
|------------|-------------|
| **Log Parsing** | Automatically detects and parses 24+ log formats |
| **AI Analysis** | Uses local AI (Ollama) for intelligent incident analysis |
| **Campaign Correlation** | Groups related incidents into attack campaigns |
| **Report Generation** | Creates HTML, PDF, JSON, and Markdown reports |
| **MITRE Mapping** | Maps attacks to MITRE ATT&CK framework |
| **Visual Analytics** | Attack graphs, kill chain, timelines, and charts |
| **Web Interface** | User-friendly web interface for file uploads |

---

## ✨ Features

### 🔍 Intelligent Log Parsing
- ✅ Auto-detection of log formats
- ✅ 24+ specialized parsers
- ✅ Handles both structured and unstructured logs
- ✅ Extensible for new log types

### 🤖 AI-Powered Analysis
- ✅ Local AI inference (no cloud dependency)
- ✅ Structured analysis with confidence scoring
- ✅ Business impact assessment
- ✅ Actionable recommendations

### 📊 Comprehensive Reporting
- ✅ **HTML Reports**: Interactive visual dashboard
- ✅ **PDF Reports**: Professional printable reports
- ✅ **JSON Export**: Machine-readable data
- ✅ **Markdown Export**: Easy documentation

### 🎯 Attack Detection
- ✅ 70+ attack patterns pre-configured
- ✅ MITRE ATT&CK technique mapping
- ✅ Severity classification (Critical, High, Medium, Low)
- ✅ Confidence scoring for each detection

### 🔗 Campaign Correlation
- ✅ Groups related incidents into campaigns
- ✅ Tracks attack progression over time
- ✅ Calculates risk scores and confidence levels

### 📈 Visual Analytics
- ✅ **Cyber Kill Chain** visualization
- ✅ **Attack Graph** showing attack flow
- ✅ **Incident Timeline** with severity colors
- ✅ **MITRE ATT&CK Matrix** with heatmaps
- ✅ **Interactive Charts** and graphs

### 🌐 Web Interface
- ✅ Drag-and-drop file upload
- ✅ Real-time analysis progress
- ✅ Report preview and download
- ✅ Report management dashboard

---

## 📁 Supported Log Types

### Web Servers
| Parser | Description |
|--------|-------------|
| **Apache** | Apache access/error logs |
| **Nginx** | Nginx access/error logs |

### Authentication
| Parser | Description |
|--------|-------------|
| **SSH** | SSH authentication logs |
| **Auth** | Generic authentication logs |
| **Windows Events** | Windows Security Event Logs |

### Cloud Services
| Parser | Description |
|--------|-------------|
| **AWS CloudTrail** | AWS API activity logs |
| **AWS** | VPC Flow, ELB, WAF, S3 logs |

### Containers & Orchestration
| Parser | Description |
|--------|-------------|
| **Docker** | Docker container logs |
| **Kubernetes** | Kubernetes API/kubelet logs |

### Network Security
| Parser | Description |
|--------|-------------|
| **Zeek** | Zeek/IDMEF network logs |
| **Suricata** | Suricata IDS/IPS alerts |
| **Firewall** | Generic firewall logs |
| **DNS** | DNS query logs |

### VPN & Proxy
| Parser | Description |
|--------|-------------|
| **OpenVPN** | OpenVPN server logs |
| **VPN** | Generic VPN logs |
| **Proxy** | Proxy server logs |

### Security & Endpoint
| Parser | Description |
|--------|-------------|
| **ModSecurity** | WAF attack logs |
| **Cisco ASA** | Cisco ASA firewall logs |
| **Fortinet** | Fortinet firewall logs |
| **Palo Alto** | Palo Alto firewall logs |
| **Osquery** | Osquery endpoint logs |
| **Sysmon** | Windows Sysmon logs |
| **Syslog** | Generic syslog messages |

### Email
| Parser | Description |
|--------|-------------|
| **Email** | Email phishing detection |

---

## 🎯 Attack Detection

### Web Application Attacks
| Attack Type | MITRE ID | Severity |
|-------------|----------|----------|
| SQL Injection | T1190 | Critical |
| Cross-Site Scripting (XSS) | T1059 | High |
| Directory/Path Traversal | T1006 | High |
| Command Injection | T1059 | Critical |
| Local File Inclusion (LFI) | T1006 | High |
| Remote File Inclusion (RFI) | T1190 | Critical |
| Web Shell Access | T1505.003 | Critical |

### Authentication Attacks
| Attack Type | MITRE ID | Severity |
|-------------|----------|----------|
| Brute Force | T1110 | High |
| Password Spraying | T1110.003 | High |
| Credential Stuffing | T1110.004 | High |
| Account Lockout | T1110 | Medium |

### Cloud Attacks
| Attack Type | MITRE ID | Severity |
|-------------|----------|----------|
| Unauthorized API Access | T1078 | Critical |
| Access Key Creation | T1134 | High |
| CloudTrail Disabling | T1562.008 | Critical |
| S3 Bucket Policy Modification | T1530 | High |
| Security Group Modification | T1562.006 | High |
| IAM Role/User Modification | T1098 | High |

### Container Attacks
| Attack Type | MITRE ID | Severity |
|-------------|----------|----------|
| Container Escape | T1611 | Critical |
| Privileged Container | T1611 | High |
| HostPath Volume Mount | T1611 | High |
| Kubernetes Privilege Escalation | T1068 | Critical |

### Network Attacks
| Attack Type | MITRE ID | Severity |
|-------------|----------|----------|
| Port Scanning | T1046 | Medium |
| Network Reconnaissance | T1595 | Medium |
| DNS Tunneling | T1071.004 | High |
| Data Exfiltration | T1041 | Critical |

### Email Attacks
| Attack Type | MITRE ID | Severity |
|-------------|----------|----------|
| Phishing | T1566 | High |
| Business Email Compromise | T1586 | Critical |
| Suspicious Attachments | T1566.001 | High |

### Endpoint Attacks
| Attack Type | MITRE ID | Severity |
|-------------|----------|----------|
| Malware Detection | T1204 | Critical |
| Ransomware Detection | T1486 | Critical |
| PowerShell Abuse | T1059.001 | High |
| Reverse Shell Detection | T1059 | Critical |

---

## 🏗️ Architecture

### High-Level Architecture
┌─────────────────────────────────────────────────────────────────────────────────┐
│ AI SECURITY INCIDENT ASSISTANT │
├─────────────────────────────────────────────────────────────────────────────────┤
│ │
│ ┌─────────────┐ ┌─────────────┐ ┌─────────────┐ ┌─────────────┐ │
│ │ CLI/Web │───▶│ Parser │───▶│ AI │───▶│ Campaign │ │
│ │ Interface │ │ Factory │ │ Analysis │ │ Correlation │ │
│ └─────────────┘ └─────────────┘ └─────────────┘ └─────────────┘ │
│ │ │ │ │ │
│ ▼ ▼ ▼ ▼ │
│ ┌─────────────┐ ┌─────────────┐ ┌─────────────┐ ┌─────────────┐ │
│ │ Upload │ │ 24+ Parsers │ │ AI Agents │ │ Reports │ │
│ │ Log Files │ │ │ │ (Ollama) │ │ Generator │ │
│ └─────────────┘ └─────────────┘ └─────────────┘ └─────────────┘ │
│ │
└─────────────────────────────────────────────────────────────────────────────────┘

### Cyber Kill Chain Mapping

┌─────────────────────────────────────────────────────────────────────────────┐
│ CYBER KILL CHAIN │
├─────────────────────────────────────────────────────────────────────────────┤
│ │
│ ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐ │
│ │ Recon │───▶│ Weaponize│───▶│ Deliver │───▶│ Exploit │───▶│ Install │ │
│ │ naissance│ │ ation │ │ │ │ ation │ │ ation │ │
│ └──────────┘ └──────────┘ └──────────┘ └──────────┘ └──────────┘ │
│ │ │ │ │ │ │
│ ▼ ▼ ▼ ▼ ▼ │
│ ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐ │
│ │ Admin │ │ Malware │ │ Phishing │ │ SQL Inj │ │ Web │ │
│ │ Access │ │ Ransom │ │ Malicious│ │ XSS │ │ Shell │ │
│ │ Scanning │ │ Exploits │ │ File │ │ Command │ │ Reverse │ │
│ │ Brute │ │ │ │ Upload │ │ Injection│ │ Shell │ │
│ │ Force │ │ │ │ │ │ │ │ │ │
│ └──────────┘ └──────────┘ └──────────┘ └──────────┘ └──────────┘ │
│ │
│ ┌──────────┐ ┌──────────┐ │
│ │ C2 │───▶│ Actions │ │
│ │ │ │ on │ │
│ │ │ │ Objectives│ │
│ └──────────┘ └──────────┘ │
│ │ │ │
│ ▼ ▼ │
│ ┌──────────┐ ┌──────────┐ │
│ │ DNS │ │ Data │ │
│ │ Tunneling│ │ Exfil │ │
│ │ Beaconing│ │ Lateral │ │
│ │ C2 │ │ Movement │ │
│ └──────────┘ └──────────┘ │
│ │
└─────────────────────────────────────────────────────────────────────────────┘

---

## 🚀 Installation

### Prerequisites

| Requirement | Version | Notes |
|-------------|---------|-------|
| Python | 3.10+ | Required |
| Ollama | Latest | For AI analysis |
| Git | Latest | For cloning |
| pip | Latest | For dependencies |

### Step 1: Clone the Repository

```bash
git clone https://github.com/shahid45754/ai-security-assistant.git
cd ai-security-assistant

Linux Based:

python -m venv .venv
source .venv/bin/activate

Windows Based:

python -m venv .venv
.venv\Scripts\activate

Install Dependencies
pip install -r requirement.txt

Install Ollama
curl -fsSL https://ollama.ai/install.sh | sh
```
NOTE: FIRST MAKE SURE YOU HAVE .VENV is on.
### Step 2: Run the code
1. If you want run on terminal version use :- python3 run.py
2. If you want run on web apps then:- python3 web_app.py 




