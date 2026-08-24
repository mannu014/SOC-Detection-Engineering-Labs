# 🛡️ SOC & Detection Engineering Portfolio

Hands-on cybersecurity repository documenting lab setups, adversary technique emulation, and custom detection engineering in Splunk.

## 💻 Home Lab Architecture
- **SIEM:** Splunk Enterprise 9.x
- **Telemetry:** Sysmon v14 + Windows Event Logs via Universal Forwarder
- **Target OS:** Windows 10/11 VM
- **Attack Platform:** PowerShell / Kali Linux

---
## 🧠 Skills Demonstrated

### 🔎 SOC & Detection Engineering

- **Security Event Monitoring & Investigation**
- **Log Analysis & Event Correlation**
- **Detection Rule Development**
- **Alert Triage**
- **True Positive / False Positive Classification**
- **Basic Threat Hunting**
- **Detection Tuning**
- **Incident Documentation**

### 📊 Splunk & SIEM

- **Splunk Enterprise**
- **Splunk Universal Forwarder**
- **SPL Query Development**
- **`spath` XML Parsing**
- **`rex` Regular-Expression Field Extraction**
- **Custom Field Extraction from Raw XML Telemetry**
- **Event Filtering & Correlation**
- **Detection Searches**
- **Investigation Queries**
- **Dashboards, Reports & Alerts**

### 🪟 Windows Security & Telemetry

- **Windows Process Monitoring**
- **PowerShell Activity Analysis**
- **Parent-Child Process Analysis**
- **Registry Modification Monitoring**
- **Scheduled Task Monitoring**
- **WMI Process Execution Analysis**
- **Network Connection Telemetry Analysis**
- **Sysmon Event ID Analysis**

### 🛡️ Threat Detection

- **PowerShell Execution Detection**
- **Encoded PowerShell Detection**
- **Registry Persistence Detection**
- **Scheduled Task Persistence Detection**
- **WMI Execution Detection**
- **Suspicious Parent-Child Process Detection**
- **Network Activity Analysis**
- **Basic C2 Behavior Analysis**

### 🧩 MITRE ATT&CK

Practical detection mapping and analysis of techniques including:

- **T1059.001** — PowerShell
- **T1027** — Obfuscated/Compressed Files and Information
- **T1547.001** — Registry Run Keys / Startup Folder
- **T1053.005** — Scheduled Task/Job
- **T1047** — Windows Management Instrumentation
- **T1071.001** — Web Protocols

### 🧪 Practical Security Lab Skills

- **Windows Security Lab Deployment**
- **Sysmon Configuration**
- **Security Telemetry Collection**
- **Splunk Log Ingestion**
- **Controlled Adversary-Technique Emulation**
- **Detection Validation**
- **Security Investigation & Triage**
- **Evidence-Based Analysis**
- **Incident Documentation**
---

## 🔬 Detection Engineering Labs

| Lab #  | Lab Name                                 | Focus Area         | Attack Technique | Write-Up Link |
| :---:  | :--------------------------------------- | :----------------- | :--------------- | :-----------: |
| **01** | PowerShell Execution & XML Parsing       | Execution          | T1059.001        | [View Write-Up](labs/Lab-01-PowerShell-Execution.md) |
| **02** | Encoded PowerShell Detection             | Obfuscation        | T1027            | [View Write-Up](labs/Lab-02-Encoded-PowerShell.md)   |
| **03** | Registry Persistence Detection           | Persistence        | T1547.001        | [View Write-Up](labs/Lab-03-Registry-Persistence.md) |
| **04** | Parent-Child Process Anomaly             | Execution          | T1059.001        | [View Write-Up](labs/Lab-04-Parent-Child-Process.md) |
| **05** | Scheduled Task Persistence               | Persistence        | T1053.005        | [View Write-Up](labs/Lab-05-Scheduled-Task-Persistence.md) |
| **06** | WMI process creation/execution detection | Execution          | T1047            | [View Write-Up](labs/Lab-06-WMI-Execution.md)        |
| **07** | Network Telemetry & C2 Detection         | Command & Control  | T1071.001        | [View Write-Up](labs/Lab-07-Network-Detection.md)    |
| **08** | Full SOC Investigation Scenario          | Multi-Stage Threat | Tactic Chain     | [View Write-Up](labs/Lab-08-SOC-Investigation.md)|

---
## 🎯 Portfolio Focus

This portfolio demonstrates a practical security workflow:

**Telemetry Collection → XML Parsing → Detection Engineering → Alert Investigation → Threat Triage → MITRE ATT&CK Mapping → Incident Documentation**

All activities are performed in controlled virtual lab environments for educational and defensive-security purposes.


