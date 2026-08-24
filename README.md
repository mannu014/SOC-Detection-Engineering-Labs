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
Security event monitoring and alert investigation
Log analysis and event correlation
Detection rule development
True Positive / False Positive classification
SOC alert triage and investigation
Basic threat hunting methodology
Detection tuning and contextual analysis
### 📊 Splunk & SIEM
Splunk Enterprise
Splunk Universal Forwarder
SPL search development
spath XML parsing
rex regular-expression field extraction
Custom field extraction from raw telemetry
Event filtering and correlation
Detection searches and investigation queries
Dashboards, reports, and alerts
### 🪟 Windows Security & Telemetry
Windows process monitoring
PowerShell activity analysis
Parent-child process analysis
Registry modification monitoring
Scheduled task monitoring
WMI process execution analysis
Network connection telemetry analysis
Sysmon Event ID analysis
### 🛡️ Threat Detection
PowerShell execution detection
Encoded PowerShell detection
Registry persistence detection
Scheduled task persistence detection
WMI execution detection
Suspicious parent-child process detection
Network activity analysis
Basic C2 behavior analysis
### 🧩 MITRE ATT&CK

**Practical detection mapping and analysis of techniques including:**

T1059.001 — PowerShell
T1027 — Obfuscated/Compressed Files and Information
T1547.001 — Registry Run Keys / Startup Folder
T1053.005 — Scheduled Task/Job
T1047 — Windows Management Instrumentation
T1071.001 — Web Protocols
### 🧪 Practical Security Lab Skills
Windows security lab deployment
Sysmon configuration and telemetry collection
Splunk log ingestion
Controlled adversary-technique emulation
Detection validation
Investigation and triage
Incident documentation
Evidence-based security analysis

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
