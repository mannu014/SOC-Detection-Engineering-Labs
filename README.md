# 🛡️ SOC & Detection Engineering Portfolio

Hands-on cybersecurity repository documenting lab setups, adversary technique emulation, and custom detection engineering in Splunk.

## 💻 Home Lab Architecture
- **SIEM:** Splunk Enterprise 9.x
- **Telemetry:** Sysmon v14 + Windows Event Logs via Universal Forwarder
- **Target OS:** Windows 10/11 VM
- **Attack Platform:** PowerShell / Kali Linux

---

## 🔬 Detection Engineering Labs

| Lab #  | Lab Name                           | Focus Area  | Attack Technique | Write-Up Link |
| :---:  | :--------------------------------- | :---------- | :--------------- | :-----------: |
| **01** | PowerShell Execution & XML Parsing | Execution   | T1059.001        | [View Write-Up](labs/Lab-01-PowerShell-Execution.md) |
| **02** | Encoded PowerShell Detection       | Obfuscation | T1027            | [View Write-Up](labs/Lab-02-Encoded-PowerShell.md)   |
| **03** | Registry Persistence Detection     | Persistence | T1547.001        | [View Write-Up](labs/Lab-03-Registry-Persistence.md) |
| **04** | Parent-Child Process Anomaly       | Execution   | T1059            | *In Progress* |
| **05** | Scheduled Task Persistence         | Persistence | T1053.005        | *In Progress* |
