# 🔬 Detection Lab 7: Sysmon Network Connection Telemetry & Analysis

## 1. Executive Summary
- **Objective:** Capture and analyze process network activity via Sysmon Event ID 3, engineer robust XML regex field extraction rules in Splunk SPL when node attributes fail to flatten, and evaluate network connections using threat triage frameworks.
- **Environment:** Windows VM, Sysmon v14, Splunk Universal Forwarder, Splunk Enterprise.
- **MITRE ATT&CK Mapping:** 
  - **Tactic:** Command and Control ([TA0109](https://attack.mitre.org/tactics/TA0109/))
  - **Technique:** Application Layer Protocol: Web Protocols ([T1071.001](https://attack.mitre.org/techniques/T1071/001/))
  - **Technique:** Ingress Tool Transfer ([T1105](https://attack.mitre.org/techniques/T1105/))

---

## 2. Telemetry Ingestion & XML Field Extraction Strategy

### Ingestion Verification
- **Log Channel:** `Microsoft-Windows-Sysmon/Operational`
- **Target Event ID:** `3` (Network Connection Initiated)
- **Ingestion Challenge:** Raw Sysmon events ingested as XML store key-value telemetry within nested `<Data Name="...">` nodes. When standard `spath` multi-value index flattening fails to surface discrete named fields, direct regex extractions (`rex`) are leveraged.

### Production Production Extraction & Analysis Search

### spl
`index=main source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
| spath
| search Event.System.EventID=3
| rex field=_raw "<Data Name="['\"]Image['\"]">(?<Image>[^<]*)</Data>"
| rex field=_raw "<Data Name="['\"]User['\"]">(?<User>[^<]*)</Data>"
| rex field=_raw "<Data Name="['\"]Protocol['\"]">(?<Protocol>[^<]*)</Data>"
| rex field=_raw "<Data Name="['\"]Initiated['\"]">(?<Initiated>[^<]*)</Data>"
| rex field=_raw "<Data Name="['\"]SourceIp['\"]">(?<SourceIp>[^<]*)</Data>"
| rex field=_raw "<Data Name="['\"]SourcePort['\"]">(?<SourcePort>[^<]*)</Data>"
| rex field=_raw "<Data Name="['\"]DestinationIp['\"]">(?<DestinationIp>[^<]*)</Data>"
| rex field=_raw "<Data Name="['\"]DestinationPort['\"]">(?<DestinationPort>[^<]*)</Data>"
| table _time host Image User Protocol Initiated SourceIp SourcePort DestinationIp DestinationPort
| sort - _time`

### SPL Explanation:
**Source Isolation:** Filters specifically for XmlWinEventLog telemetry under Event ID 3.

**Explicit Regular Expression Extractions (rex):** Captures individual values directly from the _raw XML string tags (Image, Protocol, SourceIp, DestinationIp, DestinationPort).

**Structured Dashboard Output:** Formats extracted attributes into a clear timeline sorted by event timestamp.

## 3. Case Investigation & Network Triage

### Observed Telemetry Artifact
| Field Name | Extracted Value | Analysis Context |
| :--- | :--- | :--- |
| **Process Binary (`Image`)** | `C:\Users\...\OneDrive.Sync.Service.exe` | Legitimate executable path |
| **Protocol** | `TCP` | Standard transport protocol |
| **Initiated** | `true` | Outbound socket connection initiated by host |
| **Source IP / Port** | `192.168.43.135` / `62716` | Internal lab machine IP and dynamic ephemeral port |
| **Destination IP** | `20.42.65.88` | Microsoft infrastructure endpoint |
| **Destination Port** | `443` | Standard encrypted HTTPS web traffic |

### SOC Analyst Triage Checklist
| Investigation Check | Observation | Assessment |
| :--- | :--- | :--- |
| **Binary Legitimacy** | Executable is standard OneDrive sync utility | Normal / Expected |
| **Execution Path** | File is running from standard system location | Benign |
| **Destination Reputation** | `20.42.65.88` maps to Microsoft Azure/Cloud range | Trusted |
| **Port & Protocol** | Standard TCP port 443 (HTTPS) | Expected |
| **Final Classification** | **True Positive (Benign Activity)** | **Action:** Document & Close Ticket |

### Analyst Assessment & Triage Checklist:
**Binary Location & Legitimacy:** OneDrive.Sync.Service.exe is running from a recognized system directory.

**Destination Identity:** Destination IP (20.42.65.88) resolves to Microsoft cloud infrastructure.

**Port Profile:** Connection utilizes standard HTTPS (443) for file synchronization.

**Verdict:** Benign / Expected Activity. While the event rule triggered correctly, the underlying activity represents legitimate software operations rather than a security breach.

## 4. Threat Indicators: Benign vs. High-Risk Indicators


###              Sysmon Event ID 3 Triggered
                              │
            ┌─────────────────┴─────────────────┐
            │                                   │
   Expected System Binary             Anomalous / LOLBIN Executable
 (e.g., OneDrive / Browser)        (e.g., AppData\Temp\update.exe,
            │                       powershell.exe, wscript.exe)
            │                                   │
    Standard Port (443)                 Non-Standard Port (4444)
    Known Enterprise IP                 Unverified / Suspicious External IP
            │                                   │
            ▼                                   ▼
 [Benign / Document & Close]          [High-Risk / Escalate Investigation]

### High-Risk Indicators Requiring Escalation:

Non-browser binaries (powershell.exe, cmd.exe, rundll32.exe, mshta.exe, certutil.exe) opening outbound external network sockets.

Executables spawning out of staging directories (C:\Users\*\AppData\Local\Temp\ or C:\ProgramData\).

Connections across non-standard remote ports (e.g., 4444, 8080, 1337).

## 5. Multi-Event Telemetry Correlation Playbook

When an anomalous Event ID 3 is identified, analysts must correlate across adjacent Sysmon telemetry:

[Event ID 1: Process Creation] ➡️ [Event ID 3: Outbound Connection] ➡️ [Event ID 11: File Dropped]
  (Who spawned the process?)      (Where did it connect?)            (What payload was written?)

