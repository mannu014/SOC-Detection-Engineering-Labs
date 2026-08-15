# 🔬 Detection Lab 4: Suspicious Parent-Child Process Detection

## 1. Executive Summary
- **Objective:** Detect anomalous process execution chains where PowerShell is spawned by unexpected parent processes (such as `cmd.exe`, MS Office applications, or script hosts), mimicking phishing payload drops and malicious macro execution.
- **Environment:** Windows VM, Sysmon v14, Splunk Universal Forwarder, Splunk Enterprise.
- **MITRE ATT&CK Mapping:** 
  - **Tactic:** Execution ([TA0002](https://attack.mitre.org/tactics/TA0002/))
  - **Technique:** Command and Scripting Interpreter: PowerShell ([T1059.001](https://attack.mitre.org/techniques/T1059/001/))
  - **Technique:** User Execution: Malicious File ([T1204.002](https://attack.mitre.org/techniques/T1204/002/))

---

## 2. Attack Emulation & Process Chain Generation
To simulate a parent process spawning PowerShell without relying on direct user initiation through Windows GUI (`explorer.exe`), the following command was executed in Command Prompt (`cmd.exe`):

### cmd
`powershell -Command "Get-Date"`

### Target Process Chain:

1.cmd.exe (Parent Process) ➡️ powershell.exe (Child Process)

### Threat Context: While benign, this emulates real-world malicious execution paths such as WINWORD.EXE → powershell.exe (Office Macro Execution) or wscript.exe → powershell.exe (VBScript payload execution).

## 3. Log Telemetry & Event Identification

-Log Source: XmlWinEventLog:Microsoft-Windows-Sysmon/Operational

-Sysmon Event ID: 1 (Process Creation)

-Key Fields Tracked:

-Event.EventData.Image: Target process (powershell.exe)

-Event.EventData.ParentImage: Spawning binary (cmd.exe)

-Event.EventData.CommandLine: Executed command parameters (powershell -Command "Get-Date")

## 4. Splunk SPL Detection & Analysis Queries
Macro Configuration: sysmon_base expands to index=main source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" | spath to ingest raw XML telemetry and auto-extract fields.

## Initial Process Chain Discovery Search
### Splunk SPL
`sysmon_base
| search Event.System.EventID=1
| table _time Event.EventData.Image Event.EventData.ParentImage Event.EventData.CommandLine
| head 20`

## Targeted Parent-Child Detection Query
Splunk SPL
`sysmon_base
| search Event.System.EventID=1
| search Event.EventData.Image="*powershell.exe"
| search Event.EventData.ParentImage="*cmd.exe"
| table _time Event.EventData.ParentImage Event.EventData.Image Event.EventData.CommandLine`

### SPL Explanation:
1. Macro Ingestion & XML Parsing: Invokes sysmon_base to target raw XmlWinEventLog data and runs spath for node extraction.

2. Event Filter: Filters specifically for Sysmon Event ID 1 (Process Creation).

3. Parent-Child Correlation: Matches instances where Event.EventData.Image ends in powershell.exe and Event.EventData.ParentImage ends in cmd.exe.

### Output: Displays execution timestamps alongside parent binary, child process, and full command-line arguments.

## 5. SOC Analyst Triage & Remediation Steps
1. Identify Parent Binary Context: Determine if the parent process is a web browser (chrome.exe), Office app (winword.exe, excel.exe), or scripting engine (wscript.exe, mshta.exe). High-risk parent binaries warrant immediate escalation.

2. Inspect Command Line: Analyze the child process command line for download strings (Invoke-WebRequest, Net.WebClient), hidden window flags (-WindowStyle Hidden), or Base64 encoding.

3. Cross-Reference Network Telemetry: Correlate Event ID 1 with Sysmon Event ID 3 (Network Connection) for the parent or child process PID to check for outbound C2 callback activity.

### Remediation: If unexpected, terminate the child process tree and isolate the affected host.


