# 🔬 Detection Lab 6: WMI Process Creation Detection & Triage

## 1. Executive Summary
- **Objective:** Detect and analyze process creation initiated via Windows Management Instrumentation (`wmic.exe`), parse raw XML telemetry using `spath`/`rex` in Splunk, and practice distinguishing True Positive (TP) detections from actual malicious activity.
- **Environment:** Windows VM, Sysmon v14, Splunk Universal Forwarder, Splunk Enterprise.
- **MITRE ATT&CK Mapping:** 
  - **Tactic:** Execution ([TA0002](https://attack.mitre.org/tactics/TA0002/))
  - **Technique:** Windows Management Instrumentation ([T1047](https://attack.mitre.org/techniques/T1047/))

---

## 2. Attack Emulation & Mechanics
To simulate WMI-based process creation, two controlled executions were triggered from different parent shells:

* **Test 1:** `wmic process call create "notepad.exe"` (Parent Shell: PowerShell)
* **Test 2:** `wmic process call create "calc.exe"` (Parent Shell: Command Prompt)

### Conceptual Process Chains
### text
[PowerShell.exe] ➡️ [WMIC.exe] ➡️ [WMI Engine] ➡️ [notepad.exe]
[cmd.exe]        ➡️ [WMIC.exe] ➡️ [WMI Engine] ➡️ [calc.exe]

### Command Breakdown:
wmic: Windows Management Instrumentation command-line utility.

process: WMI class targeted for execution.

call create: WMI method invoked to spawn the target application.

## 3. Log Telemetry & Data Ingestion Pipeline
## Universal Forwarder Validation

Telemetry ingestion was configured in inputs.conf to collect raw XML Sysmon logs:

Channel: Microsoft-Windows-Sysmon/Operational

Settings: renderXml = true, start_from = oldest, index = main

Validation Command:

### `PowerShell`
`& "C:\Program Files\SplunkUniversalForwarder\bin\splunk.exe" btool inputs list --debug`
Target Sysmon Artifact:
Event ID: 1 (Process Create)

Key Fields Monitored: Image, ParentImage, CommandLine, ParentCommandLine, User, ProcessId, UtcTime

## 4. XML Parsing & Detection Logic

Because logs were ingested as raw XML structure, standard field extractions required spath and rex pattern matching.

## Refined Detection & Correlation Search
### Splunk SPL
`sysmon_base
| spath
| search Event.System.EventID=1
| rex field=_raw "<Data Name="Image">(?<Image>[^<]+)</Data>"
| rex field=_raw "<Data Name="CommandLine">(?<CommandLine>[^<]+)</Data>"
| rex field=_raw "<Data Name="ParentImage">(?<ParentImage>[^<]+)</Data>"
| rex field=_raw "<Data Name="ParentCommandLine">(?<ParentCommandLine>[^<]+)</Data>"
| search Image="*wmic.exe*" CommandLine="*process call create*"
| table _time host User ParentImage ParentCommandLine Image CommandLine`
### SPL Explanation:
-Macro Ingestion: Invokes sysmon_base targeting XmlWinEventLog telemetry.

-XML Node Extraction (spath/rex): Parses raw XML tags to populate Image, ParentImage, and CommandLine key-value pairs.

-Behavioral Logic: Filters specifically for executions where Image is wmic.exe AND CommandLine contains process call create.

-Contextual Display: Tables user identity, parent process chain, and child arguments for immediate triage.

## 5. SOC Analyst Triage: True Positive vs. Malicious Classification
A core focus of this lab was understanding alert triage workflow:

Plaintext
                     Did Detection Rule Match Intended Behavior?
                                         │
                        ┌────────────────┴────────────────┐
                       YES                                NO
                        │                                  │
                 True Positive (TP)                 False Positive (FP)
                        │
             Is the Activity Malicious?
             ┌──────────┴──────────┐
            YES                    NO
             │                     │
    Escalate / Contain     Document / Close (Benign TP)
### Lab 6 Case Analysis:
Rule Match: Yes — The detection matched wmic.exe process creation perfectly (True Positive ✅).

Malicious Intent: No — Executed applications were notepad.exe and calc.exe as part of controlled testing (Benign Activity ❌).

Analyst Action: Document investigation notes and close ticket without escalation (Document / Close ✅).

## 6. End-to-End Detection Workflow Summary
Plaintext
[Generate WMI Activity] 
       ⬇️
[Sysmon Event ID 1 Generated] 
       ⬇️
[Ingested as XML via Splunk UF] 
       ⬇️
[Parsed via spath & rex] 
       ⬇️
[Correlated Parent/Child Chains] 
       ⬇️
[Classified as Benign True Positive (TP)] 
       ⬇️
[Ticket Closed & Documented]
