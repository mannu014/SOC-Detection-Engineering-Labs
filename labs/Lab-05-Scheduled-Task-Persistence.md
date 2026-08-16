# 🔬 Detection Lab 5: Scheduled Task Persistence Detection

## 1. Executive Summary
- **Objective:** Detect the creation and registration of unauthorized Windows Scheduled Tasks used by malware, ransomware, and red-team operators to establish persistence and achieve scheduled payload execution.
- **Environment:** Windows VM, TaskScheduler Operational Logs, Splunk Universal Forwarder, Splunk Enterprise.
- **MITRE ATT&CK Mapping:** 
  - **Tactic:** Persistence ([TA0003](https://attack.mitre.org/tactics/TA0003/))
  - **Tactic:** Execution ([TA0002](https://attack.mitre.org/tactics/TA0002/))
  - **Technique:** Scheduled Task/Job: Scheduled Task ([T1053.005](https://attack.mitre.org/techniques/T1053/005/))

---

## 2. Attack Emulation & Task Creation
To simulate an adversary attempting autostart execution via Windows Task Scheduler, a new task was created using `schtasks.exe` in elevated PowerShell:

### powershell
`schtasks /create /tn "SplunkLabTask" /tr "notepad.exe" /sc once /st 23:59 /f`

### Parameters Defined:

/tn "SplunkLabTask": Task Name

/tr "notepad.exe": Action / Program to execute

/sc once /st 23:59: Schedule trigger (Run once at 23:59)

/f: Force creation (overwrite existing)

## 3. Log Telemetry & Event Identification

Log Source: XmlWinEventLog:Microsoft-Windows-TaskScheduler/Operational

### Key TaskScheduler Event IDs:
 
Event ID 106: User registered a scheduled task (Task Creation).

Event ID 140 / 141: Task updated or deleted.

Event ID 200 / 201: Task executed / completed.

Target Task Captured: SplunkLabTask

## 4. Splunk SPL Detection & Analysis Queries
### Targeted Task Creation Discovery Search
### Splunk SPL
`index=main source="XmlWinEventLog:Microsoft-Windows-TaskScheduler/Operational"
| search SplunkLabTask`
### Advanced Task Registration Detection Query
### Splunk SPL
`index=main source="XmlWinEventLog:Microsoft-Windows-TaskScheduler/Operational" Event.System.EventID=106
| table _time Event.System.EventID Event.EventData.TaskName Event.EventData.ActionName Event.System.Execution.ProcessID`

### SPL Explanation:

-Source Filtering: Targets raw XML logs forwarded specifically from the TaskScheduler/Operational Windows log channel.

-Event ID Isolation: Filters for Event ID 106 to pinpoint task creation and registration activities specifically.

-Structured Field Output: Formats results to expose the exact task name, targeted executable action, process ID, and registration timestamp.

## 5. SOC Analyst Triage & Remediation Steps

1. Analyze Task Payload: Inspect the ActionName field. Verify if the target application is standard administrative software or executing suspicious binaries/scripts (powershell.exe -enc, wscript.exe, cmd.exe /c).

2. Review Execution Privileges: Determine if the task is configured to run under SYSTEM or high-privilege user accounts.

3. Inspect Schedule Triggers: Look for suspicious recurrence patterns (e.g., executing at system startup, every 5 minutes, or during off-hours).

4. Remediation & Cleanup: Delete the malicious scheduled task via PowerShell or Command Prompt:

### PowerShell
`schtasks /delete /tn "SplunkLabTask" /f`
