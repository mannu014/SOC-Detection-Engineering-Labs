# 🔬 Detection Lab 3: Registry Persistence Detection

## 1. Executive Summary
- **Objective:** Detect adversary persistence established via Windows `CurrentVersion\Run` registry keys using Sysmon telemetry and Splunk SPL.
- **Environment:** Windows VM, Sysmon v14, Splunk Universal Forwarder, Splunk Enterprise.
- **MITRE ATT&CK Mapping:** 
  - **Tactic:** Persistence ([TA0003](https://attack.mitre.org/tactics/TA0003/))
  - **Technique:** Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder ([T1547.001](https://attack.mitre.org/techniques/T1547/001/))
  - **Technique:** Modify Registry ([T1112](https://attack.mitre.org/techniques/T1112/))

---

## 2. Attack Emulation
To simulate persistence after achieving initial access, an entry was added to the Current User `Run` registry key via PowerShell:

### powershell

`New-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" -Name "LabTest" -Value "notepad.exe" -Force`

#### Attack Mechanism: Applications registered under the Run registry key execute automatically every time the target user logs into the operating system.

## 3. Log Telemetry & Event Identification

-Log Source: WinEventLog:Microsoft-Windows-Sysmon/Operational

-Sysmon Event ID: 13 (RegistryEvent - Value Set)

-Target Path: HKCU:\Software\Microsoft\Windows\CurrentVersion\Run

-Created Value Name: LabTest

-Target Payload: notepad.exe

## 4. Splunk SPL Detection Query
### Splunk SPL
`sysmon_base
| search Event.System.EventID=13
| table _time Event.System.EventID`

### SPL Explanation:
Macro Base: Loads raw Sysmon event logs using sysmon_base.

Event ID Filter: Filters strictly for Sysmon Event ID 13, which tracks registry value creation and modification events.

Output: Formats matching events into a simple table displaying event timestamps and Event IDs.

5. SOC Analyst Triage & Remediation Steps
Verify Target Path: Confirm whether the modified registry key is a known autostart location (e.g., ...\CurrentVersion\Run or ...\CurrentVersion\RunOnce).

Inspect Executable Path: Verify if the target binary (notepad.exe in this lab) is located in a standard system directory or executing from an untrusted path (e.g., AppData\Local\Temp).

Remediation: Remove unauthorized startup entries from the registry using PowerShell:

###PowerShell
`Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" -Name "LabTest"`

