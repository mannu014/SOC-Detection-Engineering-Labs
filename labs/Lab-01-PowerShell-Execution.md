# 🔬 Detection Lab 1: PowerShell Execution Telemetry & XML Parsing

## 1. Executive Summary
- **Objective:** Simulate a standard PowerShell command execution, parse raw Sysmon XML telemetry using Splunk `rex` regex field extractions, and isolate command-line execution details.
- **Environment:** Windows VM, Sysmon v14, Splunk Universal Forwarder, Splunk Enterprise.
- **MITRE ATT&CK Mapping:** 
  - **Tactic:** Execution ([TA0002](https://attack.mitre.org/tactics/TA0002/))
  - **Technique:** Command and Scripting Interpreter: PowerShell ([T1059.001](https://attack.mitre.org/techniques/T1059/001/))

---

## 2. Attack Emulation
To trigger benign process creation telemetry while capturing true execution parameters, the following safe commands were executed sequentially inside PowerShell on the target VM:

```powershell``

Get-Date

Get-Process

Get-Service

Purpose: Adversaries frequently use initial discovery commands via PowerShell upon landing on an endpoint.

## 3 Log Telemetry & Event Identification
-Log Source: WinEventLog:Microsoft-Windows-Sysmon/Operational

-Sysmon Event ID: 1 (Process Creation)

-Target Process: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe

## 4. Splunk SPL Detection & Regex Parsing Query
Splunk SPL
`sysmon_base 
| rex field=_raw "<Data Name="Image">(?<ImagePath>[^<]+)</Data>"
| rex field=_raw "<Data Name="CommandLine">(?<CmdLine>[^<]+)</Data>"
| search ImagePath="*powershell.exe"
| table _time ImagePath CmdLine`

## SPL Explanation:
1. Macro Base: Filters down to raw Sysmon logs via sysmon_base.

2. Regex Field Extractions (rex):

3. Extracts the binary path (ImagePath) from XML data tags.

4. Extracts full command-line arguments (CmdLine) executed by the process.

5. Filtering: Filters results specifically for instances involving powershell.exe.

## Output: Displays a clean timestamped table of all PowerShell executions along with their command lines.

## 5. SOC Analyst Takeaways
-Field Extraction Mastery: Standard Windows event logs often ship as raw XML blocks. Using rex to perform inline regex parsing enables rapid custom field extraction without relying on pre-built data models.

-Baseline Monitoring: Command-line visibility is vital for identifying initial reconnaissance activities like process listing (Get-Process) or service discovery (Get-Service).

