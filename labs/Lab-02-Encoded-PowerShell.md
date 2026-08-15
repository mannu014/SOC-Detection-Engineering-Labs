# 🔬 Detection Lab 2: Encoded PowerShell Detection

## 1. Executive Summary
- **Objective:** Detect execution of Base64-encoded PowerShell commands used by threat actors to obfuscate script content and bypass basic string-matching security controls.
- **Environment:** Windows VM, Sysmon v14, Splunk Universal Forwarder, Splunk Enterprise.
- **MITRE ATT&CK Mapping:** 
  - **Tactic:** Execution ([TA0002](https://attack.mitre.org/tactics/TA0002/))
  - **Tactic:** Defense Evasion ([TA0005](https://attack.mitre.org/tactics/TA0005/))
  - **Technique:** Command and Scripting Interpreter: PowerShell ([T1059.001](https://attack.mitre.org/techniques/T1059/001/))
  - **Technique:** Obfuscated Files or Information ([T1027](https://attack.mitre.org/techniques/T1027/))

---

## 2. Attack Emulation
To simulate an obfuscated command execution, a Base64-encoded string was passed to PowerShell via the command line:

```powershell``

powershell -enc RwBlAHQALQBEAGEAdABlAA==

## Payload Analysis:

Base64 String: RwBlAHQALQBEAGEAdABlAA==

Decoded Value: Get-Date (UTF-16LE / Unicode encoded)

## 3. Log Telemetry & Event Identification
Log Source: WinEventLog:Microsoft-Windows-Sysmon/Operational

Sysmon Event ID: 1 (Process Creation)

Key Attribute: CommandLine containing -enc flag followed by Base64 text.

## 4. Splunk SPL Detection Query
# Splunk SPL
`sysmon_base`
| rex field=_raw "<Data Name="CommandLine">(?<CmdLine>[^<]+)</Data>"
| search CmdLine="*-enc*" OR CmdLine="*-EncodedCommand*"
| table _time CmdLine

# SPL Explanation:
1. Macro Base: Filters down to raw Sysmon event logs using sysmon_base.

2. Field Extraction (rex): Extracts the raw command line string into the CmdLine field directly from the raw XML payload.

3. Pattern Matching: Filters events specifically where CmdLine contains parameter variations like -enc or -EncodedCommand.

## Output: Formats results into a table displaying the exact execution timestamp and command string.

## 5. SOC Analyst Triage & Remediation Steps

-Extract Base64 Payload: Copy the encoded string from the CmdLine output.

-Decode Payload: Input the string into CyberChef (using From Base64 -> Decode Text (UTF-16LE)) or decode in PowerShell:

# PowerShell
[System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String("RwBlAHQALQBEAGEAdABlAA=="))

-Assess Threat Intent: Review the decoded script to check for secondary malicious activities (such as web downloads via Invoke-WebRequest or memory injection).
