

# 🔬 Detection Lab 8: Full-Chain SOC Investigation & Threat Triage

## 1. Executive Summary
- **Objective:** Execute an end-to-end multi-event investigation correlating process creation (Sysmon Event ID 1) with outbound network activity (Sysmon Event ID 3), extract structured XML telemetry using Splunk SPL, and apply analyst reasoning to differentiate benign activity from high-risk C2 execution.
- **Environment:** Windows VM, Sysmon v14, Splunk Universal Forwarder, Splunk Enterprise.
- **MITRE ATT&CK Mapping:** 
  - **Tactic:** Execution ([TA0002](https://attack.mitre.org/tactics/TA0002/)) — **Technique:** Command and Scripting Interpreter: PowerShell ([T1059.001](https://attack.mitre.org/techniques/T1059/001/))
  - **Tactic:** Command and Control ([TA0109](https://attack.mitre.org/tactics/TA0109/)) — **Technique:** Application Layer Protocol: Web Protocols ([T1071.001](https://attack.mitre.org/techniques/T1071/001/))

---

## 2. Attack Emulation & Execution
To simulate a multi-stage attack chain, a child PowerShell process was spawned to initiate a network request:

### powershell
```Start-Process powershell -ArgumentList "-NoProfile -Command `"Invoke-WebRequest [https://example.com](https://example.com) -UseBasicParsing | Out-Null`""```
### Attack Breakdown:
**Start-Process powershell:** Spawns an isolated child PowerShell process.

**-NoProfile:** Evades profile loading to reduce execution footprint.

**Invoke-WebRequest https://example.com:** Initiates an outbound HTTPS connection.

**-UseBasicParsing | Out-Null:** Suppresses output rendering while completing the HTTP handshake.

---

## 3. Splunk Ingestion & Telemetry Correlation
### Phase 1: Process Creation Search (Event ID 1)
Verify that Sysmon captured the child process execution:

### Splunk SPL
``index=main source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
| spath
| search Event.System.EventID=1
| search "powershell.exe"
| table _time host``
### Phase 2: Outbound Network Connection Search (Event ID 3)
Extract XML attributes using regular expressions to correlate the process with network events:

### Splunk SPL
``index=main source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
| spath
| search Event.System.EventID=3
| rex field=_raw "<Data Name="['\"]Image['\"]">(?<Image>[^<]*)</Data>"
| rex field=_raw "<Data Name="['\"]User['\"]">(?<User>[^<]*)</Data>"
| rex field=_raw "<Data Name="['\"]Protocol['\"]">(?<Protocol>[^<]*)</Data>"
| rex field=_raw "<Data Name="['\"]Initiated['\"]">(?<Initiated>[^<]*)</Data>"
| rex field=_raw "<Data Name="['\"]DestinationIp['\"]">(?<DestinationIp>[^<]*)</Data>"
| rex field=_raw "<Data Name="['\"]DestinationPort['\"]">(?<DestinationPort>[^<]*)</Data>"
| where like(lower(Image), "%powershell.exe%")
| table _time host Image User Protocol Initiated DestinationIp DestinationPort
| sort - _time``

---

## 4. Case Investigation & Triage Analysis
### Telemetry Artifact Correlation Table:

| Triage Artifact              | Observed Telemetry Data                    | Analyst Reasoning & Findings |
| :--------------------------- | :----------------------------------------- | :--------------------------- |
| **Parent & Child Process**   | `powershell.exe` spawning `powershell.exe` | Parent shell executed a isolated child process utilizing `-NoProfile` arguments. |
| **Executed Command Line**    | `Invoke-WebRequest https://example.com`    | Standard unencoded HTTP GET request targeting a known, reserved RFC testing domain. |
| **Sysmon Event Correlation** | Event ID 1 (Process Create) ➡️ Event ID 3 (Network Connection) | Process creation directly generated an outbound socket connection across HTTPS (Port 443). |
| **Network Profile**           | `Protocol: TCP` / `DestinationPort: 443`  | Outbound web traffic utilizes standard encrypted web ports to a non-malicious host. |
| **Investigation Verdict**     | **False Positive — Benign Lab Activity**  | **Document & Close:** Detection triggered expected alert logic, but telemetry shows zero malicious intent, encoding, or lateral movement. |

---

### 5. Escalation Decision Matrix: Benign vs. Malicious Indicators
```
                                 PowerShell Outbound Activity Detected
                                                   │
                  ┌────────────────────────────────┴────────────────────────────────┐
                  │                                                                 │
    [Benign Profile (This Lab)]                                    [Malicious Profile (Escalate)]
   • Destination: example.com (Port 443)                           • Obfuscated / Base64 Encoded Commands (`-enc`)
   • Standard interactive user context                             • Connection to dynamic C2 / untrusted IP (`185.x.x.x`)
   • Unencoded web request commands                                • Non-standard ports (`4444`, `8080`, `1337`)
                  │                                                                 │
                  ▼                                                                 ▼
      [Document & Close Ticket]                                       [Isolate Host & Initiate IR Playbook]
```
---

## 6. Full Investigation Flowchart
```
                          ALERT TRIGGERED
                                │
                                ▼
                   PowerShell Process Creation
                                │
                                ▼
                    Sysmon Event ID 1 Logged
                   (CommandLine Identification)
                                │
                                ▼
                  Sysmon Event ID 3 Logged
               (Outbound Network Connection)
                                │
                                ▼
                     Destination IP: 443
                                │
                                ▼
                Context Correlation & Analysis
                                │
                                ▼
                     BENIGN TEST ACTIVITY
                                │
                                ▼
                    DOCUMENT & CLOSE TICKET

```
