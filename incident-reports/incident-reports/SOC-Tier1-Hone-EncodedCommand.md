
# SOC Tier 1 Incident Report
## Hone - Encoded PowerShell Investigation

### 1. Incident Information

| Field | Details |
|---|---|
| Incident ID | MINI-SOC-2026-001 |
| Analyst | Raymond Ramirez Torres |
| Incident Type | Suspicious PowerShell Activity |
| Source | TryHackMe SOC Investigation Lab |
| Severity | Medium - Preliminary |
| Status | Investigated |
| Tool | Splunk |

### 2. Executive Summary

During this investigation, suspicious PowerShell activity involving an EncodedCommand parameter was reviewed.

The investigation focused on analyzing process execution, identifying the parent process, decoding the Base64 command, and understanding the behavior of the executed script.

The objective was to determine whether the observed activity represented malicious behavior or legitimate administrative activity.

### 3. Investigation Objectives

- Identify suspicious PowerShell execution.
- Analyze process creation events.
- Review parent-child process relationships.
- Decode the Base64 command.
- Determine the behavior of the executed command.
- Document findings and recommend next steps.

### 4. Tools Used

| Tool | Purpose |
|---|---|
| Splunk | Event log analysis |
| Sysmon | Endpoint telemetry |
| PowerShell | Command analysis |
| TryHackMe | Investigation environment |

### 5. Investigation Process

**Step 1 - PowerShell Activity**

Reviewed PowerShell-related events to identify suspicious execution patterns, including encoded commands.

**Step 2 - Process Analysis**

Examined process creation events and parent-child relationships to understand how PowerShell was launched.

**Step 3 - Base64 Analysis**

Reviewed and decoded the EncodedCommand parameter to understand the actual command being executed.

**Step 4 - Behavioral Analysis**

Evaluated the decoded command to identify potentially suspicious actions and determine whether additional investigation was necessary.


### 6. Findings

- PowerShell execution containing an EncodedCommand parameter was identified.
- The process tree showed PowerShell launched through cmd.exe, with Hone.exe as the parent application.
- The Base64 command was decoded and reviewed.
- The decoded commands queried Windows system information, including operating system details and connected input devices.
- No confirmed malicious behavior was identified in the decoded commands examined.

### 7. Incident Classification

**Preliminary Classification:** Likely Benign - Further Validation Required.

The observed PowerShell activity was associated with the Hone Windows optimization application. The decoded commands examined appeared to collect system and device information.

The use of EncodedCommand and ExecutionPolicy Bypass can be suspicious indicators, but they do not independently establish malicious activity.

The investigation did not establish a confirmed security incident. Additional review of related events would be necessary to validate the complete execution context.

### 8. Recommendations

- Monitor encoded PowerShell execution.
- Review unusual parent-child process relationships.
- Investigate unexpected PowerShell network connections.
- Correlate Sysmon events with other Windows logs.
- Escalate confirmed malicious behavior to Tier 2.

### 9. Skills Demonstrated

- SIEM investigation using Splunk.
- Windows event log analysis.
- Sysmon telemetry analysis.
- PowerShell investigation.
- Base64 command analysis.
- Incident documentation.
- Security alert triage.

### 10. Conclusion

This investigation provided practical experience analyzing suspicious PowerShell activity in a SOC environment.

The investigation followed a structured Tier 1 workflow involving event review, process analysis, command decoding, behavioral assessment, and incident documentation.

---

**Project:** Mini SOC Home Lab  
**Analyst:** Raymond Ramirez Torres  
**Role:** SOC Analyst Tier 1 Portfolio
