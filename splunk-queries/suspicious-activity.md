
# Suspicious Activity Detection - Splunk SPL

## Objective
Identify potentially suspicious Windows endpoint activity using Sysmon telemetry.

## Query 1 - Suspicious PowerShell Arguments

```spl
index=* EventCode=1
| search CommandLine="*-EncodedCommand*" OR CommandLine="*-WindowStyle Hidden*" OR CommandLine="*-ExecutionPolicy Bypass*"
| table _time host User ParentImage Image CommandLine
| sort -_time
```

## Query 2 - Unusual Process Execution

```spl
index=* EventCode=1
| stats count by ParentImage Image
| sort - count
| head 20
```

## Query 3 - Process Termination Monitoring

```spl
index=* EventCode=5
| table _time host Image ProcessId
| sort -_time
```

## SOC Analyst Purpose

- Identify potentially suspicious command-line arguments.
- Investigate unusual process execution.
- Review parent-child process relationships.
- Monitor process termination events.
- Support incident triage and escalation.

## Data Source

Sysmon Operational Event Log.

## Event IDs

- Event ID 1 - Process Creation.
- Event ID 5 - Process Termination.

**Project:** Mini SOC Home Lab  
**SIEM:** Splunk Enterprise  
**Endpoint:** Windows 10
