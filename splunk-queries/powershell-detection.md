
# PowerShell Detection - Splunk SPL

## Objective
Monitor PowerShell execution and identify potentially suspicious commands.

## Query 1 - PowerShell Execution

```spl
index=* EventCode=1
| search Image="*powershell.exe"
| table _time host User Image ParentImage CommandLine
| sort -_time
```

## Query 2 - Encoded PowerShell Commands

```spl
index=* EventCode=1
| search CommandLine="*-EncodedCommand*" OR CommandLine="*-enc*"
| table _time host User ParentImage CommandLine
| sort -_time
```

## Query 3 - PowerShell Activity by User

```spl
index=* EventCode=1
| search Image="*powershell.exe"
| stats count by User Image
| sort - count
```

## SOC Analyst Purpose

These searches help analysts:

- Monitor PowerShell execution.
- Identify encoded command usage.
- Review suspicious command-line arguments.
- Identify unusual PowerShell activity.
- Investigate parent-child process relationships.

## Data Source

Sysmon Operational Event Log.

## Event ID

Event ID 1 - Process Creation.

**Project:** Mini SOC Home Lab  
**SIEM:** Splunk Enterprise  
**Endpoint:** Windows 10
