
# PowerShell Detection - Splunk SPL

## Objective

Monitor PowerShell execution using Sysmon Event ID 1 and identify potentially suspicious command-line activity.

## Data Source

- SIEM: Splunk Enterprise
- Endpoint: Windows 10 Home 64-bit
- Log Source: Sysmon Operational
- Event ID: 1 - Process Creation
- Index: main

**Note:** The queries extract fields from raw Sysmon XML events using `rex`.

## Query 1 - PowerShell Execution

Monitor PowerShell process creation and review parent processes and command lines.

```spl
index=main sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
| rex field=_raw "<EventID>(?<EventCode>\d+)</EventID>"
| search EventCode=1
| rex max_match=0 field=_raw "<Data Name='(?<fieldname>[^']+)'>(?<fieldvalue>[^<]*)</Data>"
| eval pairs=mvzip(fieldname,fieldvalue,"=")
| eval Image=replace(mvindex(mvfilter(match(pairs,"^Image=")),0),"^Image=","")
| eval User=replace(mvindex(mvfilter(match(pairs,"^User=")),0),"^User=","")
| eval ParentImage=replace(mvindex(mvfilter(match(pairs,"^ParentImage=")),0),"^ParentImage=","")
| eval CommandLine=replace(mvindex(mvfilter(match(pairs,"^CommandLine=")),0),"^CommandLine=","")
| search Image="*powershell.exe"
| table _time User Image ParentImage CommandLine
| sort -_time
```

## Query 2 - Encoded PowerShell Commands

Identify PowerShell executions containing encoded command arguments.

```spl
index=main sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
| rex field=_raw "<EventID>(?<EventCode>\d+)</EventID>"
| search EventCode=1
| rex max_match=0 field=_raw "<Data Name='(?<fieldname>[^']+)'>(?<fieldvalue>[^<]*)</Data>"
| eval pairs=mvzip(fieldname,fieldvalue,"=")
| eval Image=replace(mvindex(mvfilter(match(pairs,"^Image=")),0),"^Image=","")
| eval User=replace(mvindex(mvfilter(match(pairs,"^User=")),0),"^User=","")
| eval ParentImage=replace(mvindex(mvfilter(match(pairs,"^ParentImage=")),0),"^ParentImage=","")
| eval CommandLine=replace(mvindex(mvfilter(match(pairs,"^CommandLine=")),0),"^CommandLine=","")
| search Image="*powershell.exe"
| where match(CommandLine,"(?i)-encodedcommand|-enc(\s|$)")
| table _time User ParentImage CommandLine
| sort -_time
```

## Query 3 - PowerShell Activity by User

Review PowerShell execution frequency by user.

```spl
index=main sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
| rex field=_raw "<EventID>(?<EventCode>\d+)</EventID>"
| search EventCode=1
| rex max_match=0 field=_raw "<Data Name='(?<fieldname>[^']+)'>(?<fieldvalue>[^<]*)</Data>"
| eval pairs=mvzip(fieldname,fieldvalue,"=")
| eval Image=replace(mvindex(mvfilter(match(pairs,"^Image=")),0),"^Image=","")
| eval User=replace(mvindex(mvfilter(match(pairs,"^User=")),0),"^User=","")
| search Image="*powershell.exe"
| stats count by User Image
| sort -count
```

## SOC Analyst Purpose

These searches help analysts:

- Monitor PowerShell execution.
- Identify encoded command usage.
- Review suspicious command-line arguments.
- Identify unusual PowerShell activity.
- Investigate parent-child process relationships.

## Investigation Considerations

Encoded PowerShell commands are not automatically malicious.

Analysts should review:

- Parent process and execution context.
- Decoded command behavior.
- User account associated with execution.
- Whether the command performs downloads, registry changes, or other sensitive actions.
- Additional endpoint and network evidence.

## Limitations

- Detection depends on available Sysmon Event ID 1 telemetry.
- Command-line visibility depends on event configuration.
- Matching encoded command arguments does not establish malicious intent.

**Project:** Mini SOC Home Lab  
**SIEM:** Splunk Enterprise  
**Endpoint:** Windows 10


