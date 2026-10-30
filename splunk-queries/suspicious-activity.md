
# Suspicious Activity Detection - Splunk SPL

## Objective

Identify potentially suspicious Windows endpoint activity using Sysmon telemetry and Splunk Enterprise.

These searches support SOC Tier 1 alert triage and investigation.

## Data Source

- SIEM: Splunk Enterprise
- Endpoint: Windows 10 Home 64-bit
- Log Source: Sysmon Operational
- Index: main

**Note:** Sysmon events are ingested as XML. These queries extract fields from raw events using `rex`.

## Query 1 - Suspicious PowerShell Arguments

Identify PowerShell executions containing potentially suspicious command-line arguments.

```spl
index=main sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
| rex field=_raw "<EventID>(?<EventCode>\d+)</EventID>"
| search EventCode=1
| rex max_match=0 field=_raw "<Data Name='(?<fieldname>[^']+)'>(?<fieldvalue>[^<]*)</Data>"
| eval pairs=mvzip(fieldname,fieldvalue,"=")
| eval User=replace(mvindex(mvfilter(match(pairs,"^User=")),0),"^User=","")
| eval ParentImage=replace(mvindex(mvfilter(match(pairs,"^ParentImage=")),0),"^ParentImage=","")
| eval Image=replace(mvindex(mvfilter(match(pairs,"^Image=")),0),"^Image=","")
| eval CommandLine=replace(mvindex(mvfilter(match(pairs,"^CommandLine=")),0),"^CommandLine=","")
| search Image="*powershell.exe"
| where match(CommandLine,"(?i)-encodedcommand|-enc(\s|$)|-windowstyle\s+hidden|-executionpolicy\s+bypass")
| table _time User ParentImage Image CommandLine
| sort -_time
```

## Query 2 - Parent-Child Process Analysis

Review parent-child process relationships and identify execution patterns that may require further investigation.

```spl
index=main sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
| rex field=_raw "<EventID>(?<EventCode>\d+)</EventID>"
| search EventCode=1
| rex max_match=0 field=_raw "<Data Name='(?<fieldname>[^']+)'>(?<fieldvalue>[^<]*)</Data>"
| eval pairs=mvzip(fieldname,fieldvalue,"=")
| eval Image=replace(mvindex(mvfilter(match(pairs,"^Image=")),0),"^Image=","")
| eval ParentImage=replace(mvindex(mvfilter(match(pairs,"^ParentImage=")),0),"^ParentImage=","")
| stats count by ParentImage Image
| sort -count
| head 20
```

## Query 3 - Process Termination Monitoring

Monitor process termination events using Sysmon Event ID 5.

```spl
index=main sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
| rex field=_raw "<EventID>(?<EventCode>\d+)</EventID>"
| search EventCode=5
| rex max_match=0 field=_raw "<Data Name='(?<fieldname>[^']+)'>(?<fieldvalue>[^<]*)</Data>"
| eval pairs=mvzip(fieldname,fieldvalue,"=")
| eval Image=replace(mvindex(mvfilter(match(pairs,"^Image=")),0),"^Image=","")
| eval ProcessId=replace(mvindex(mvfilter(match(pairs,"^ProcessId=")),0),"^ProcessId=","")
| table _time Image ProcessId
| sort -_time
```

## SOC Analyst Purpose

- Identify potentially suspicious command-line arguments.
- Investigate unusual process execution.
- Review parent-child process relationships.
- Monitor process termination events.
- Support incident triage and escalation.

## Investigation Considerations

Suspicious command-line arguments do not automatically indicate malicious activity.

Analysts should:

- Review the complete command line.
- Identify the parent process and user.
- Decode encoded commands when appropriate.
- Determine what the command actually does.
- Correlate process activity with network and other endpoint events.
- Document findings and escalate when evidence supports it.

## Limitations

- Detection depends on available Sysmon telemetry.
- Event ID 5 records process termination, not the reason a process stopped.
- Process relationships and command-line arguments require contextual analysis.
- A detection match is an investigation lead, not proof of compromise.

**Project:** Mini SOC Home Lab  
**SIEM:** Splunk Enterprise  
**Endpoint:** Windows 10

