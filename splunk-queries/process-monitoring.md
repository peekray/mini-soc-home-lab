
# Process Monitoring - Splunk SPL

## Objective

Monitor Windows process creation events using Sysmon Event ID 1 and Splunk Enterprise.

Process monitoring helps SOC analysts understand which applications are running, which users are executing them, and how processes are being launched.

## Data Source

- SIEM: Splunk Enterprise
- Endpoint: Windows 10 Home 64-bit
- Log Source: Sysmon Operational
- Event ID: 1 - Process Creation
- Index: main

**Note:** Sysmon events are ingested as XML. These queries extract the required fields from raw events using `rex`.

## Query 1 - Process Creation Events

Display process creation events with user, executable, parent process, and command line information.

```spl id="v8t5l2"
index=main sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
| rex field=_raw "<EventID>(?<EventCode>\d+)</EventID>"
| search EventCode=1
| rex max_match=0 field=_raw "<Data Name='(?<fieldname>[^']+)'>(?<fieldvalue>[^<]*)</Data>"
| eval pairs=mvzip(fieldname,fieldvalue,"=")
| eval User=replace(mvindex(mvfilter(match(pairs,"^User=")),0),"^User=","")
| eval Image=replace(mvindex(mvfilter(match(pairs,"^Image=")),0),"^Image=","")
| eval ParentImage=replace(mvindex(mvfilter(match(pairs,"^ParentImage=")),0),"^ParentImage=","")
| eval CommandLine=replace(mvindex(mvfilter(match(pairs,"^CommandLine=")),0),"^CommandLine=","")
| table _time User Image ParentImage CommandLine
| sort -_time
```

## Query 2 - Most Executed Processes

Identify the processes generating the highest number of process creation events.

```spl id="b3j7x9"
index=main sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
| rex field=_raw "<EventID>(?<EventCode>\d+)</EventID>"
| search EventCode=1
| rex max_match=0 field=_raw "<Data Name='(?<fieldname>[^']+)'>(?<fieldvalue>[^<]*)</Data>"
| eval pairs=mvzip(fieldname,fieldvalue,"=")
| eval Image=replace(mvindex(mvfilter(match(pairs,"^Image=")),0),"^Image=","")
| stats count by Image
| sort -count
| head 10
```

## Query 3 - Parent Process Analysis

Review parent-child process relationships to identify unusual execution chains.

```spl id="k5w2n8"
index=main sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
| rex field=_raw "<EventID>(?<EventCode>\d+)</EventID>"
| search EventCode=1
| rex max_match=0 field=_raw "<Data Name='(?<fieldname>[^']+)'>(?<fieldvalue>[^<]*)</Data>"
| eval pairs=mvzip(fieldname,fieldvalue,"=")
| eval Image=replace(mvindex(mvfilter(match(pairs,"^Image=")),0),"^Image=","")
| eval ParentImage=replace(mvindex(mvfilter(match(pairs,"^ParentImage=")),0),"^ParentImage=","")
| stats count by ParentImage Image
| sort -count
```

## SOC Analyst Purpose

These searches help a SOC Analyst Tier 1:

- Monitor process creation.
- Identify frequently executed processes.
- Review parent-child process relationships.
- Investigate unusual process execution.
- Identify potentially suspicious activity.

## Investigation Considerations

A frequently executed process is not automatically malicious.

Analysts should review:

- Executable file path.
- User account.
- Parent process.
- Command-line arguments.
- Execution frequency and context.
- Whether the process behavior is expected.

## Limitations

- Detection depends on available Sysmon Event ID 1 telemetry.
- Parent-child relationships provide context but do not independently establish malicious activity.
- Additional investigation may be required to confirm suspicious behavior.

**Project:** Mini SOC Home Lab  
**SIEM:** Splunk Enterprise  
**Endpoint:** Windows 10


