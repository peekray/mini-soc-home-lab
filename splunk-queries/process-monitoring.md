
# Process Monitoring - Splunk SPL

## Objective
Monitor Windows process creation events using Sysmon and Splunk.

## Query 1 - Process Creation Events

```spl
index=* EventCode=1
| table _time host User Image ParentImage CommandLine
| sort -_time
```

## Query 2 - Most Executed Processes

```spl
index=* EventCode=1
| stats count by Image
| sort - count
| head 10
```

## Query 3 - Parent Process Analysis

```spl
index=* EventCode=1
| stats count by ParentImage Image
| sort - count
```

## SOC Analyst Purpose

These searches help a SOC Analyst Tier 1:

- Monitor process creation.
- Identify frequently executed processes.
- Review parent-child process relationships.
- Investigate unusual process execution.
- Identify potentially suspicious activity.

## Data Source

Sysmon Operational Event Log.

## Event ID

Event ID 1 - Process Creation.

**Project:** Mini SOC Home Lab  
**SIEM:** Splunk Enterprise  
**Endpoint:** Windows 10
