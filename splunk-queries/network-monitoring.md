
# Network Monitoring - Splunk SPL

## Objective
Monitor network connections from Windows endpoints using Sysmon and Splunk.

## Query 1 - Network Connections

```spl
index=* EventCode=3
| table _time host Image SourceIp SourcePort DestinationIp DestinationPort Protocol
| sort -_time
```

## Query 2 - Top Destination IP Addresses

```spl
index=* EventCode=3
| stats count by DestinationIp
| sort - count
| head 10
```

## Query 3 - Network Activity by Process

```spl
index=* EventCode=3
| stats count by Image DestinationIp
| sort - count
```

## SOC Analyst Purpose

These searches help identify:

- Network connections initiated by processes.
- Frequently contacted destination IP addresses.
- Unusual network communication.
- Potentially suspicious process activity.
- Connections requiring further investigation.

## Data Source

Sysmon Operational Event Log.

## Event ID

Event ID 3 - Network Connection.

**Project:** Mini SOC Home Lab  
**SIEM:** Splunk Enterprise  
**Endpoint:** Windows 10
