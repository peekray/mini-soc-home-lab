
# Network Monitoring - Splunk SPL

## Objective

Monitor Windows endpoint network connections using Sysmon Event ID 3 and Splunk Enterprise.

These searches help a SOC Analyst Tier 1 review network activity, identify frequently contacted destinations, and investigate potentially unusual connections.

## Data Source

- SIEM: Splunk Enterprise
- Endpoint: Windows 10 Home 64-bit
- Log Source: Sysmon Operational
- Event ID: 3 - Network Connection
- Index: main

**Note:** Sysmon events are ingested as XML. The following queries extract the required fields from the raw event data using `rex`.

## Query 1 - Network Connections

Display detailed network connection events.

```spl
index=main sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
| rex field=_raw "<EventID>(?<EventCode>\d+)</EventID>"
| search EventCode=3
| rex max_match=0 field=_raw "<Data Name='(?<fieldname>[^']+)'>(?<fieldvalue>[^<]*)</Data>"
| eval pairs=mvzip(fieldname,fieldvalue,"=")
| eval Image=replace(mvindex(mvfilter(match(pairs,"^Image=")),0),"^Image=","")
| eval SourceIp=replace(mvindex(mvfilter(match(pairs,"^SourceIp=")),0),"^SourceIp=","")
| eval DestinationIp=replace(mvindex(mvfilter(match(pairs,"^DestinationIp=")),0),"^DestinationIp=","")
| eval DestinationPort=replace(mvindex(mvfilter(match(pairs,"^DestinationPort=")),0),"^DestinationPort=","")
| eval Protocol=replace(mvindex(mvfilter(match(pairs,"^Protocol=")),0),"^Protocol=","")
| table _time Image SourceIp DestinationIp DestinationPort Protocol
| sort -_time
```

## Query 2 - Top Destination IP Addresses

Identify the most frequently contacted destination IP addresses.

```spl
index=main sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
| rex field=_raw "<EventID>(?<EventCode>\d+)</EventID>"
| search EventCode=3
| rex max_match=0 field=_raw "<Data Name='(?<fieldname>[^']+)'>(?<fieldvalue>[^<]*)</Data>"
| eval pairs=mvzip(fieldname,fieldvalue,"=")
| eval DestinationIp=replace(mvindex(mvfilter(match(pairs,"^DestinationIp=")),0),"^DestinationIp=","")
| stats count by DestinationIp
| sort -count
| head 10
```

## Query 3 - Network Activity by Process

Identify which processes generate the most network connections and their destination IP addresses.

```spl
index=main sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
| rex field=_raw "<EventID>(?<EventCode>\d+)</EventID>"
| search EventCode=3
| rex max_match=0 field=_raw "<Data Name='(?<fieldname>[^']+)'>(?<fieldvalue>[^<]*)</Data>"
| eval pairs=mvzip(fieldname,fieldvalue,"=")
| eval Image=replace(mvindex(mvfilter(match(pairs,"^Image=")),0),"^Image=","")
| eval DestinationIp=replace(mvindex(mvfilter(match(pairs,"^DestinationIp=")),0),"^DestinationIp=","")
| stats count by Image DestinationIp
| sort -count
```

## SOC Analyst Purpose

These searches help identify:

- Network connections initiated by endpoint processes.
- Frequently contacted destination IP addresses.
- Processes generating network traffic.
- Unusual network communication patterns.
- Connections that may require further investigation.

## Investigation Considerations

A high connection count does not automatically indicate malicious activity.

A SOC Analyst should consider:

- Whether the process is expected.
- Whether the destination IP is legitimate.
- Which destination port and protocol are being used.
- Whether the activity is consistent with normal endpoint behavior.
- Whether additional evidence supports a security incident.

## Limitations

- Event ID 3 records network connections, but does not independently establish malicious activity.
- Destination IP addresses may belong to legitimate services.
- Additional telemetry and investigation may be required to determine whether an event is suspicious.

**Project:** Mini SOC Home Lab  
**SIEM:** Splunk Enterprise  
**Endpoint:** Windows 10

