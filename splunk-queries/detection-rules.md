# SOC Detection Rules

This document describes the detection rules developed and tested in my Mini SOC Home Lab using Sysmon and Splunk Enterprise.

## 1. Suspicious PowerShell Execution

**Sysmon Event ID:** 1 - Process Creation

**Objective:** Identify potentially suspicious PowerShell activity.

**Indicators monitored:**
- EncodedCommand parameters
- ExecutionPolicy Bypass
- Hidden PowerShell windows
- Suspicious command-line arguments

**SOC Analyst Action:**
Review the command line, parent process, user account, and execution context before determining whether the activity is malicious.

## 2. Process Creation Monitoring

**Sysmon Event ID:** 1 - Process Creation

**Objective:** Monitor newly created processes.

**SOC Analyst Action:**
Investigate unusual executables, unexpected parent-child relationships, and suspicious command-line activity.

## 3. Network Connection Monitoring

**Sysmon Event ID:** 3 - Network Connection

**Objective:** Monitor network connections initiated by processes.

**Indicators reviewed:**
- Destination IP addresses
- Destination ports
- Protocols
- Initiating processes

**SOC Analyst Action:**
Review unusual destinations and investigate process activity associated with suspicious connections.

## 4. Process Termination Monitoring

**Sysmon Event ID:** 5 - Process Terminated

**Objective:** Review process termination events.

**SOC Analyst Action:**
Correlate termination events with process creation and other relevant telemetry when investigating suspicious activity.

## 5. Detection and Triage Methodology

For each potentially suspicious event:

1. Identify the relevant Sysmon event.
2. Review the process name and command line.
3. Examine the parent process and user account.
4. Review related network activity when available.
5. Correlate events in Splunk.
6. Document findings and limitations.
7. Classify the activity as benign, suspicious, or requiring further investigation.

## Important Note

These detection rules identify potentially suspicious behavior. An alert does not automatically confirm malicious activity.

Additional investigation and context are required before classifying an event as a security incident.
