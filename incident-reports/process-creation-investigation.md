
# Process Creation Investigation

## 1. Investigation Overview

**Project:** Mini SOC Home Lab  
**Investigation ID:** MINI-SOC-2026-003  
**Date:** October 30, 2026  
**Host:** DESKTOP-M3GTP15  
**Tools:** Sysmon and Splunk Enterprise

## 2. Objective

Validate the collection and monitoring of Windows process creation and termination events using Sysmon and Splunk.

## 3. Test Activity

A controlled test was performed by launching Notepad through PowerShell:

```powershell
Start-Process notepad.exe
```

## 4. Events Observed

### Sysmon Event ID 1 – Process Creation

Splunk successfully captured the Notepad process creation event.

Observed information:
- Process: notepad.exe
- User: rayy\astru
- Parent process: powershell.exe
- Parent Process ID: 20364
- Process ID: 2968

A child process associated with the packaged Windows Notepad application was also observed.

### Sysmon Event ID 5 – Process Termination

Sysmon captured the termination of the original Notepad process.

Observed information:
- Process: Notepad.exe
- Process ID: 2968
- Event ID: 5

## 5. Splunk Investigation Query

```spl
index=main "notepad.exe"
| rex field=_raw "<EventID>(?<EventID>\d+)</EventID>"
| search EventID="1" OR EventID="5"
| table _time EventID host
| sort _time
```

## 6. Findings

- Sysmon successfully generated process creation telemetry.
- Splunk received and displayed the events.
- The PowerShell parent process was identified.
- Process termination activity was also recorded.
- The test demonstrated basic event correlation using process information.

## 7. Classification

**Result: Benign Test Activity**

The activity was intentionally generated for laboratory testing. No malicious behavior was identified in this controlled test.

## 8. Conclusion

This investigation validated the Mini SOC's ability to collect and review Windows process creation and termination events using Sysmon and Splunk.

These capabilities are important for SOC Tier 1 analysts when investigating suspicious process execution.
