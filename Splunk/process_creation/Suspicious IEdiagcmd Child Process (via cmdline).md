# Splunk SPL Search: Suspicious iediagcmd.exe Child Process

## Description
This Splunk query detects the execution of suspicious child processes spawned by `iediagcmd.exe` (Microsoft Internet Explorer diagnostic tool) through Windows Security Event Logs (Event ID 4688). This activity is commonly associated with malware leveraging living-off-the-land binaries (LOLBins) for reconnaissance, credential dumping, and data collection.

## MITRE ATT&CK Mapping
- **Tactics:** Discovery (TA0007), Collection (TA0009)
- **Techniques:** 
  - System Network Configuration Discovery (T1016)
  - System Network Connections Discovery (T1049)
  - System Information Discovery (T1082)
  - Archive Collected Data (T1560)

## Copy-Paste Ready SPL Query
Copy the entire search below and paste it directly into the Splunk Search bar.

```spl
index=* source="WinEventLog:Security" EventCode=4688 
((ParentProcessName="*iediagcmd.exe" 
(NewProcessName="*route.exe" OR NewProcessName="*netsh.exe" OR NewProcessName="*ipconfig.exe" OR NewProcessName="*dxdiag.exe" OR NewProcessName="*conhost.exe" OR NewProcessName="*makecab.exe")) 
NOT (NewProcessName="*system32*" OR NewProcessName="*syswow64*"))
| table _time, host, user, ParentProcessName, NewProcessName, CommandLine
| rename ParentProcessName AS "Parent Process", NewProcessName AS "New Process", CommandLine AS "Command Line"
