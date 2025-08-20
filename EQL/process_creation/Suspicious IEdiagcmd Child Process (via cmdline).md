# EQL Search Query: Suspicious iediagcmd.exe Child Process

## Description
This query detects the execution of suspicious child processes spawned by `iediagcmd.exe`, which is a legitimate Microsoft Internet Explorer diagnostic tool. This activity is often abused by malware and threat actors for credential dumping, network discovery, and system information gathering as part of post-exploitation.

## MITRE ATT&CK Mapping
- **Tactics:** Discovery (TA0007), Collection (TA0009)
- **Techniques:** 
  - System Network Configuration Discovery (T1016)
  - System Network Connections Discovery (T1049)
  - System Information Discovery (T1082)
  - Archive Collected Data (T1560)

## Copy-Paste Ready EQL Query
Copy the entire code block below and paste it directly into **Kibana Discover** (using the EQL query bar) or the **Elastic Dev Tools** console for manual execution.

```eql
process where (event.category : "process" and (process.parent.executable : "*iediagcmd.exe" and process.executable : ("*route.exe", "*netsh.exe", "*ipconfig.exe", "*dxdiag.exe", "*conhost.exe", "*makecab.exe")) and not process.executable : ("*system32*", "*syswow64*"))
