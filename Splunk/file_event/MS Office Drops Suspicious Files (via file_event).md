# Splunk SPL Search Query: MS Office Drops Suspicious Files

## Description
This Splunk query detects when Microsoft Office applications write suspicious file types to disk, which is a common indicator of phishing campaigns, exploitation of vulnerabilities, or malware deployment through Office products.

## MITRE ATT&CK Mapping
- **Tactics:** Initial Access (TA0001), Execution (TA0002)
- **Techniques:** Phishing (T1566), Exploitation for Client Execution (T1203)

## Copy-Paste Ready SPL Query
Copy the entire search below and paste it directly into the Splunk Search bar.

```spl
index=* source="WinEventLog:*" 
(((Image="*WINWORD.EXE" OR Image="*EXCEL.EXE" OR Image="*POWERPNT.EXE" OR Image="*MSPUB.EXE" OR Image="*VISIO.EXE" OR Image="*OUTLOOK.EXE") 
AND 
(TargetFilename="*.library-ms" OR TargetFilename="*.msc" OR TargetFilename="*.rtf" OR TargetFilename="*.mdb" OR TargetFilename="*.accdb" OR TargetFilename="*.accde" OR TargetFilename="*.mmp" OR TargetFilename="*.rdp" OR TargetFilename="*.chm" OR TargetFilename="*.dot" OR TargetFilename="*.jse" OR TargetFilename="*.bat" OR TargetFilename="*.sct" OR TargetFilename="*.url" OR TargetFilename="*.cmd" OR TargetFilename="*.hta" OR TargetFilename="*.htm" OR TargetFilename="*.ps1" OR TargetFilename="*.js" OR TargetFilename="*.vbs" OR TargetFilename="*.dll" OR TargetFilename="*.exe" OR TargetFilename="*.one" OR TargetFilename="*.onepkg" OR TargetFilename="*.bz2" OR TargetFilename="*.gzip" OR TargetFilename="*.au3")) 
AND 
NOT (
    (TargetFilename="*\\AC\\Temp\\*" AND TargetFilename="*\\Local\\Packages\\*") 
    OR (TargetFilename="*SmartLookupCache*" AND TargetFilename="*microsoft.office.smartlookup.ssr.js*") 
    OR (TargetFilename="*INetCache*" AND TargetFilename="*].js*") 
    OR (TargetFilename="*Content*" AND TargetFilename="*IE*" AND TargetFilename="*].js*") 
    OR TargetFilename="*\\~$*" 
    OR TargetFilename="*\\Setup[1].exe*" 
    OR TargetFilename="*NewOutlookInstall*" 
    OR TargetFilename="*\\Temp\\OICE_*" 
    OR TargetFilename="*INetCache\\Content.MSO*" 
    OR TargetFilename="*\\Javascript\\*" 
    OR TargetFilename="*\\assembly\\tmp\\*" 
    OR TargetFilename="*Temp\\hpcUK*" 
    OR TargetFilename="*\\EPSON*"
)))
| table _time, host, user, Image, TargetFilename
| rename Image as Process, TargetFilename as "File Path"
