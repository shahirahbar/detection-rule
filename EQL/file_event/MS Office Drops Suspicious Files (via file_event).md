# EQL Search Query: MS Office Drops Suspicious Files

## Description
This query detects when Microsoft Office applications (Word, Excel, PowerPoint, etc.) write suspicious file types to disk. This activity is commonly associated with phishing attacks, exploitation of vulnerabilities, or post-exploitation actions where malware is dropped through Office products.

## MITRE ATT&CK Mapping
- **Tactics:** Initial Access (TA0001), Execution (TA0002)
- **Techniques:** Phishing (T1566), Exploitation for Client Execution (T1203)

## Copy-Paste Ready EQL Query
Copy the entire code block below and paste it directly into **Kibana Discover** (using the EQL query bar) or the **Elastic Dev Tools** console for manual execution.

```eql
any where (event.category : "file" and (process.executable : ("*WINWORD.EXE", "*EXCEL.EXE", "*POWERPNT.EXE", "*MSPUB.EXE", "*VISIO.EXE", "*OUTLOOK.EXE") and file.path : ("*.library-ms", "*.msc", "*.rtf", "*.mdb", "*.accdb", "*.accde", "*.mmp", "*.rdp", "*.chm", "*.dot", "*.jse", "*.bat", "*.sct", "*.url", "*.cmd", "*.hta", "*.htm", "*.ps1", "*.js", "*.vbs", "*.dll", "*.exe", "*.one", "*.onepkg", "*.bz2", "*.gzip", "*.au3")) and not (file.path : "*\\AC\\Temp\\*" and file.path : "*\\Local\\Packages\\*" or file.path : "*SmartLookupCache*" and file.path : "*microsoft.office.smartlookup.ssr.js*" or file.path : "*INetCache*" and file.path : "*].js*" or file.path : "*Content*" and file.path : "*IE*" and file.path : "*].js*" or file.path : ("*\\~$*", "*\\Setup[1].exe*", "*NewOutlookInstall*", "*\\Temp\\OICE_*", "*INetCache\\Content.MSO*", "*\\Javascript\\*", "*\\assembly\\tmp\\*", "*Temp\\hpcUK*", "*\\EPSON*")))
