# *Suspicious Access to Credential Stores*

## Query Information

#### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1003| OS Credential Dumping | https://attack.mitre.org/techniques/T1003 |


#### Description
Detects suspicious process access to common credential storage locations such as certificate stores, PCPKSP keys, and CloudAPCache for AzureAD credentials. The severity of the alert is escalated based on the initiating process and command line arguments, specifically looking for keywords like 'mimikatz', 'dump', or 'export'.

#### Author <Optional>
- **Name: Benjamin Zulliger**
- **Github: https://github.com/benscha/KQLAdvancedHunting**
- **LinkedIn: https://www.linkedin.com/in/benjamin-zulliger/**

#### References
- Inspired by Nestori Syynimaa Trusted by Design: How Windows Uses TPM to Secure PRTs https://yellowhat.live/session-catalog/ 


## Defender XDR
```KQL
DeviceEvents
| where InitiatingProcessFileName != "lsass.exe"
| where (
    FolderPath startswith @"Cert:\LocalMachine\My\" 
    or (FolderPath startswith @"C:\ProgramData\Microsoft\Crypto\PCPKSP\" and FileName endswith "PCBKEY")
    or (FolderPath startswith @"C:\Windows\System32\config\systemprofile\AppData\Local\Microsoft\Crypto\PCPKSP\" and FileName endswith "PCBKEY")
    or FolderPath has_any (@"CloudAPCache\AzureAD", @"cloudapcache\azuread") 
)
| extend 
    SuspiciousAccess = case(
        ProcessCommandLine has_any ("mimikatz", "dump", "export"), "High",
        InitiatingProcessFileName in~ ("powershell.exe", "cmd.exe", "wmic.exe"), "Medium",
        "Low"
    )
```
