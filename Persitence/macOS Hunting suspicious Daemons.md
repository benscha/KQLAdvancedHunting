# *Hunting suspicious Daemons on macOS*

## Query Information

#### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1543.004 | Launch Daemon | https://attack.mitre.org/techniques/T1543/004 |


#### Description
This rule detects suspicious Launch Daemons on macOS by looking for files created or modified in the `/Library/LaunchDaemons/` directory. It filters out known legitimate binaries and then flags any remaining files that have low global prevalence (less than 2500 instances) and were first seen more than 90 days ago. Additionally, it checks if the certificate is invalid or not signed by Microsoft, indicating potential malicious activity. This rule is intended for hunting and not for direct alerting due to the need for whitelisting.

#### Author <Optional>
- **Name: Benjamin Zulliger**
- **Github: https://github.com/benscha/KQLAdvancedHunting**
- **LinkedIn: https://www.linkedin.com/in/benjamin-zulliger/**

#### References
- Inspired by Threat Hunting macOS: Mastering Endpoint Security (https://www.amazon.com/Threat-Hunting-macOS-Mastering-Endpoint/dp/B0G62RG1BW)


## Defender XDR
```KQL
// Whitelisting
let WhitelistedBinaries = dynamic(["com.jamf.", "com.microsoft.", "com.docker.", "com.monotype.", "com.wibu."]);
let WhitelistedInitiatingBinary = dynamic (["jamf"]);
DeviceEvents
| where FolderPath endswith "/Library/LaunchDaemons/" 
| where not(FileName has_any (WhitelistedBinaries))
| where InitiatingProcessFileName !in (WhitelistedInitiatingBinary)
| invoke FileProfile(SHA1)
| where GlobalPrevalence < 2500
| where GlobalFirstSeen < ago(90d)
| where IsCertificateValid != true or IsRootSignerMicrosoft != true
```
