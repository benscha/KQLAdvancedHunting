# *Discovered Network Devices CVE / CVSS*

## Query Information

#### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |


#### Description
This KQL query identifies known software vulnerabilities (CVEs) affecting network infrastructure devices (such as routers, switches, and firewalls) within the environment.
 
#### Author <Optional>
- **Name: Benjamin Zulliger**
- **Github: https://github.com/benscha/KQLAdvancedHunting**
- **LinkedIn: https://www.linkedin.com/in/benjamin-zulliger/**

#### References

## Defender XDR
```KQL
DeviceInfo
| where DeviceType has_any ("NetworkDevice", "Router", "Switch", "Firewall")
| join DeviceTvmSoftwareVulnerabilities on DeviceId
| where isnotempty( CveId)
| project TimeGenerated, DeviceName, OSVersion, Model, OSDistribution, OSVersionInfo, ExposureLevel, CveId, VulnerabilitySeverityLevel
| join kind=leftouter DeviceTvmSoftwareVulnerabilitiesKB on CveId 
```
