# *Identify Windows Devices Missing Defender for Endpoint WSL Plugin*

## Query Information

#### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |


#### Description
This rule identifies Windows devices that are onboarded to Microsoft Defender for Endpoint but do not have the Defender for Endpoint plugin for Windows Subsystem for Linux (WSL) installed. This helps in ensuring comprehensive security coverage for WSL environments.
Check out the Installation Instructions on Microsoft Defender for Endpoint plug-in for Windows Subsystem for Linux (WSL) https://learn.microsoft.com/en-us/defender-endpoint/mde-plugin-wsl


#### Author <Optional>
- **Name: Benjamin Zulliger**
- **Github: https://github.com/benscha/KQLAdvancedHunting**
- **LinkedIn: https://www.linkedin.com/in/benjamin-zulliger/**

#### References
- https://learn.microsoft.com/en-us/defender-endpoint/mde-plugin-wsl

## Defender XDR
```KQL
let ActiveWindowsDevices = 
    DeviceInfo
    | where Timestamp > ago(30d)
    | where OSPlatform startswith "Windows"
    | summarize arg_max(Timestamp, *) by DeviceId
    | where isnotempty(DeviceName)
    | where OnboardingStatus == "Onboarded"
    | project DeviceId, DeviceName, OSPlatform, OSVersion;
// Identify all devices that have the WSL plugin installed
let DevicesWithWslPlugin = 
    DeviceTvmSoftwareInventory
    | where SoftwareName has "Defender for Endpoint plug-in for WSL" or SoftwareName has "DefenderPluginForWSL"
    | summarize by DeviceId;
// Combine the tables and display "yes" or "no"
ActiveWindowsDevices
| extend WslPluginInstalled = iif(DeviceId in (DevicesWithWslPlugin), "yes", "no")
| sort by DeviceName asc
// Optional Filter for Devices with missing WSL Plugin
//| where WslPluginInstalled == "no"
// Microsoft Defender for Endpoint plug-in for Windows Subsystem for Linux (WSL) https://learn.microsoft.com/en-us/defender-endpoint/mde-plugin-wsl
```
