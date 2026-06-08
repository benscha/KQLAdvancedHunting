# *Suspicious Windows Registry Policy Modifications for Evasion and Persistence*

## Query Information

#### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1562.001 | Disable or Modify Tools | https://attack.mitre.org/techniques/T1562/001/ |
| T1562.006 | Indicator Blocking | https://attack.mitre.org/techniques/T1562/006/ |


#### Description
This hunting query monitors the DeviceRegistryEvents table to detect unauthorized or suspicious modifications within the Windows Group Policy registry hives (HKLM\SOFTWARE\Policies\Microsoft\Windows\). Attackers frequently abuse these policy keys to disable security controls, disrupt telemetry, or establish persistence.

#### Risk
Defense Evasion

#### Author <Optional>
- **Name: Benjamin Zulliger**
- **Github: https://github.com/benscha/KQLAdvancedHunting**
- **LinkedIn: https://www.linkedin.com/in/benjamin-zulliger/**

#### References
- 

## Defender XDR
```KQL
// Focus on suspicious policy modifications under HKLM\SOFTWARE\Policies\Microsoft\Windows\
DeviceRegistryEvents
| where RegistryKey startswith @"HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows"
| extend LowerKey = tolower(RegistryKey),
         LowerValueName = tolower(RegistryValueName), 
         LowerValueData = tolower(RegistryValueData)
| extend AttackVector = case(
    // 1. Defender / MDE Telemetry Disruption & Offboarding
    LowerKey has "advanced threat protection" and LowerValueName == "latency" and LowerValueData == "demo", "MDE Rogue Onboarding/Offboarding Attempt",
    LowerKey has "datacollection" and LowerValueName == "allowtelemetry" and LowerValueData == "0", "Disabling Windows Diagnostic Telemetry (DiagTrack)",
    LowerKey has "windows defender" and LowerKey has "policy manager" and LowerValueName == "asrrules" and LowerValueData has "=0", "Disabling Defender Attack Surface Reduction Rules",
    // 2. BITS Abuse for Inactivity Timeouts (Persistence)
    LowerKey has "windows" and LowerKey has "bits" and (LowerValueName == "jobinactivitytimeout" or LowerValueName == "maxdownloadtime"), "Suspicious BITS Timeout Modification for Persistence",
    // 3. Windows Update Hijacking (Evasion)
    LowerKey has "windows" and LowerKey has "windowsupdate" and (LowerValueName == "wuserver" or LowerValueName == "wustatusserver"), "Hijacking Windows Update Server Location",
    LowerKey has "windows" and LowerKey has "windowsupdate" and LowerKey has "au" and LowerValueName == "auoptions" and LowerValueData == "1", "Disabling Automatic Windows Updates", 
    "Unknown / Check Context"
)
| where AttackVector != "Unknown / Check Context"

```
