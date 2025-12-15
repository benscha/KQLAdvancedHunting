# *Devices with unsucessfull AV Scan, Vulnerabilities (CVE) and related Incidents*

## Query Information

#### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1562 | Impair Defenses | https://attack.mitre.org/techniques/T1562/ |


#### Description
This KQL query finds devices with failed AV Scans, vulnerabilities and related incidents. I Recommend to run an automated AV Scan over Custom Detection Rules Action.

#### Author <Optional>
- **Name: Benjamin Zulliger**
- **Github: https://github.com/benscha/KQLAdvancedHunting**
- **LinkedIn: https://www.linkedin.com/in/benjamin-zulliger/**

#### References

## Defender XDR
```KQL
let AlertTimeframe = 30d;
let UnscannedDevices = DeviceEvents
| where TimeGenerated >ago(1d)
| where ActionType == "AntivirusScanCompleted"
| extend ParsedAdditionalFields = parse_json(AdditionalFields)
| extend ScanTypeIndex = tostring(ParsedAdditionalFields.ScanTypeIndex)
| project Timestamp,DeviceId, DeviceName, ScanTypeIndex
| summarize count() by DeviceName, ScanTypeIndex
| join kind=rightanti DeviceInfo on DeviceName
| where OnboardingStatus == "Onboarded"
| summarize arg_max(Timestamp, *) by DeviceName
| where OSPlatform != "iOS";
let AlertCount= AlertEvidence
| where TimeGenerated > ago(AlertTimeframe)
| summarize NumAlerts=count() by DeviceId
| join kind=inner UnscannedDevices on DeviceId;
DeviceTvmSoftwareVulnerabilities
| summarize NumCVE=count() by DeviceId
| join AlertCount on DeviceId
| join kind=inner UnscannedDevices on DeviceId
```
