# *Anomalous Increase in Unique Device Logon Count per User*

## Query Information

#### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1078 | Valid Accounts | https://attack.mitre.org/techniques/T1078 |
| T1021 | Remote Services | https://attack.mitre.org/techniques/T1021 |

#### Description

This rule detects potential account compromise or lateral movement by monitoring for significant spikes in the number of unique devices a single user account is logging into. It calculates a rolling baseline of daily device usage per account over the last 30 days and triggers an alert when an account's maximum daily unique device count exceeds its average by more than 5 times, with a minimum threshold of 10 unique devices, excluding known system accounts and infrastructure servers.


#### Author <Optional>
- **Name: Benjamin Zulliger**
- **Github: https://github.com/benscha/KQLAdvancedHunting**
- **LinkedIn: https://www.linkedin.com/in/benjamin-zulliger/**

#### Possible false positives
- A system administrator or a dedicated service account runs a scheduled script, a software deployment patch, or a vulnerability scan across the network.
- Helpdesk Escalation or On-Call Shift Support
- IT Administrative "Jump Boxes"

## Defender XDR
```KQL
// Definition of exclusions
let ExcludedRegex = @"^(dwm|umfd)-\d+$";
let StaticExclusions = dynamic(["-", "", "himds", "local service","iusr","defaultapppool"]);
let ExcludedServersRegex = @"^(srvA|srvB).*";
// Exclude your DCs
let ExcludedDCsRegex = @"^(dce|dca).*";
// Exclude your AzADConnectServers
let ExcludedAzADConnect = @"^AzAD[rn]{2}v13[0156].*";
//
DeviceLogonEvents
| where TimeGenerated > ago(30d)
// Filter out excluded accounts
| where AccountName !in (StaticExclusions)
| where not(AccountName matches regex ExcludedRegex)
// Filter out devices (separate lines act as strict AND logic)
| where not(DeviceName matches regex ExcludedServersRegex)
| where not(DeviceName matches regex ExcludedDCsRegex)
| where not(DeviceName matches regex ExcludedAzADConnect)
// Step 1: Track daily machine count and names per account
| summarize DailyCount = dcount(DeviceName), DailyDevices = make_set(DeviceName) by AccountName, bin(TimeGenerated, 1d)
// Step 2: Calculate baseline and aggregate all distinct Devices seen over the month
| summarize
	AvgDailyDevices = avg(DailyCount),
	MaxDailyDevices = max(DailyCount),
	DaysActive = dcount(bin(TimeGenerated, 1d)),
	DeviceList = make_set(DailyDevices)
	by AccountName
// Filter for critical deviations (Spikes)
| where MaxDailyDevices >= AvgDailyDevices * 2.5 and MaxDailyDevices > 10
| extend SpikeFactor = round(tolong(MaxDailyDevices) / AvgDailyDevices, 2)
| sort by SpikeFactor desc 
| where SpikeFactor >5
```
