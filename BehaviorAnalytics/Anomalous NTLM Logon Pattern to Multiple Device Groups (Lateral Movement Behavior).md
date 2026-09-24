# *NTLM Network Logon Anomalies (Lateral Movement)*

## Query Information

#### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1021 | Remote Services | https://attack.mitre.org/techniques/T1021/ |
| T1078 | Valid Accounts | https://attack.mitre.org/techniques/T1078/ |
| T1550.002 | Pass the Hash | https://attack.mitre.org/techniques/T1550/002/ |

#### Description

Detects user accounts performing successful NTLM logons across multiple distinct device groups (based on a common prefix) where those device groups have not been accessed by the account in the preceding 30 days. This behavior is indicative of potential lateral movement or account compromise.
#### Author <Optional>
- **Name: Benjamin Zulliger**
- **Github: https://github.com/benscha/KQLAdvancedHunting**
- **LinkedIn: https://www.linkedin.com/in/benjamin-zulliger/**


## Defender XDR
```KQL
let Lookback = 30d;
let RecentWindow = 1h;
let whitelistedAccounts = dynamic(["account0@domain.com", "account1@domain.com"]);
let RecentLogons =
    IdentityLogonEvents
    | where Timestamp > ago(RecentWindow)
    | where not(AccountUpn has_any (whitelistedAccounts))
    | where Protocol =~ "NTLM"
    | where ActionType != "LogonFailed"
    | extend AccountUpn = tolower(AccountUpn), DeviceName = tolower(DeviceName)
    | extend DeviceGroup = extract(@"^([a-z]+)\d*", 1, DeviceName)
    | summarize DistinctDeviceGroups = dcount(DeviceGroup),
                DeviceGroups = make_set(DeviceGroup),
                Devices = make_set(DeviceName),
                LogonCount = count()
            by AccountUpn;
let HistoricalDeviceGroupsPerAccount =
    IdentityLogonEvents
    | where Timestamp between (ago(Lookback + RecentWindow) .. ago(RecentWindow))
    | where Protocol =~ "NTLM"
    | where ActionType != "LogonFailed"
    | extend AccountUpn = tolower(AccountUpn), DeviceName = tolower(DeviceName)
    | extend DeviceGroup = extract(@"^([a-z]+)\d*", 1, DeviceName)
    | summarize HistoricalDeviceGroups = make_set(DeviceGroup) by AccountUpn;
RecentLogons
| join kind=leftouter HistoricalDeviceGroupsPerAccount on AccountUpn
| extend NewDeviceGroups = set_difference(DeviceGroups, HistoricalDeviceGroups)
| extend NewDeviceGroupCount = array_length(NewDeviceGroups)
| where DistinctDeviceGroups > 1 and NewDeviceGroupCount > 0
| project AccountUpn, DistinctDeviceGroups, LogonCount, NewDeviceGroupCount, NewDeviceGroups, DeviceGroups, Devices
| sort by NewDeviceGroupCount desc
| where isnotempty( AccountUpn)
| where DistinctDeviceGroups >2
```
