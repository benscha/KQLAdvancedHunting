# *Azure AD Device Registration from New IP Address*

## Query Information

#### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1098.005 | Device Registration | https://attack.mitre.org/techniques/T1098/005/ |

#### Description

This rule detects new device registrations in Azure Active Directory (AAD) that originate from an IP address not previously associated with the user's account within the last 29 days. It filters out registrations from corporate IP ranges and common mobile operating systems (iOS, Android) to reduce noise. The rule categorizes the risk level of the IP address based on historical sign-in counts, focusing on 'High Risk - New IP' events. It then enriches these events with additional sign-in details like device name, risk level during sign-in, country, and city.

#### Author <Optional>
- **Name: Benjamin Zulliger**
- **Github: https://github.com/benscha/KQLAdvancedHunting**
- **LinkedIn: https://www.linkedin.com/in/benjamin-zulliger/**


## Defender XDR
```KQL
let ExcludedOS = datatable( OperatingSystem: string) ["iOS", "Android"];
let CorporateIPRange   = "xx.xx.";
// List of new Device Registrations
let DeviceRegistration = AuditLogs
| where TimeGenerated >ago(2h)
| where Category == "Device"
| where OperationName in ("Register device")
| extend Additional = todynamic(AdditionalDetails)
| mv-expand Additional
| extend DetailKey = tostring(Additional.key), 
         DetailValue = tostring(Additional.value)
| where DetailKey == "Device OS"
| project TimeGenerated,
          OperationName,
          InitiatedBy = tostring(InitiatedBy.user.displayName),
          AccountUpn = tostring(InitiatedBy.user.userPrincipalName),
          TargetDevice = tostring(TargetResources[0].displayName),
          DeviceId = tostring(TargetResources[0].id),
          Result = tostring(Result),
          IPAddress = tostring(InitiatedBy.user.ipAddress),
          OperatingSystem = DetailValue
| where OperatingSystem !in (ExcludedOS)
| where isnotempty( AccountUpn)
| sort by TimeGenerated desc
| where IPAddress !startswith (CorporateIPRange)
| summarize arg_max(TimeGenerated, *) by AccountUpn
| project TimeGenerated, AccountUpn, TargetDevice, IPAddress, OperatingSystem;
let HistoricalIPCounts = AADSignInEventsBeta
| where ErrorCode == 0
| where Timestamp >= ago(29d)
| summarize IPSeenCount = count() by AccountUpn, IPAddress;
// Build the IP list per account
let HistoricalIPs = AADSignInEventsBeta
| where ErrorCode == 0
| where Timestamp >= ago(29d)
| summarize HistoricalIPs = make_set(IPAddress) by AccountUpn;
// Join with RiskySignIns and Counts
DeviceRegistration
| join kind=leftouter HistoricalIPs on AccountUpn
| join kind=leftouter HistoricalIPCounts on AccountUpn, IPAddress
| extend 
    IPSeenBefore = iff(isnotempty(IPSeenCount), true, false),
    IPSeenCount = coalesce(IPSeenCount, 0)
| extend IPRiskLevel = case(
        IPSeenBefore == false, "High Risk - New IP",
        IPSeenBefore == true and IPSeenCount < 3, "Medium Risk - Rare IP",
        IPSeenBefore == true and IPSeenCount >= 3, "Lower Risk - Frequent IP",
        "Unknown"
    )
// Filter for only New IPs. here you can adapt the value
| where IPRiskLevel startswith "High"
| join kind=leftouter ( AADSignInEventsBeta
        | summarize arg_max(TimeGenerated, DeviceName, RiskLevelDuringSignIn, Country, City) by AccountUpn, IPAddress ) on AccountUpn, IPAddress
```
