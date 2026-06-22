# *Unusual LDAP Query Burst from New or Known Device*

## Query Information

#### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1087.002 | Domain Account | https://attack.mitre.org/techniques/T1087/002/ |
| T1069.002 | Domain Groups | https://attack.mitre.org/techniques/T1069/002/ |

#### Description

This rule detects an unusual burst of LDAP queries originating from a device. It identifies both new devices with a high absolute burst count and known devices exhibiting a significant deviation (2 standard deviations above average) from their established baseline of LDAP query activity. The detection focuses on LDAP queries to Active Directory with a BaseObject starting with 'DC=' and excludes known scheduled sources and IP addresses.

#### Author <Optional>
- **Name: Benjamin Zulliger**
- **Github: https://github.com/benscha/KQLAdvancedHunting**
- **LinkedIn: https://www.linkedin.com/in/benjamin-zulliger/**


## Defender XDR
```KQL
let LookbackWindow = 24h;
let BurstWindow = 10min;
let KnownScheduledSources = dynamic([
    "DEVICE001",
    "DEVICE002"
]);
let BurstBase =
    IdentityQueryEvents
    | where TimeGenerated >= ago(LookbackWindow)
    | where ActionType == "LDAP query"
    | where Application == "Active Directory"
    | extend AF = parse_json(AdditionalFields)
    | extend
        BaseObject = tostring(AF.BaseObject),
        SearchFilter = tostring(AF.SearchFilter),
        FromDevice = tostring(AF["FROM.DEVICE"]),
        SourceOS = tostring(AF.SourceComputerOperatingSystem)
    | where BaseObject matches regex @"^DC="
    | where isnull(parse_ipv4(FromDevice))
    | where FromDevice !in~ (KnownScheduledSources)
    | summarize
        BurstCount = count(),
        TargetDCCount = dcount(DestinationDeviceName),
        TargetDCs = make_set(DestinationDeviceName, 5),
        BaseObjects = make_set(BaseObject, 5),
        SearchFilters = make_set(SearchFilter, 5),
        FirstSeen = min(TimeGenerated),
        LastSeen = max(TimeGenerated)
        by FromDevice, IPAddress, SourceOS, bin(TimeGenerated, BurstWindow);
// Flat-pattern autodetect across the entire lookback window
let FlatPatternDevices =
    BurstBase
    | summarize
        UniqueCounts = dcount(BurstCount),
        BinCount = count()
        by FromDevice
    | where BinCount >= 3 and UniqueCounts == 1
    | project FromDevice;
// Baseline per device: typical BurstCount of the last 7 days
let Baseline =
    IdentityQueryEvents
    | where TimeGenerated between (ago(7d) .. ago(LookbackWindow))
    | where ActionType == "LDAP query"
    | where Application == "Active Directory"
    | extend AF = parse_json(AdditionalFields)
    | extend
        BaseObject = tostring(AF.BaseObject),
        FromDevice = tostring(AF["FROM.DEVICE"])
    | where BaseObject matches regex @"^DC="
    | where isnull(parse_ipv4(FromDevice))
    | summarize
        BinCount = count()
        by FromDevice, bin(TimeGenerated, BurstWindow)
    | summarize
        AvgBurst = avg(BinCount),
        StdBurst = stdev(BinCount)
        by FromDevice;
BurstBase
| where FromDevice !in (FlatPatternDevices)
// Baseline join: only significant deviation from normal behavior
| join kind=leftouter Baseline on FromDevice
| extend
    Threshold = AvgBurst + (2 * StdBurst),   // 2-sigma above baseline
    IsNewDevice = isnull(AvgBurst)             // No baseline = unknown device
| where
    // New device without baseline AND high absolute burst
    (IsNewDevice and BurstCount >= 50 and TargetDCCount >= 2)
    or
    // Known device that lies significantly above its own baseline
    (not(IsNewDevice) and BurstCount > Threshold and TargetDCCount >= 2)
| extend Severity = case(
    TargetDCCount >= 3 and BurstCount >= 200, "High",
    TargetDCCount >= 2 and BurstCount >= 50,  "Medium",
    "Low"
)
| project
    bin_TimeGenerated = bin(TimeGenerated, BurstWindow),
    FromDevice,
    IPAddress,
    SourceOS,
    BurstCount,
    TargetDCCount,
    TargetDCs,
    BaseObjects,
    SearchFilters,
    AvgBurst = round(AvgBurst, 1),
    Threshold = round(Threshold, 1),
    IsNewDevice,
    Severity
| order by BurstCount desc
```
