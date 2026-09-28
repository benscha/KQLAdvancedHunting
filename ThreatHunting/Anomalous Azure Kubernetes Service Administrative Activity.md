# *Anomalous Azure Kubernetes Service Administrative Activity*

## Query Information

#### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1613 | Container and Resource Discovery | https://attack.mitre.org/techniques/T1613 |
| T1078 | Valid Accounts | https://attack.mitre.org/techniques/T1078 |


#### Description

This rule detects anomalous administrative operations on Azure Kubernetes Service (AKS) managed clusters by baseline profiling of caller activity. It monitors for unusual service principal or user behavior, such as first-time usage of sensitive operations (e.g., listing credentials, running commands, or modifying role assignments), usage from new IP addresses, or new callers interacting with specific clusters. A scoring system aggregates these anomalies to identify potentially malicious administrative access.

#### Author <Optional>
- **Name: Benjamin Zulliger**
- **Github: https://github.com/benscha/KQLAdvancedHunting**
- **LinkedIn: https://www.linkedin.com/in/benjamin-zulliger/**


## Defender XDR
```KQL
let Lookback = 30d;
let DetectWindow = 1d;
let OpWeights = datatable(OpShort:string, Weight:int)[
    "LISTCLUSTERADMINCREDENTIAL/ACTION", 4,
    "RUNCOMMAND/ACTION", 4,
    "ACCESSPROFILES/LISTCREDENTIAL/ACTION", 4,
    "RESETAADPROFILE/ACTION", 3,
    "RESETSERVICEPRINCIPALPROFILE/ACTION", 3,
    "ROTATECLUSTERCERTIFICATES/ACTION", 3,
    "ROLEASSIGNMENTS/WRITE", 3,
    "WRITE", 2,
    "AGENTPOOLS/WRITE", 1,
    "LISTCLUSTERUSERCREDENTIAL/ACTION", 1
];
let AksOps = AzureActivity
| where TimeGenerated > ago(Lookback)
| extend ResId = tolower(_ResourceId), Op = toupper(OperationNameValue)
| where ResId has "microsoft.containerservice/managedclusters"
| where Op startswith "MICROSOFT.CONTAINERSERVICE/MANAGEDCLUSTERS/" or Op == "MICROSOFT.AUTHORIZATION/ROLEASSIGNMENTS/WRITE"
| where ActivityStatusValue in~ ("Success", "Succeeded")
| extend OpShort = case(Op == "MICROSOFT.AUTHORIZATION/ROLEASSIGNMENTS/WRITE", "ROLEASSIGNMENTS/WRITE",
                        replace_string(Op, "MICROSOFT.CONTAINERSERVICE/MANAGEDCLUSTERS/", ""))
| extend ClusterId = extract(@"(.*/managedclusters/[^/]+)", 1, ResId)
| join kind=inner OpWeights on OpShort;
let Baseline = AksOps
| where TimeGenerated < ago(DetectWindow)
| summarize KnownOps = make_set(OpShort, 50), KnownIps = make_set(CallerIpAddress, 200) by Caller, ClusterId;
AksOps
| where TimeGenerated >= ago(DetectWindow)
| join kind=leftouter Baseline on Caller, ClusterId
| extend NewCaller = array_length(KnownOps) == 0 or isnull(KnownOps),
         NewOpForCaller = not(set_has_element(KnownOps, OpShort)),
         NewIp = not(set_has_element(KnownIps, CallerIpAddress))
| summarize FirstSeen = min(TimeGenerated), LastSeen = max(TimeGenerated),
            Operations = make_set(OpShort, 20), MaxWeight = max(Weight),
            NewCaller = max(toint(NewCaller)), NewOp = max(toint(NewOpForCaller)), NewIp = max(toint(NewIp)),
            CallerIps = make_set(CallerIpAddress, 10)
    by Caller, ClusterId
| extend Score = MaxWeight + NewCaller * 3 + NewOp * 2 + NewIp
| where Score >= 6
| order by Score desc
```
