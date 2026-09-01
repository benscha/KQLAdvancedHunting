# *Suspicious External Network Connection to Malicious ASN with Rare File Execution*

## Query Information

#### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1078 | Valid Accounts | https://attack.mitre.org/techniques/T1078 |
| T1021 | Remote Services | https://attack.mitre.org/techniques/T1021 |

#### Description

This rule identifies network connections to IP addresses belonging to known malicious Autonomous System Numbers (ASN). It filters for low-frequency connections from these malicious networks and then correlates them with the execution of files with low global prevalence (rarely seen in the environment) to detect potential malicious tool downloads or C2 communication.


#### Author <Optional>
- **Name: Benjamin Zulliger**
- **Github: https://github.com/benscha/KQLAdvancedHunting**
- **LinkedIn: https://www.linkedin.com/in/benjamin-zulliger/**


## Defender XDR
```KQL
// thx to my Buddy Sergio Albea for a big part of this Query
let CIDRASN = externaldata (CIDR:string, CIDRASN:int, CIDRASNName:string) 
    ['https://firewalliplists.gypthecat.com/lists/kusto/kusto-cidr-asn.csv.zip'] 
    with (ignoreFirstRecord=true);
let MaliciousASNSet = toscalar(
    externaldata (asn:string) ['https://www.spamhaus.org/drop/asndrop.json'] with (format="multijson")
    | extend asn_int = toint(asn)
    | summarize make_set(asn_int)
);
let SuspiciousIPs =
    DeviceNetworkEvents
    | where TimeGenerated between (ago(8d) .. ago(1d))
    | project RemoteIP
    | summarize ConnCount = count() by RemoteIP
    | where ConnCount < 25
    | evaluate ipv4_lookup(CIDRASN, RemoteIP, CIDR)
    | where CIDRASN in (MaliciousASNSet)
    | distinct RemoteIP;
DeviceNetworkEvents
| where TimeGenerated > ago(1d)
| where RemoteIP in (SuspiciousIPs)
| where ActionType in ("ConnectionSuccess", "InboundConnectionAccepted")
| where isnotempty(InitiatingProcessSHA256)
| invoke FileProfile(InitiatingProcessSHA256)
| where GlobalPrevalence < 2500 and GlobalFirstSeen > ago(14d)
```
