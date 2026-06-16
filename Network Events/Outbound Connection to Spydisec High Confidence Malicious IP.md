# *Outbound Connection to Spydisec High Confidence Malicious IP*

## Query Information

#### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1041| Exfiltration Over C2 Channel | https://attack.mitre.org/techniques/T1041 |


#### Description

This rule detects outbound network connections from devices to IP addresses identified as high confidence malicious by Spydisec. It specifically filters for outbound connections within the last two hours, indicating potential command and control activity or data exfiltration to known malicious infrastructure.

#### Author <Optional>
- **Name: Benjamin Zulliger**
- **Github: https://github.com/benscha/KQLAdvancedHunting**
- **LinkedIn: https://www.linkedin.com/in/benjamin-zulliger/**

#### References
- https://spydisec.com/


## Defender XDR
```KQL
let SpydisecHCIPs = externaldata(IP: string)["https://spydisec.com/high_confidence_limited.txt"]
| where IP !startswith "#";
DeviceNetworkEvents
| where TimeGenerated >ago(2h)
| join kind=inner (SpydisecHCIPs) on $left.RemoteIP == $right.IP
//if you only like to see outbound connections activate the following filter
| extend Direction = tostring(parse_json(AdditionalFields).direction)
| where Direction != "In"
```
