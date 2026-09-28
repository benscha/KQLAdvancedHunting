# *Anomalous Kubernetes Service Account API Activity*

## Query Information

#### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1078.004 | Cloud Accounts | https://attack.mitre.org/techniques/T1078/004 |
| T1133 | External Remote Services | https://attack.mitre.org/techniques/T1133 |
| T1609 | Container Administration Command | https://attack.mitre.org/techniques/T1609 |

#### Description

This rule detects potentially unauthorized or anomalous activity from Kubernetes service accounts by baselining historical source IP and user agent patterns. It triggers when a service account performs actions from a new IP address or using a new user agent string, especially when those identifiers match known adversarial tooling or originate from non-private IP addresses.

#### Author <Optional>
- **Name: Benjamin Zulliger**
- **Github: https://github.com/benscha/KQLAdvancedHunting**
- **LinkedIn: https://www.linkedin.com/in/benjamin-zulliger/**


## Defender XDR
```KQL
let Lookback = 14d;
let DetectWindow = 1h;
let SAAudit = CloudAuditEvents
| where Timestamp > ago(Lookback)
| where DataSource =~ "Kubernetes Audit"
| extend User = tostring(RawEventData.user.username)
| where User startswith "system:serviceaccount:"
| extend SourceIp = tostring(RawEventData.sourceIPs[0]),
         UserAgent = tostring(RawEventData.userAgent),
         UAFamily = tolower(tostring(split(tostring(RawEventData.userAgent), "/")[0])),
         Verb = tolower(tostring(RawEventData.verb)),
         Resource = tolower(tostring(RawEventData.objectRef.resource)),
         Code = toint(RawEventData.responseStatus.code);
let Baseline = SAAudit
| where Timestamp < ago(DetectWindow)
| summarize KnownIps = make_set(SourceIp, 1000), KnownUA = make_set(UAFamily, 100) by User, AzureResourceId;
SAAudit
| where Timestamp >= ago(DetectWindow)
| join kind=inner Baseline on User, AzureResourceId
| extend NewIp = not(set_has_element(KnownIps, SourceIp)),
         NewUA = not(set_has_element(KnownUA, UAFamily)),
         PublicIp = not(ipv4_is_private(SourceIp)),
         HackerUA = UAFamily has_any ("kubectl", "curl", "python", "go-http-client", "wget", "postman")
| where NewIp
| summarize FirstSeen = min(Timestamp), LastSeen = max(Timestamp), Requests = count(),
            Actions = make_set(strcat(Verb, " ", Resource), 30),
            Forbidden = countif(Code == 403),
            UserAgents = make_set(UserAgent, 5),
            NewUA = max(toint(NewUA)), PublicIp = max(toint(PublicIp)), HackerUA = max(toint(HackerUA))
    by User, SourceIp, AzureResourceId
| extend Score = 2 + NewUA * 2 + PublicIp * 3 + HackerUA * 2 + iff(Forbidden > 0, 1, 0)
| where Score >= 4
| order by Score desc
```
