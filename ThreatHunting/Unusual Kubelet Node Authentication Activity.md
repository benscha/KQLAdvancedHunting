# *Unusual Kubelet Node Authentication Activity*

## Query Information

#### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1609 | Container Administration Command | https://attack.mitre.org/techniques/T1609 |
| T1613 | Container Ressource Discovery | https://attack.mitre.org/techniques/T1613 |


#### Description

This rule detects anomalous actions performed by accounts identifying as 'system:node', which corresponds to Kubelet service accounts. It monitors for unusual source IPs, non-standard User-Agents, and sensitive API verb interactions (such as 'list' secrets or 'exec' into pods) which deviate from established baselines for a given node.


#### Author <Optional>
- **Name: Benjamin Zulliger**
- **Github: https://github.com/benscha/KQLAdvancedHunting**
- **LinkedIn: https://www.linkedin.com/in/benjamin-zulliger/**


## Defender XDR
```KQL
let Lookback = 7d;
let DetectWindow = 1h;
let NodeAudit = CloudAuditEvents
| where Timestamp > ago(Lookback)
| where DataSource =~ "Kubernetes Audit"
| extend User = tostring(RawEventData.user.username)
| where User startswith "system:node:"
| extend SourceIp = tostring(RawEventData.sourceIPs[0]),
         UserAgent = tostring(RawEventData.userAgent),
         UAFamily = tolower(tostring(split(tostring(RawEventData.userAgent), "/")[0])),
         Verb = tolower(tostring(RawEventData.verb)),
         Resource = tolower(tostring(RawEventData.objectRef.resource)),
         SubResource = tolower(tostring(RawEventData.objectRef.subresource)),
         Namespace = tostring(RawEventData.objectRef.namespace),
         Code = toint(RawEventData.responseStatus.code);
let Baseline = NodeAudit
| where Timestamp < ago(DetectWindow)
| summarize KnownIps = make_set(SourceIp, 50), KnownUA = make_set(UAFamily, 20) by User, AzureResourceId;
NodeAudit
| where Timestamp >= ago(DetectWindow)
| join kind=leftouter Baseline on User, AzureResourceId
| extend HasBaseline = array_length(KnownIps) > 0
| extend NewIp = HasBaseline and not(set_has_element(KnownIps, SourceIp)),
         NewUA = (HasBaseline and not(set_has_element(KnownUA, UAFamily))) or UAFamily != "kubelet",
         SensitiveAttempt = (Resource == "secrets" and Verb in ("list", "watch"))
                         or (Resource == "pods" and SubResource in ("exec", "attach", "portforward"))
                         or (Resource in ("rolebindings", "clusterrolebindings", "serviceaccounts"))
| summarize FirstSeen = min(Timestamp), LastSeen = max(Timestamp), Requests = count(),
            NewIp = max(toint(NewIp)), NewUA = max(toint(NewUA)),
            SensitiveAttempts = countif(SensitiveAttempt), Forbidden = countif(Code == 403),
            DistinctNamespaces = dcount(Namespace),
            Actions = make_set(strcat(Verb, " ", Resource, iff(isnotempty(SubResource), strcat("/", SubResource), "")), 30),
            UserAgents = make_set(UserAgent, 5)
    by User, SourceIp, AzureResourceId
| extend Score = NewIp * 2 + NewUA * 3 + iff(SensitiveAttempts > 0, 2, 0) + iff(Forbidden >= 3, 2, 0)
| where Score >= 3
| order by Score desc
```
