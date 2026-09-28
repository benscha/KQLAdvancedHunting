# *Kubernetes Suspicious Probing and Subsequent Escalation Activity*

## Query Information

#### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1613 | Container and Resource Discovery | https://attack.mitre.org/techniques/T1613 |
| T1078 | Valid Accounts | https://attack.mitre.org/techniques/T1078 |


#### Description

This rule detects a multi-stage attack pattern in Kubernetes environments where an entity first performs suspicious probing activities (e.g., numerous self-subject rules/access reviews or repeated 403 Forbidden errors) followed by privileged or sensitive API actions within a short timeframe. The logic correlates reconnaissance attempts against the API server with subsequent successful escalation-related operations such as accessing secrets, pod execution, or role/clusterrole modifications.

#### Author <Optional>
- **Name: Benjamin Zulliger**
- **Github: https://github.com/benscha/KQLAdvancedHunting**
- **LinkedIn: https://www.linkedin.com/in/benjamin-zulliger/**


## Defender XDR
```KQLlet Lookback = 1d;
let ProbeBin = 30m;
let FollowUp = 1h;
let Audit = CloudAuditEvents
| where Timestamp > ago(Lookback)
| where DataSource =~ "Kubernetes Audit"
| extend User = tostring(RawEventData.user.username),
         Verb = tolower(tostring(RawEventData.verb)),
         Resource = tolower(tostring(RawEventData.objectRef.resource)),
         SubResource = tolower(tostring(RawEventData.objectRef.subresource)),
         Namespace = tostring(RawEventData.objectRef.namespace),
         Code = toint(RawEventData.responseStatus.code),
         SourceIp = tostring(RawEventData.sourceIPs[0])
| extend Action = strcat(Verb, " ", Resource, iff(isnotempty(SubResource), strcat("/", SubResource), ""))
| where not(User startswith "system:") or User startswith "system:serviceaccount:"
| where not(User startswith "system:serviceaccount:kube-system:");
let Probing = Audit
| extend IsSelfReview = Resource in ("selfsubjectrulesreviews", "selfsubjectaccessreviews")
| where IsSelfReview or Code == 403
| summarize SelfReviews = countif(IsSelfReview),
            Forbidden = countif(Code == 403),
            DeniedActions = make_set_if(Action, Code == 403, 50),
            ProbeStart = min(Timestamp), ProbeEnd = max(Timestamp)
    by User, AzureResourceId, SourceIp, bin(Timestamp, ProbeBin)
| where (SelfReviews > 0 and Forbidden > 0) or array_length(DeniedActions) >= 5;
let Escalation = Audit
| where Code between (200 .. 299)
| extend ImpersonatedUser = tostring(RawEventData.impersonatedUser.username)
| where (Resource == "secrets" and Verb in ("get", "list", "watch"))
     or (Resource == "pods" and SubResource in ("exec", "attach"))
     or (Resource == "pods" and Verb == "create" and isempty(SubResource))
     or (Resource in ("rolebindings", "clusterrolebindings", "roles", "clusterroles") and Verb in ("create", "update", "patch"))
     or (Resource == "serviceaccounts" and SubResource == "token")
     or (Resource == "nodes" and SubResource == "proxy")
     or isnotempty(ImpersonatedUser)
| project EscAt = Timestamp, User, AzureResourceId, Action, Namespace, ImpersonatedUser;
Probing
| join kind=inner Escalation on User, AzureResourceId
| where EscAt between (ProbeStart .. (ProbeEnd + FollowUp))
| summarize FirstProbe = min(ProbeStart), FirstEscalation = min(EscAt),
            SelfReviews = max(SelfReviews), Forbidden = max(Forbidden),
            DeniedActions = take_any(DeniedActions),
            SuccessfulActions = make_set(Action, 30),
            Namespaces = make_set(Namespace, 20),
            ImpersonatedUsers = make_set_if(ImpersonatedUser, isnotempty(ImpersonatedUser))
    by User, AzureResourceId, SourceIp
```
