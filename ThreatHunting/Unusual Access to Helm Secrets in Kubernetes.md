# Unusual Access to Helm Secrets in Kubernetes*

## Query Information

#### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1552.001 | Credentials in Files | https://attack.mitre.org/techniques/T1552/001 |
| T1555 | Credentials from Password Stores | https://attack.mitre.org/techniques/T1552 |


#### Description

Detects instances where an identity (user or service account) accesses Kubernetes secrets associated with Helm releases (prefixed with sh.helm.release.v1.) without a historical baseline for such activity. The rule flags potential unauthorized credential access in a containerized environment, with heightened severity for non-standard user agents or cross-namespace activity.

#### Author <Optional>
- **Name: Benjamin Zulliger**
- **Github: https://github.com/benscha/KQLAdvancedHunting**
- **LinkedIn: https://www.linkedin.com/in/benjamin-zulliger/**


## Defender XDR
```KQL
let Lookback = 30d;
let DetectWindow = 1d;
let HelmSecrets = CloudAuditEvents
| where Timestamp > ago(Lookback)
| where DataSource =~ "Kubernetes Audit"
| extend Resource = tolower(tostring(RawEventData.objectRef.resource)),
         Verb = tolower(tostring(RawEventData.verb)),
         ObjName = tostring(RawEventData.objectRef.name),
         Namespace = tostring(RawEventData.objectRef.namespace),
         Actor = tostring(RawEventData.user.username),
         UserAgent = tostring(RawEventData.userAgent),
         SourceIp = tostring(RawEventData.sourceIPs[0]),
         Code = toint(RawEventData.responseStatus.code)
| where Resource == "secrets" and Verb == "get" and ObjName startswith "sh.helm.release.v1."
| where Code between (200 .. 299);
let Baseline = HelmSecrets
| where Timestamp < ago(DetectWindow)
| distinct Actor, AzureResourceId, Namespace;
HelmSecrets
| where Timestamp >= ago(DetectWindow)
| join kind=leftanti Baseline on Actor, AzureResourceId, Namespace
| extend UAFamily = tolower(tostring(split(UserAgent, "/")[0]))
| summarize FirstSeen = min(Timestamp), Releases = make_set(ObjName, 50), Namespaces = make_set(Namespace, 20),
            UserAgents = make_set(UserAgent, 5), SourceIps = make_set(SourceIp, 5),
            NonHelmClient = max(toint(not(UAFamily startswith "helm")))
    by Actor, AzureResourceId
| extend Severity = iff(NonHelmClient == 1 or array_length(Namespaces) > 1, "High", "Medium")
```
