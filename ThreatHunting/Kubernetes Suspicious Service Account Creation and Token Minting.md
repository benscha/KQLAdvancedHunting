# *Kubernetes Suspicious Service Account Creation and Token Minting*

## Query Information

#### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1136.001 | Local Account | https://attack.mitre.org/techniques/T1136/001 |
| T1528 | Steal Application Access Token | https://attack.mitre.org/techniques/T1528 |
| T1098.003 | Additional Cloud Roles | https://attack.mitre.org/techniques/T1098/003 |


#### Description

This rule detects a sequence of suspicious Kubernetes activities involving the creation of a new Service Account, followed by the attachment of high-privilege RoleBindings (admin, edit, or cluster-admin) to that account, and finally the requesting of an authentication token for the newly created account. This pattern is indicative of a privilege escalation attempt where an adversary attempts to create a persistent, highly-privileged identity within the cluster.


#### Author <Optional>
- **Name: Benjamin Zulliger**
- **Github: https://github.com/benscha/KQLAdvancedHunting**
- **LinkedIn: https://www.linkedin.com/in/benjamin-zulliger/**


## Defender XDR
```KQL
let Lookback = 1d;
let ChainWindow = 1h;
let AllowedAutomation = dynamic(["system:serviceaccount:argocd:argocd-application-controller"]);
let Audit = CloudAuditEvents
| where Timestamp > ago(Lookback)
| where DataSource =~ "Kubernetes Audit"
| extend Verb = tolower(tostring(RawEventData.verb)),
         Resource = tolower(tostring(RawEventData.objectRef.resource)),
         SubResource = tolower(tostring(RawEventData.objectRef.subresource)),
         Namespace = tostring(RawEventData.objectRef.namespace),
         ObjName = tostring(RawEventData.objectRef.name),
         Actor = tostring(RawEventData.user.username),
         SourceIp = tostring(RawEventData.sourceIPs[0]),
         Code = toint(RawEventData.responseStatus.code),
         Req = RawEventData.requestObject
| where Verb == "create" and Code between (200 .. 299)
| where Actor !in (AllowedAutomation) and not(Actor startswith "system:node:");
let SACreated = Audit
| where Resource == "serviceaccounts" and isempty(SubResource)
| project SACreatedAt = Timestamp, AzureResourceId, Actor, SourceIp, Namespace,
          SAName = coalesce(ObjName, tostring(Req.metadata.name));
let Bindings = Audit
| where Resource in ("rolebindings", "clusterrolebindings")
| mv-expand Subject = Req.subjects
| where tostring(Subject.kind) == "ServiceAccount"
| project BindAt = Timestamp, AzureResourceId, Actor,
          Namespace = coalesce(tostring(Subject.namespace), Namespace),
          SAName = tostring(Subject.name),
          BindingKind = Resource, RoleRef = tostring(Req.roleRef.name);
let TokenMint = union
    (Audit
     | where Resource == "serviceaccounts" and SubResource == "token"
     | project MintAt = Timestamp, AzureResourceId, Actor, Namespace, SAName = ObjName,
               MintType = "TokenRequest", ExpirationSec = tolong(Req.spec.expirationSeconds)),
    (Audit
     | where Resource == "secrets" and tostring(Req.type) == "kubernetes.io/service-account-token"
     | project MintAt = Timestamp, AzureResourceId, Actor, Namespace,
               SAName = tostring(Req.metadata.annotations["kubernetes.io/service-account.name"]),
               MintType = "LegacySecretToken", ExpirationSec = long(null));
SACreated
| join kind=inner Bindings on AzureResourceId, Actor, Namespace, SAName
| where BindAt between (SACreatedAt .. (SACreatedAt + ChainWindow))
| join kind=inner TokenMint on AzureResourceId, Actor, Namespace, SAName
| where MintAt between (SACreatedAt .. (SACreatedAt + ChainWindow))
| extend Severity = case(RoleRef in ("cluster-admin", "admin", "edit") or BindingKind == "clusterrolebindings", "High",
                         MintType == "LegacySecretToken" or ExpirationSec > 86400, "High",
                         "Medium")
| project SACreatedAt, BindAt, MintAt, Actor, SourceIp, AzureResourceId, Namespace, SAName,
          BindingKind, RoleRef, MintType, ExpirationSec, Severity
```
