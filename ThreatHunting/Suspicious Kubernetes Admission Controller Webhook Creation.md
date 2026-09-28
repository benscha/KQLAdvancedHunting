# Suspicious Kubernetes Admission Controller Webhook Creation*

## Query Information

#### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1611 | Escape to Host | https://attack.mitre.org/techniques/T1611 |
| T1610 | Deploy to Container | https://attack.mitre.org/techniques/T1610 |

#### Description

This rule detects the creation of new Mutating or Validating Webhook Configurations in a Kubernetes cluster that bypass established trusted actors. It scores these creations based on risk factors such as targeting sensitive resources (pods, secrets), absence of namespace selectors, use of 'Ignore' failure policies, and external URLs. The rule further correlates these webhooks with evidence of successful object mutations to identify potential malicious interceptors or privilege escalation attempts.

#### Author <Optional>
- **Name: Benjamin Zulliger**
- **Github: https://github.com/benscha/KQLAdvancedHunting**
- **LinkedIn: https://www.linkedin.com/in/benjamin-zulliger/**


## Defender XDR
```KQL
let Lookback = 1d;
let AllowedWebhookCreators = dynamic([
    "system:serviceaccount:flux-system:kustomize-controller",
    "system:serviceaccount:argocd:argocd-application-controller"]);
let KnownWebhookNamespaces = dynamic(["gatekeeper-system", "kyverno", "cert-manager", "kube-system"]);
let Audit = CloudAuditEvents
| where Timestamp > ago(Lookback)
| where DataSource =~ "Kubernetes Audit"
| extend Verb = tolower(tostring(RawEventData.verb)),
         Resource = tolower(tostring(RawEventData.objectRef.resource)),
         Actor = tostring(RawEventData.user.username),
         Code = toint(RawEventData.responseStatus.code);
let NewWebhooks = Audit
| where Resource in ("mutatingwebhookconfigurations", "validatingwebhookconfigurations")
| where Verb == "create" and Code between (200 .. 299)
| where Actor !in (AllowedWebhookCreators)
| extend Req = RawEventData.requestObject, SourceIp = tostring(RawEventData.sourceIPs[0])
| extend Config = coalesce(tostring(RawEventData.objectRef.name), tostring(Req.metadata.name))
| mv-expand WH = Req.webhooks
| extend WebhookName = tostring(WH.name),
         ExternalUrl = tostring(WH.clientConfig.url),
         SvcNamespace = tostring(WH.clientConfig.service.namespace),
         SvcName = tostring(WH.clientConfig.service.name),
         FailurePolicy = tostring(WH.failurePolicy),
         NsSelectorEmpty = isnull(WH.namespaceSelector) or array_length(bag_keys(WH.namespaceSelector)) == 0,
         Rules = WH.rules
| mv-apply R = Rules on (
    mv-expand Res = R.resources, Op = R.operations
    | summarize Resources = make_set(tostring(Res)), Operations = make_set(tostring(Op)))
| extend TargetsPods = set_has_element(Resources, "pods") or set_has_element(Resources, "*"),
         TargetsSecrets = set_has_element(Resources, "secrets") or set_has_element(Resources, "*")
| extend Score = iff(isnotempty(ExternalUrl), 4, 0)
               + iff(isnotempty(SvcNamespace) and SvcNamespace !in (KnownWebhookNamespaces), 2, 0)
               + iff(Resource == "mutatingwebhookconfigurations" and TargetsPods, 2, 0)
               + iff(TargetsSecrets, 3, 0)
               + iff(FailurePolicy =~ "Ignore", 1, 0)
               + iff(NsSelectorEmpty, 1, 0)
| project CreatedAt = Timestamp, AzureResourceId, WebhookType = Resource, Config, WebhookName, Actor, SourceIp,
          ExternalUrl, SvcNamespace, SvcName, FailurePolicy, NsSelectorEmpty, Resources, Operations, Score;
let Mutations = Audit
| where Resource == "pods" and Verb == "create"
| extend Ann = RawEventData.annotations, PodNamespace = tostring(RawEventData.objectRef.namespace)
| where tostring(Ann) has "mutation.webhook.admission.k8s.io"
| mv-apply AnnKey = bag_keys(Ann) to typeof(string) on (
    where AnnKey startswith "mutation.webhook.admission.k8s.io"
    | extend AnnVal = parse_json(tostring(Ann[AnnKey]))
    | where tobool(AnnVal.mutated)
    | project Config = tostring(AnnVal.configuration))
| summarize MutatedPods = count(), MutatedNamespaces = make_set(PodNamespace, 20), FirstMutation = min(Timestamp)
    by AzureResourceId, Config;
NewWebhooks
| join kind=leftouter Mutations on AzureResourceId, Config
| extend MutatedPods = coalesce(MutatedPods, 0)
| extend Score = Score + iff(MutatedPods > 0 and FirstMutation >= CreatedAt, 2, 0)
| where Score >= 3
| extend Severity = iff(Score >= 6, "High", "Medium")
| project-away AzureResourceId1, Config1
| order by Score desc
```
