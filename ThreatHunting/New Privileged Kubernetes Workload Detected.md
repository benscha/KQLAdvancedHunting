# *New Privileged Kubernetes Workload Detected*

## Query Information

#### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1611 | Escape to Host | https://attack.mitre.org/techniques/T1611 |
| T1078.004 | Cloud Accounts | https://attack.mitre.org/techniques/T1078/004 |


#### Description

This rule monitors Kubernetes audit logs to detect the creation or update of new containerized workloads (Pods, Deployments, etc.) that utilize a ServiceAccount which has been granted privileged cluster roles or is otherwise identified as privileged. The rule establishes a baseline of existing workload-ServiceAccount pairs and alerts on newly introduced associations, helping to detect potential privilege escalation or persistence via unauthorized workload deployment.

#### Author <Optional>
- **Name: Benjamin Zulliger**
- **Github: https://github.com/benscha/KQLAdvancedHunting**
- **LinkedIn: https://www.linkedin.com/in/benjamin-zulliger/**


## Defender XDR
```KQL
let Lookback = 30d;
let DetectWindow = 1d;
let WorkloadResources = dynamic(["pods", "deployments", "statefulsets", "daemonsets", "replicasets", "jobs", "cronjobs"]);
let AllowedAutomation = dynamic(["system:serviceaccount:argocd:argocd-application-controller"]);
let StaticPrivilegedSAs = dynamic(["<namespace>:<sa-name>"]);   // SAs mit bekannten mächtigen Bindings
let Audit = CloudAuditEvents
| where Timestamp > ago(Lookback)
| where DataSource =~ "Kubernetes Audit"
| extend Verb = tolower(tostring(RawEventData.verb)),
         Resource = tolower(tostring(RawEventData.objectRef.resource)),
         SubResource = tolower(tostring(RawEventData.objectRef.subresource)),
         Namespace = tostring(RawEventData.objectRef.namespace),
         Actor = tostring(RawEventData.user.username),
         Code = toint(RawEventData.responseStatus.code),
         RequestUri = tostring(RawEventData.requestURI),
         Req = RawEventData.requestObject
| where Code between (200 .. 299) and not(RequestUri has "dryRun");
let PrivilegedFromBindings = Audit
| where Resource in ("rolebindings", "clusterrolebindings") and Verb in ("create", "update")
| extend RoleRef = tostring(Req.roleRef.name)
| where Resource == "clusterrolebindings" or RoleRef in ("admin", "edit", "cluster-admin")
| mv-expand Subject = Req.subjects
| where tostring(Subject.kind) == "ServiceAccount"
| extend SAKey = strcat(coalesce(tostring(Subject.namespace), Namespace), ":", tostring(Subject.name))
| summarize BoundRoles = make_set(RoleRef, 10) by SAKey;
let Workloads = Audit
| where Resource in (WorkloadResources) and isempty(SubResource) and Verb in ("create", "update")
| where not(Actor startswith "system:serviceaccount:kube-system:") and not(Actor startswith "system:node:")
| where Actor !in (AllowedAutomation)
| extend PodSpec = case(Resource == "pods", Req.spec,
                        Resource == "cronjobs", Req.spec.jobTemplate.spec.template.spec,
                        Req.spec.template.spec)
| extend SAName = coalesce(tostring(PodSpec.serviceAccountName), tostring(PodSpec.serviceAccount), "default"),
         Workload = coalesce(tostring(RawEventData.objectRef.name), tostring(Req.metadata.name), tostring(Req.metadata.generateName)),
         AutomountToken = tostring(PodSpec.automountServiceAccountToken)
| extend SAKey = strcat(Namespace, ":", SAName)
| where SAName != "default" and Actor != strcat("system:serviceaccount:", SAKey);
let Baseline = Workloads
| where Timestamp < ago(DetectWindow)
| distinct Actor, AzureResourceId, SAKey;
Workloads
| where Timestamp >= ago(DetectWindow)
| join kind=leftanti Baseline on Actor, AzureResourceId, SAKey
| join kind=leftouter PrivilegedFromBindings on SAKey
| extend IsPrivileged = isnotempty(BoundRoles) or SAKey in (StaticPrivilegedSAs) or Namespace == "kube-system"
| summarize FirstSeen = min(Timestamp), Workloads = make_set(strcat(Resource, "/", Workload), 20),
            BoundRoles = take_any(BoundRoles), IsPrivileged = max(toint(IsPrivileged)),
            AutomountToken = make_set(AutomountToken, 3),
            SourceIps = make_set(tostring(RawEventData.sourceIPs[0]), 5)
    by Actor, AzureResourceId, Namespace, SAName
| extend Severity = iff(IsPrivileged == 1, "High", "Medium")
```
