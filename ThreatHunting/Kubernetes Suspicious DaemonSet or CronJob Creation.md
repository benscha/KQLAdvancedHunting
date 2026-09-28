# Kubernetes Suspicious DaemonSet or CronJob Creation*

## Query Information

#### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1053.007 | Container Orchestration Job | https://attack.mitre.org/techniques/T1053/007 |
| T1609 | Container Administration Command | https://attack.mitre.org/techniques/T1609 |
| T1611 | Escape to Host | https://attack.mitre.org/techniques/T1611 |

#### Description

Detects the creation or update of Kubernetes DaemonSets or CronJobs that exhibit suspicious characteristics, such as the use of privileged containers, hostPath mounts, host networking, or execution of common adversary-used command-line tools. The rule implements a scoring mechanism based on behavioral indicators including name mimicry, frequent execution schedules, and the namespace context, filtering out known automation service accounts.

#### Author <Optional>
- **Name: Benjamin Zulliger**
- **Github: https://github.com/benscha/KQLAdvancedHunting**
- **LinkedIn: https://www.linkedin.com/in/benjamin-zulliger/**


## Defender XDR
```KQL
let Lookback = 30d;
let DetectWindow = 1d;
let AllowedAutomation = dynamic([
    "system:serviceaccount:flux-system:kustomize-controller",
    "system:serviceaccount:argocd:argocd-application-controller"]);
let Persist = CloudAuditEvents
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
| where Resource in ("daemonsets", "cronjobs") and Verb in ("create", "update") and isempty(SubResource)
| where Code between (200 .. 299) and not(RequestUri has "dryRun")
| where not(Actor startswith "system:") or Actor startswith "system:serviceaccount:"
| where not(Actor startswith "system:serviceaccount:kube-system:");
let Baseline = Persist
| where Timestamp < ago(DetectWindow)
| distinct Actor, AzureResourceId, Resource;
Persist
| where Timestamp >= ago(DetectWindow)
| where Actor !in (AllowedAutomation)
| join kind=leftanti Baseline on Actor, AzureResourceId, Resource
| extend ObjName = coalesce(tostring(RawEventData.objectRef.name), tostring(Req.metadata.name)),
         PodSpec = iff(Resource == "cronjobs", Req.spec.jobTemplate.spec.template.spec, Req.spec.template.spec),
         Schedule = tostring(Req.spec.schedule),
         SourceIp = tostring(RawEventData.sourceIPs[0])
| extend HostAccess = tobool(PodSpec.hostPID) or tobool(PodSpec.hostNetwork) or tobool(PodSpec.hostIPC)
                   or tostring(PodSpec.volumes) has "hostPath"
                   or tostring(PodSpec.containers) has "\"privileged\":true",
         HighFrequency = Schedule matches regex @"^(\*|\*/[1-5])\s",
         NameMimicry = ObjName matches regex @"^(kube-|azure-|aks-|calico-|coredns|konnectivity|csi-|ama-|omsagent|cloud-node-manager|microsoft-defender)"
| mv-expand C = PodSpec.containers
| extend Image = tostring(C.image), Cmd = tolower(strcat(tostring(C.command), " ", tostring(C.args)))
| extend SuspiciousCmd = Cmd has_any ("curl", "wget", "base64", "/dev/tcp", "socat", "ncat", "nsenter", "xmrig", "chmod +x", "python -c", "perl -e")
                      or Cmd matches regex @"\|\s*(ba)?sh\b"
| summarize Images = make_set(Image, 10), Commands = make_set(Cmd, 10), SuspiciousCmd = max(toint(SuspiciousCmd))
    by Timestamp, Actor, SourceIp, AzureResourceId, Resource, Verb, Namespace, ObjName, Schedule,
       HostAccess = toint(HostAccess), HighFrequency = toint(HighFrequency), NameMimicry = toint(NameMimicry)
| extend Score = 1
               + SuspiciousCmd * 3
               + HostAccess * 2
               + iff(Resource == "daemonsets" and HostAccess == 1, 1, 0)
               + HighFrequency
               + NameMimicry * 2
               + iff(Namespace == "kube-system", 2, 0)
| where Score >= 3
| extend Severity = iff(Score >= 5, "High", "Medium")
| order by Score desc
```
