# *Unauthorized Kubelet API or Proxy Access*

## Query Information

#### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1613 | Container and Resource Discovery | https://attack.mitre.org/techniques/T1613 |
| T1611 | Escape to Host | https://attack.mitre.org/techniques/T1611 |


#### Description

Detects unauthorized attempts to interact with the Kubelet API directly from pods or via the Kubernetes API server proxy. This includes potential remote execution, container discovery, log access, or debug/config endpoint access by non-authorized service accounts or processes, which may indicate container breakout attempts or lateral movement within a cluster.

#### Author <Optional>
- **Name: Benjamin Zulliger**
- **Github: https://github.com/benscha/KQLAdvancedHunting**
- **LinkedIn: https://www.linkedin.com/in/benjamin-zulliger/**


## Defender XDR
```KQL
let Lookback = 1d;
let AllowedNamespaces = dynamic(["kube-system", "calico-system", "gatekeeper-system", "monitoring"]);
let AllowedImages = dynamic(["prometheus", "metrics-server", "node-exporter", "kube-state-metrics", "otel", "datadog", "dynatrace"]);
let AllowedProxyIdentities = dynamic(["system:serviceaccount:monitoring:prometheus"]);
let ClassifyEndpoint = (s:string) {
    case(s has_any ("/run/", "/exec/", "/attach/", "/portforward/"), "RemoteExec",
         s has_any ("/runningpods", "/pods"), "PodDiscovery",
         s has_any ("/containerlogs/", "/logs/"), "LogAccess",
         s has_any ("/configz", "/debug/", "/checkpoint/"), "ConfigOrDebug",
         "Other")
};
let FromPod = CloudProcessEvents
| where Timestamp > ago(Lookback)
| where isnotempty(KubernetesPodName) and ContainerName != "host"
| where KubernetesNamespace !in (AllowedNamespaces)
| where not(ContainerImageName has_any (AllowedImages))
| extend Cmd = tolower(ProcessCommandLine)
| where Cmd matches regex @":1025[05]\b" or Cmd has "kubeletctl"
| where not(Cmd has_any ("/metrics", "/stats/summary", "/healthz"))
| project Timestamp, Source = "PodToKubelet", AzureResourceId, Identity = strcat(KubernetesNamespace, "/", KubernetesPodName),
          Detail = ProcessCommandLine, Endpoint = ClassifyEndpoint(Cmd), ContainerImageName, ParentProcessName, HostName;
let ViaApiServer = CloudAuditEvents
| where Timestamp > ago(Lookback)
| where DataSource =~ "Kubernetes Audit"
| extend Resource = tolower(tostring(RawEventData.objectRef.resource)),
         SubResource = tolower(tostring(RawEventData.objectRef.subresource))
| where Resource == "nodes" and SubResource == "proxy"
| extend User = tostring(RawEventData.user.username),
         RequestUri = tolower(tostring(RawEventData.requestURI)),
         Code = toint(RawEventData.responseStatus.code)
| where not(User startswith "system:") or User startswith "system:serviceaccount:"
| where User !in (AllowedProxyIdentities)
| where not(RequestUri has_any ("/metrics", "/stats/summary", "/healthz"))
| project Timestamp, Source = "NodesProxyViaApiServer", AzureResourceId, Identity = User,
          Detail = strcat(tostring(RawEventData.verb), " ", RequestUri, " (", Code, ")"),
          Endpoint = ClassifyEndpoint(RequestUri), SourceIp = tostring(RawEventData.sourceIPs[0]);
union FromPod, ViaApiServer
| extend Severity = case(Endpoint == "RemoteExec", "High",
                         Endpoint in ("PodDiscovery", "ConfigOrDebug", "LogAccess"), "Medium",
                         "Low")
| where Severity != "Low"
| order by Timestamp desc
```
