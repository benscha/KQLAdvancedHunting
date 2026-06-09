# *RPC Attack Detection* 

## Query Information

#### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1003.002 | OS Credential Dumping: Security Account Manager | https://attack.mitre.org/techniques/T1003/002 |
| T1021.002 | Remote Services: SMB/Windows Admin Shares | https://attack.mitre.org/techniques/T1021/002/ |
| T1049 | System Network Connections Discovery | https://attack.mitre.org/techniques/T1049 |

#### Description

This rule detects suspicious inbound remote RPC calls indicative of credential dumping (remote registry save), lateral movement (remote service creation), or reconnaissance (session/user discovery). It identifies specific RPC interface UUIDs and operation numbers associated with these attack types. The rule also filters out local loopback traffic and noisy system accounts for reconnaissance activities to reduce false positives, and calculates a risk score based on network origin and NTLM authentication.

#### Author <Optional>
- **Name: Benjamin Zulliger**
- **Github: https://github.com/benscha/KQLAdvancedHunting**
- **LinkedIn: https://www.linkedin.com/in/benjamin-zulliger/**


## Defender XDR
```KQL
// RPC Attack Detection 
DeviceEvents
| where Timestamp > ago(2h)
| where ActionType == "InboundRemoteRpcCall"
// Parse telemetry details from JSON payload
| extend AF = parse_json(AdditionalFields)
| extend
	RpcInterfaceUuid   = tostring(AF.RpcInterfaceUuid),
	RpcOpNum           = toint(AF.RpcOpNum),
	AuthenticationType = tostring(AF.AuthenticationType),
	LocalRpcProcess    = InitiatingProcessFileName 
// Classify critical RPC interfaces and hazardous OpNums
| extend RpcAttackType = case(
	RpcInterfaceUuid == "338cd001-2244-31f1-aaaa-900038001003" and RpcOpNum in(20, 31), 
		"Credential Dumping (Remote Registry Save)",
	RpcInterfaceUuid == "367abb81-9844-35f1-ad32-98f038001003" and RpcOpNum in(12, 24, 44, 45, 60), 
		"Lateral Movement (Remote Service Creation)",
	RpcInterfaceUuid == "4b324fc8-1670-01d3-1278-5a47bf6ee188" and RpcOpNum == 12, 
		"Reconnaissance (Session/User Discovery)",
	"Unknown"
)
| where RpcAttackType != "Unknown"
// Filter out local loopback traffic
| where LocalIP != RemoteIP
// Filter noisy system accounts only for low-risk discovery tasks to catch privilege escalation
| where not(
	AccountName in~ ("SYSTEM", "LOCAL SERVICE", "NETWORK SERVICE") 
	and RpcAttackType == "Reconnaissance (Session/User Discovery)"
)
// Identify network boundaries including IPv6 scopes
| extend IsInternalIP = iff(ipv4_is_private(RemoteIP) or RemoteIP startswith "fe80" or RemoteIP == "::1", true, false)
| extend NtlmAuth = iff(AuthenticationType =~ "NTLM", 1, 0)
// Map findings to MITRE ATT&CK framework
| extend
	MitreTechnique = case(
		RpcAttackType contains "Credential",   "T1003.002",
		RpcAttackType contains "Lateral",      "T1021.002",
		RpcAttackType contains "Reconnais",    "T1049",
		""
	),
	MitreTactic = case(
		RpcAttackType contains "Credential",   "Credential Access",
		RpcAttackType contains "Lateral",      "Lateral Movement",
		RpcAttackType contains "Reconnais",    "Discovery",
		""
	)
| summarize
	FirstSeen        = min(Timestamp),
	LastSeen         = max(Timestamp),
	OccurrenceCount  = count(),
	HasNtlmAuth      = max(NtlmAuth), 
	LocalProcesses   = make_set(LocalRpcProcess, 10)
	by
	DeviceName, DeviceId,
	AccountName, AccountDomain,
	RemoteIP, IsInternalIP,
	RpcInterfaceUuid, RpcOpNum,
	RpcAttackType,
	MitreTechnique, MitreTactic
// Calculate RiskScore based on network origin and target value (NTLM adds penalty)
| extend RiskScore = case(
	not(IsInternalIP) and RpcAttackType contains "Credential", 100,
	not(IsInternalIP) and RpcAttackType contains "Lateral",     90,
	not(IsInternalIP),                                          80,
	IsInternalIP     and RpcAttackType contains "Credential",   75,
	IsInternalIP     and RpcAttackType contains "Lateral",      65,
	IsInternalIP,                                               40,
	30
)
| extend RiskScore = iff(HasNtlmAuth == 1, min_of(RiskScore + 15, 100), RiskScore)
| extend Severity = case(
	RiskScore >= 85, "Critical",
	RiskScore >= 65, "High",
	RiskScore >= 40, "Medium",
	"Low"
)
| extend ActivityDurationMin = datetime_diff('minute', LastSeen, FirstSeen)
| project
	Severity, RiskScore,
	DeviceName, AccountName, AccountDomain,
	RemoteIP, IsInternalIP,
	RpcAttackType, MitreTechnique, MitreTactic,
	RpcInterfaceUuid, RpcOpNum,
	HasNtlmAuth, LocalProcesses,
	OccurrenceCount, FirstSeen, LastSeen, ActivityDurationMin
| order by RiskScore desc, OccurrenceCount asc```
