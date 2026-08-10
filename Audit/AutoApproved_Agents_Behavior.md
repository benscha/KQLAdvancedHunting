# *AutoApproved Agents Behavior*

## Query Information

#### Recommondation
it's not recommended to use this Query as a Custom Detection Rule. This Query is for Audit purposes.

#### Description
This KQL query implements a multi-stage threat hunting and correlation engine designed to detect high-risk or malicious command execution originating from local AI and automation agents.

It begins by dynamically scoping active, auto-approving agents and mapping them to specific endpoints. After isolating the process events linked to these agents, the query normalizes command-line strings by stripping whitespace and common evasion-escaping characters, while filtering out known benign baseline activity.

Each command line is evaluated against over twenty threat categories spanning traditional ATT&CK tactics, cloud credentials, container escapes, and supply-chain tampering to calculate an individual event risk score. To capture broader campaign dynamics, individual events are grouped into thirty-minute operational sessions that track progression through reconnaissance, access, and action phases. Finally, the query filters for high-impact single events, active kill-chain patterns, or cumulative session risks, returning a prioritized list of alerts categorized by severity for immediate SOC triage.

#### Author <Optional>
- **Name: Benjamin Zulliger**
- **Github: https://github.com/benscha/KQLAdvancedHunting**
- **LinkedIn: https://www.linkedin.com/in/benjamin-zulliger/**

#### References

## Defender XDR
```KQL
let Lookback      = 7d;
let SessionWindow = 30m;   // Time window for kill-chain correlation
let MinScore      = 5;     // Single-event threshold; below this only visible via Session/Chain
let RxWhitelist   = @"(?i)(conhost\.exe.*-ForceV1|reg(\.exe)?\s+query\s|git\s+(status|diff|log|fetch|pull)\b)";
// --- Classic attacker categories ---
let RxCredentials = @"(?i)(lsass|mimikatz|sekurlsa|comsvcs.*minidump|reg(\.exe)?\s+save\s+hk|ntds\.dit|vaultcmd|cmdkey\s+/list|security\s+find-generic-password)";
let RxSecrets     = @"(?i)(\.ssh[\\/]id_|\.aws[\\/]credentials|\.env\b|credentials\.json|\.kube[\\/]config|gh\s+auth\s+token|\.git-credentials|\.npmrc|\.pypirc)";
let RxObfuscation = @"(?i)(-enc(odedcommand)?\s|frombase64string|invoke-expression|\biex\b|downloadstring|downloadfile|-w(indowstyle)?\s+hidden|-nop\b|base64\s+-d|eval\(atob)";
let RxEvasion     = @"(?i)(set-mppreference|add-mppreference\s+-exclusion|wevtutil\s+cl|vssadmin\s+delete|bcdedit|netsh\s+advfirewall\s+set|sc(\.exe)?\s+(stop|delete)\s+(sense|windefend))";
let RxPersistence = @"(?i)(schtasks\s+/create|sc(\.exe)?\s+create|new-service|currentversion\\run|crontab|launchctl\s+load)";
let RxDiscovery   = @"(?i)(whoami\s+/all|net\s+(local)?group|nltest|get-ad(user|group|computer)|dsquery|adfind|systeminfo|quser|klist)";
let RxLateral     = @"(?i)(psexec|wmic\s+/node|enter-pssession|invoke-command\s+-computername|\brunas\b|winrs)";
let RxDestructive = @"(?i)(rm\s+-rf\s+[/~]|remove-item.*-recurse.*-force|cipher\s+/w|del\s+/f\s+/s\s+/q|format\s+[a-z]:)";
// --- Cloud, identity, container ---
let RxCloudCreds  = @"(?i)(169\.254\.169\.254|metadata\.google\.internal|az\s+account\s+get-access-token|get-azaccesstoken|aws\s+sts\s+(get-session|assume-role)|gcloud\s+auth\s+(print-access-token|application-default)|az\s+keyvault\s+secret\s+show|secretsmanager\s+get-secret|\.azure[\\/]|\.docker[\\/]config\.json|serviceaccount[\\/]token)";
let RxIdentity    = @"(?i)(new-azadserviceprincipal|new-azadappcredential|update-mgapplication|add-mgapplicationpassword|new-mgoauth2permissiongrant|new-inboxrule|set-inboxrule|add-mailboxpermission|add-mgdirectoryrolemember)";
let RxContainer   = @"(?i)(/var/run/docker\.sock|docker\s+run.*--privileged|\bnsenter\b|kubectl\s+(get\s+secret|exec|cp|port-forward)|crictl|/proc/1/root)";
let RxInfraDestroy= @"(?i)(terraform\s+destroy|az\s+group\s+delete|remove-azresourcegroup|aws\s+s3\s+rb\b|kubectl\s+delete\s+(namespace|ns|pvc)|drop\s+(database|table))";
// --- Agent-specific ---
let RxSupplyChain = @"(?i)((curl|wget)[^|;]*\|\s*(ba)?sh|pip\s+install\s+(git\+|https?://|--index-url)|npm\s+(publish|config\s+set\s+registry)|npx\s+--yes\s+https?://|--allow-scripts|postinstall|go\s+install\s+.*@|iwr[^|]*\|\s*iex)";
let RxSelfMod     = @"(?i)(--dangerously-skip-permissions|--yolo\b|autoapprove|\.mcp\.json|mcp[_-]?config|settings\.local\.json|claude\.md|\.cursorrules|\.github[\\/]workflows[\\/]|allowedtools)";
let RxGitTamper   = @"(?i)(git\s+remote\s+(add|set-url)|git\s+config.*url\..*insteadof|git\s+push\s+.*(--force|-f)\b|filter-branch|git\s+config\s+core\.hookspath|\.git[\\/]hooks[\\/])";
// --- C2, anti-forensics, staging, hunting ---
let RxC2          = @"(?i)(/dev/tcp/|\bsocat\b|\bngrok\b|cloudflared\s+tunnel|\bchisel\b|ssh\s+-[a-z]*R\b|localtunnel|pty\.spawn|new-object\s+system\.net\.sockets)";
let RxAntiForensic= @"(?i)(history\s+-c|unset\s+HISTFILE|HISTFILE=/dev/null|\bshred\b|truncate\s+-s\s*0\s+/var/log|journalctl\s+--vacuum|chattr\s+\+i|touch\_-[amt]\s|log\s+erase|rm\s+.*\.bash_history)";
let RxSecretHunt  = @"(?i)((grep|rg|findstr)\s+[^\n]*(-r|/s)[^\n]*(passw|secret|api[_-]?key|token|begin\s+.*private)|select-string\s+.*passw|trufflehog|gitleaks)";
let RxStaging     = @"(?i)((7z|zip)\s+.*\s-p|tar\s+-?c[^\s]*z?f?\s+.*(/home/|/users/|\$HOME)|base64\s+-w\s*0|split\s+-b|compress-archive.*-path\s+.*(users|home))";
let RxLolBin      = @"(?i)((rundll32|regsvr32|mshta|msbuild|installutil|forfiles|pcalua)(\.exe)?\b|wmic\s+process\s+call\s+create|certreq\s+-post)";
// --- Exfil: hard indicators vs. context-dependent network tools ---
let RxExfilHard   = @"(?i)(certutil\s+-urlcache|bitsadmin\s+/transfer|rclone\s+(copy|sync|move)|\bnc\b\s+-)";
let RxNetTool     = @"(?i)(\bcurl\b|\bwget\b|\bscp\b|invoke-webrequest|invoke-restmethod|\biwr\b)";
let RxSuspDest    = @"(?i)(https?://(\d{1,3}\.){3}\d{1,3}|pastebin|paste\.ee|transfer\.sh|file\.io|0x0\.st|gofile|anonfiles|webhook\.site|requestbin|\.workers\.dev|\.ngrok|discord(app)?\.com/api/webhooks|api\.telegram\.org)";
let AutoApproveAgents =
	AgentsInfo
	| where Platform == "LocalAgents"
	| summarize arg_max(Timestamp, Name, Version, LifecycleStatus, RawAgentInfo) by AgentId
	| where LifecycleStatus !in~ ("Deleted", "Uninstalled")
	| extend Meta = RawAgentInfo.localAgentMetadata
	| extend AutoApprove  = tostring(Meta.autoApprove),
	         AgentExe     = tostring(Meta.relatedProcess),
	         AadDeviceId  = tolower(tostring(Meta.aadDeviceId)),
	         AgentAccount = tostring(Meta.accountName)
	| where AutoApprove =~ "true"
	| project AadDeviceId, AgentName = Name, AgentExe, AgentAccount;
let AgentDevices =
	AutoApproveAgents
	| join kind=inner (
		DeviceInfo
		| where Timestamp > ago(Lookback)
		| where isnotempty(AadDeviceId)
		| summarize arg_max(Timestamp, DeviceId, DeviceName) by AadDeviceId = tolower(AadDeviceId)
	) on AadDeviceId
	| project DeviceId, DeviceName, AgentName, AgentExe, AgentAccount;
let Hits = materialize(
	AgentDevices
	| join kind=inner (
		DeviceProcessEvents
		| where Timestamp > ago(Lookback)
	) on DeviceId
	| where InitiatingProcessFileName        =~ AgentExe
		 or InitiatingProcessParentFileName =~ AgentExe
		 or InitiatingProcessCommandLine contains AgentExe
	| extend CmdRaw = coalesce(ProcessCommandLine, FileName)
	// Normalize: strip caret/backtick/quote escaping and collapse whitespace before matching
	| extend Cmd = replace_regex(replace_regex(CmdRaw, @"[\^`""']", ""), @"\s+", " ")
	| where not(Cmd matches regex RxWhitelist)
	| extend
		IsCredentials = Cmd matches regex RxCredentials,
		IsSecrets     = Cmd matches regex RxSecrets,
		IsCloudCreds  = Cmd matches regex RxCloudCreds,
		IsIdentity    = Cmd matches regex RxIdentity,
		IsDestructive = Cmd matches regex RxDestructive,
		IsInfraDestr  = Cmd matches regex RxInfraDestroy,
		IsC2          = Cmd matches regex RxC2,
		IsEvasion     = Cmd matches regex RxEvasion,
		IsAntiForens  = Cmd matches regex RxAntiForensic,
		IsContainer   = Cmd matches regex RxContainer,
		IsSupplyChain = Cmd matches regex RxSupplyChain,
		IsSelfMod     = Cmd matches regex RxSelfMod,
		IsObfuscation = Cmd matches regex RxObfuscation,
		IsPersistence = Cmd matches regex RxPersistence,
		IsLateral     = Cmd matches regex RxLateral,
		IsGitTamper   = Cmd matches regex RxGitTamper,
		IsStaging     = Cmd matches regex RxStaging,
		IsSecretHunt  = Cmd matches regex RxSecretHunt,
		IsLolBin      = Cmd matches regex RxLolBin,
		IsDiscovery   = Cmd matches regex RxDiscovery,
		HasNetTool    = Cmd matches regex RxNetTool,
		HasSuspDest   = Cmd matches regex RxSuspDest
	// Network tools only count as exfil when the destination or the payload is suspicious
	| extend IsExfil  = Cmd matches regex RxExfilHard
		or (HasNetTool and (HasSuspDest or Cmd matches regex RxSecrets))
	| extend IsNetTool = HasNetTool and not(IsExfil)
	| extend Categories = array_concat(
		iff(IsCredentials, dynamic(["Credential Access"]), dynamic([])),
		iff(IsDestructive, dynamic(["Destructive Action"]), dynamic([])),
		iff(IsSecrets,     dynamic(["Secret / Token Access"]), dynamic([])),
		iff(IsCloudCreds,  dynamic(["Cloud Credential Access"]), dynamic([])),
		iff(IsIdentity,    dynamic(["Identity Persistence"]), dynamic([])),
		iff(IsInfraDestr,  dynamic(["Infrastructure Destruction"]), dynamic([])),
		iff(IsExfil,       dynamic(["Exfiltration"]), dynamic([])),
		iff(IsC2,          dynamic(["C2 / Tunnel"]), dynamic([])),
		iff(IsEvasion,     dynamic(["Defense Evasion"]), dynamic([])),
		iff(IsAntiForens,  dynamic(["Anti-Forensics"]), dynamic([])),
		iff(IsContainer,   dynamic(["Container Escape"]), dynamic([])),
		iff(IsSupplyChain, dynamic(["Supply Chain"]), dynamic([])),
		iff(IsSelfMod,     dynamic(["Agent Self-Modification"]), dynamic([])),
		iff(IsObfuscation, dynamic(["Obfuscation / Download Cradle"]), dynamic([])),
		iff(IsPersistence, dynamic(["Persistence"]), dynamic([])),
		iff(IsLateral,     dynamic(["Lateral Movement"]), dynamic([])),
		iff(IsGitTamper,   dynamic(["Git Tampering"]), dynamic([])),
		iff(IsStaging,     dynamic(["Collection / Staging"]), dynamic([])),
		iff(IsSecretHunt,  dynamic(["Secret Hunting"]), dynamic([])),
		iff(IsLolBin,      dynamic(["LOLBin Execution"]), dynamic([])),
		iff(IsDiscovery,   dynamic(["Discovery"]), dynamic([])),
		iff(IsNetTool,     dynamic(["Network Activity"]), dynamic([])))
	| where array_length(Categories) > 0
	| extend BaseScore = case(
		IsCredentials or IsDestructive, 10,
		IsSecrets or IsCloudCreds or IsIdentity or IsInfraDestr, 9,
		IsExfil or IsC2, 8,
		IsEvasion or IsAntiForens or IsContainer, 7,
		IsSupplyChain or IsSelfMod, 6,
		IsObfuscation or IsPersistence or IsLateral, 5,
		IsGitTamper or IsStaging or IsSecretHunt, 4,
		IsLolBin, 3,
		IsDiscovery, 2,
		1)
	// Multiple categories in one command line are a strong signal on their own
	| extend Score = BaseScore + iff(array_length(Categories) > 1, 2, 0)
	| extend
		PhaseRecon  = toint(IsDiscovery or IsSecretHunt or IsContainer),
		PhaseAccess = toint(IsCredentials or IsSecrets or IsCloudCreds),
		PhaseAct    = toint(IsExfil or IsC2 or IsStaging or IsDestructive or IsInfraDestr or IsIdentity or IsPersistence)
	| extend SessionKey = strcat(DeviceId, "|", AgentName, "|", tostring(bin(Timestamp, SessionWindow)))
	| project Timestamp, SessionKey, DeviceId, DeviceName, AgentName, AgentExe, AgentAccount,
		AccountName, AccountUpn, Categories, Score, PhaseRecon, PhaseAccess, PhaseAct,
		TopCategory = tostring(Categories[0]), ExecutedCommand = CmdRaw,
		ParentProcess = InitiatingProcessFileName, ParentCommandLine = InitiatingProcessCommandLine
);
let Sessions =
	Hits
	| summarize
		SessionScore  = sum(Score),
		SessionEvents = count(),
		SessionStart  = min(Timestamp),
		SessionEnd    = max(Timestamp),
		HasRecon      = max(PhaseRecon),
		HasAccess     = max(PhaseAccess),
		HasAct        = max(PhaseAct)
		by SessionKey
	| extend ChainStages = HasRecon + HasAccess + HasAct
	| extend KillChain = case(
		HasAccess == 1 and HasAct == 1 and HasRecon == 1, "Recon > Access > Action",
		HasAccess == 1 and HasAct == 1, "Access > Action",
		ChainStages >= 2, "Partial",
		"None");
Hits
| join kind=inner (Sessions) on SessionKey
| where Score >= MinScore or KillChain != "None" or SessionScore >= 15
| extend Severity = case(
	Score >= 9 or KillChain == "Recon > Access > Action", "High",
	Score >= 5 or KillChain != "None" or SessionScore >= 15, "Medium",
	"Low")
| extend Rank = case(Severity == "High", 1, Severity == "Medium", 2, 3)
| project Timestamp, Rank, Severity, Score, TopCategory, Categories,
	KillChain, SessionScore, SessionEvents, SessionStart, SessionEnd,
	DeviceName, AgentName, AgentExe, AgentAccount, AccountName, AccountUpn,
	ExecutedCommand, ParentProcess, ParentCommandLine
| sort by Rank asc, SessionScore desc, Timestamp desc
| project-away Rank
```
