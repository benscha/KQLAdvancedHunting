# *UAC Weakening and Persistence Mechanism Detection*

## Query Information

#### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1548.002 | Bypass User Account Control | https://attack.mitre.org/techniques/T1548/002/ |
| T1547.001 | Registry Run Keys / Startup Folder | https://attack.mitre.org/techniques/T1547/001/ |


#### Description
This rule monitors for the simultaneous disabling of critical User Account Control (UAC) registry settings (ConsentPromptBehaviorAdmin, PromptOnSecureDesktop, and EnableLUA) on a single device within a short correlation window. It further correlates this activity with the creation of a 'Windows Service Host' registry run key, which is a common persistence technique. This combination of UAC modification and suspicious persistence often indicates an attempt to facilitate unauthorized execution or privilege escalation.

#### Risk
Defense Evasion

#### Author <Optional>
- **Name: Benjamin Zulliger**
- **Github: https://github.com/benscha/KQLAdvancedHunting**
- **LinkedIn: https://www.linkedin.com/in/benjamin-zulliger/**

#### References
- 

## Defender XDR
```KQL
// Detect all three UAC settings being disabled by the same process on one device.
let Lookback = 7d;
let CorrelationWindow = 15m;
let UACWrites = materialize(
	DeviceRegistryEvents
	| where Timestamp >= ago(Lookback)
	| where ActionType == "RegistryValueSet"
	| where RegistryKey endswith @"\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
	| where RegistryValueName in~ (
		"ConsentPromptBehaviorAdmin",
		"PromptOnSecureDesktop",
		"EnableLUA"
	)
	| where tostring(RegistryValueData) in~ ("0", "0x0", "0x00000000", "00000000")
	| where isnotnull(InitiatingProcessId)
	| project
		DeviceId,
		DeviceName,
		Timestamp,
		RegistryValueName,
		InitiatingProcessId,
		InitiatingProcessFileName,
		InitiatingProcessFolderPath,
		InitiatingProcessCommandLine,
		InitiatingProcessSHA1,
		InitiatingProcessAccountName
);
let WindowsServiceHostRunWrites = materialize(
	DeviceRegistryEvents
	| where Timestamp >= ago(Lookback)
	| where ActionType == "RegistryValueSet"
	| where RegistryKey contains @"\Software\Microsoft\Windows\CurrentVersion\Run"
	| where RegistryValueName =~ "Windows Service Host"
	| where RegistryValueData contains "WindowsServiceHost.exe"
	| project
		DeviceId,
		PersistenceTime = Timestamp,
		PersistenceRegistryKey = RegistryKey,
		PersistenceData = RegistryValueData
);
let FirstWrite =
	UACWrites
	| project
		DeviceId,
		DeviceName,
		InitiatingProcessId,
		InitiatingProcessFileName,
		InitiatingProcessFolderPath,
		InitiatingProcessCommandLine,
		InitiatingProcessSHA1,
		InitiatingProcessAccountName,
		FirstTime = Timestamp,
		FirstValue = RegistryValueName;
let SecondWrite =
	UACWrites
	| project
		DeviceId,
		InitiatingProcessId,
		SecondTime = Timestamp,
		SecondValue = RegistryValueName;
let ThirdWrite =
	UACWrites
	| project
		DeviceId,
		InitiatingProcessId,
		ThirdTime = Timestamp,
		ThirdValue = RegistryValueName;
FirstWrite
| join kind=inner (SecondWrite) on DeviceId, InitiatingProcessId
| where SecondTime between (FirstTime .. FirstTime + CorrelationWindow)
| where FirstValue != SecondValue
| join kind=inner (ThirdWrite) on DeviceId, InitiatingProcessId
| where ThirdTime between (FirstTime .. FirstTime + CorrelationWindow)
| where ThirdValue != FirstValue and ThirdValue != SecondValue
| join kind=leftouter (WindowsServiceHostRunWrites) on DeviceId
| summarize
	FirstSeen = min(FirstTime),
	LastSecondWrite = max(SecondTime),
	LastThirdWrite = max(ThirdTime),
	HasWindowsServiceHostRunKey = countif(
		isnotnull(PersistenceTime)
		and PersistenceTime >= FirstTime - 1h
		and PersistenceTime <= FirstTime + CorrelationWindow + 1h
	) > 0,
	RunKeyRegistryPaths = make_set_if(
		PersistenceRegistryKey,
		isnotnull(PersistenceTime)
		and PersistenceTime >= FirstTime - 1h
		and PersistenceTime <= FirstTime + CorrelationWindow + 1h
	),
	RunKeyData = make_set_if(
		PersistenceData,
		isnotnull(PersistenceTime)
		and PersistenceTime >= FirstTime - 1h
		and PersistenceTime <= FirstTime + CorrelationWindow + 1h
	)
	by
		DeviceId,
		DeviceName,
		InitiatingProcessId,
		InitiatingProcessFileName,
		InitiatingProcessFolderPath,
		InitiatingProcessCommandLine,
		InitiatingProcessSHA1,
		InitiatingProcessAccountName
	| extend LastSeen = iif(LastSecondWrite > LastThirdWrite, LastSecondWrite, LastThirdWrite)
| extend Triage = iff(
	HasWindowsServiceHostRunKey,
	"Higher confidence: UAC weakening plus Windows Service Host Run-key persistence",
	"Investigate: correlated UAC weakening; validate against approved deployment activity"
)
| project
	FirstSeen,
	LastSeen,
	DeviceName,
	DeviceId,
	Triage,
	HasWindowsServiceHostRunKey,
	RunKeyRegistryPaths,
	RunKeyData,
	InitiatingProcessFileName,
	InitiatingProcessFolderPath,
	InitiatingProcessCommandLine,
	InitiatingProcessId,
	InitiatingProcessSHA1,
	InitiatingProcessAccountName
| order by FirstSeen desc
```

