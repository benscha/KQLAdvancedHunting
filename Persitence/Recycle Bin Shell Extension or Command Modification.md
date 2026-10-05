# *Recycle Bin Shell Extension or Command Modification*

## Query Information

#### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1546.015 | Component Object Model Hijack | https://attack.mitre.org/techniques/T1546/015/ |

#### Description

Detects modifications to the Recycle Bin's registry shell keys, specifically targeting 'shell' command execution, 'delegateexecute' handlers, or shell extension handlers. Such modifications are often used as persistence mechanisms or to hijack execution flow when a user interacts with the Recycle Bin.

#### Author <Optional>
- **Name: Benjamin Zulliger**
- **Github: https://github.com/benscha/KQLAdvancedHunting**
- **LinkedIn: https://www.linkedin.com/in/benjamin-zulliger/**

#### References
- Linkedin Post Maurice Fielenbach https://www.linkedin.com/posts/mauricefielenbach_threatintel-dfir-cybersecurity-activity-7512198572235223040-aWdw


## Defender XDR
```KQL
let Lookback = 7d;
let IncludeHuntingSignals = false;
let RecycleBinClsid = "{645ff040-5081-101b-9f08-00aa002f954e}";
let ClassRootPattern = @"^(?:(?:hklm|hkey_local_machine|hkcu|hkey_current_user|(?:hku|hkey_users)\\[^\\]+)\\software\\(?:wow6432node\\)?classes\\(?:wow6432node\\)?clsid\\|(?:hkcr|hkey_classes_root|(?:hku|hkey_users)\\[^\\]+_classes)\\(?:wow6432node\\)?clsid\\)";
let RecyclePathPattern = strcat(ClassRootPattern, @"\{645ff040-5081-101b-9f08-00aa002f954e\}(?:\\|$)");
let RelativePathPattern = @"\{645ff040-5081-101b-9f08-00aa002f954e\}\\(.*)$";
let ShellCommandPattern = @"^shell\\[^\\]+\\command$";
let HandlerPattern = @"^shellex\\(?:contextmenuhandlers|dragdrophandlers)(?:\\|$)";
let ScriptHostPattern = @"(?:^|[\\/\s""'])(?:powershell|pwsh|cmd|wscript|cscript|mshta|rundll32|regsvr32)(?:\.exe)?(?:[\s""']|$)";
let WritablePathPattern = @"(?:\\(?:appdata|programdata|temp|tmp|users\\public)(?:\\|$)|%(?:appdata|localappdata|programdata|temp|tmp|userprofile)%|\\downloads(?:\\|$))";
let ScriptPattern = @"\.(?:ps1|vbs|vbe|js|jse|hta|bat|cmd|wsf|wsh)(?:[\s""']|$)";
DeviceRegistryEvents
| where Timestamp >= ago(Lookback)
| where RegistryKey contains RecycleBinClsid or PreviousRegistryKey contains RecycleBinClsid
| extend KeyLower = tolower(trim_end(@"\\+", RegistryKey)),
		 PreviousKeyLower = tolower(trim_end(@"\\+", PreviousRegistryKey)),
		 ValueNameLower = tolower(RegistryValueName),
		 ValueData = trim(@"\s+", RegistryValueData)
| extend IsCurrentRecycleKey = KeyLower matches regex RecyclePathPattern,
		 IsPreviousRecycleKey = PreviousKeyLower matches regex RecyclePathPattern
| where IsCurrentRecycleKey or IsPreviousRecycleKey
| extend RelativeKey = extract(RelativePathPattern, 1, KeyLower),
		 PreviousRelativeKey = extract(RelativePathPattern, 1, PreviousKeyLower)
| extend IsDefaultValue = ValueNameLower in ("", "(default)", "@"),
		 IsShellCommand = IsCurrentRecycleKey and RelativeKey matches regex ShellCommandPattern,
		 IsHandlerKey = IsCurrentRecycleKey and RelativeKey matches regex HandlerPattern,
		 IsShellTree = (IsCurrentRecycleKey and (RelativeKey == "shell" or RelativeKey startswith @"shell\"))
					   or (IsPreviousRecycleKey and (PreviousRelativeKey == "shell" or PreviousRelativeKey startswith @"shell\")),
		 DataLower = tolower(ValueData)
| extend IsCommandWrite = ActionType == "RegistryValueSet" and IsShellCommand and IsDefaultValue and isnotempty(ValueData),
		 IsDelegateWrite = ActionType == "RegistryValueSet" and IsShellCommand and ValueNameLower == "delegateexecute" and isnotempty(ValueData),
		 IsHandlerWrite = ActionType == "RegistryValueSet" and IsHandlerKey and isnotempty(ValueData),
		 IsShellKeyChange = ActionType in ("RegistryKeyCreated", "RegistryKeyRenamed") and IsShellTree,
		 HasScriptHost = DataLower matches regex ScriptHostPattern,
		 HasWritablePath = DataLower matches regex WritablePathPattern,
		 HasScriptFile = DataLower matches regex ScriptPattern
| extend DetectionClass = case(
			 IsCommandWrite, "RecycleBinShellCommandWrite",
			 IsDelegateWrite, "RecycleBinDelegateExecuteChange",
			 IsHandlerWrite, "RecycleBinShellExtensionChange",
			 IsShellKeyChange, "RecycleBinShellKeyChange",
			 ""),
		 Confidence = iff(IsCommandWrite, "High", "Hunting")
| where IsCommandWrite or (IncludeHuntingSignals and isnotempty(DetectionClass))
| extend DetectionReason = case(
			 IsCommandWrite and HasScriptHost, "Non-empty default command invokes a script host or LOLBin",
			 IsCommandWrite and HasWritablePath, "Non-empty default command references a commonly writable location",
			 IsCommandWrite and HasScriptFile, "Non-empty default command references a script",
			 IsCommandWrite, "Non-empty default command on a Recycle Bin shell verb",
			 IsDelegateWrite, "DelegateExecute changed; resolve the referenced COM class before escalation",
			 IsHandlerWrite, "Shell extension changed; resolve the COM class and its DLL before escalation",
			 "Shell key created or renamed; command execution is not established"),
		 ShellVerb = extract(@"^shell\\([^\\]+)", 1, RelativeKey),
		 TargetTextMentionsSystem32 = DataLower contains @"\windows\system32\" or DataLower contains @"%systemroot%\system32\" or DataLower contains @"%windir%\system32\",
		 MitreTechnique = "T1546.015"
| project Timestamp, DeviceId, DeviceName, ReportId, Confidence, DetectionClass,
		  DetectionReason, MitreTechnique, ActionType, ShellVerb,
		  RegistryKey, RegistryValueName, RegistryValueType, RegistryValueData,
		  PreviousRegistryKey, PreviousRegistryValueData,
		  HasScriptHost, HasWritablePath, HasScriptFile, TargetTextMentionsSystem32,
		  InitiatingProcessAccountDomain, InitiatingProcessAccountName,
		  InitiatingProcessAccountSid, InitiatingProcessFileName,
		  InitiatingProcessFolderPath, InitiatingProcessCommandLine,
		  InitiatingProcessParentFileName, InitiatingProcessSHA1,
		  InitiatingProcessId, InitiatingProcessCreationTime
| order by Timestamp desc


```
