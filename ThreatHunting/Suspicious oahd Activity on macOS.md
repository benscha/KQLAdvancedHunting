# *Suspicious oahd Activity on macOS*

## Query Information

#### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1543.001 | Launch Agent | https://attack.mitre.org/techniques/T1543/001|


#### Description

This rule detects suspicious activities related to the 'oahd' process on macOS, which could indicate persistence mechanisms or execution of malicious code. It correlates file events (creation/modification of oahd-related files or plist manipulation) with subsequent process execution of 'oahd' outside its legitimate path, with suspicious parent processes, or with suspicious command-line arguments. Specifically, it looks for writes to the Rosetta Translation Cache, creation of a fake 'oahd' binary outside '/usr/libexec', manipulation of 'com.apple.oahd.plist' outside standard LaunchDaemon paths, and 'oahd' process execution from non-legitimate paths, with non-standard parent processes (not 'launchd' or 'xpcproxy'), or with command-line arguments pointing to suspicious locations like /tmp, /Users/Shared, /var/tmp, or containing URLs.

#### Author <Optional>
- **Name: Benjamin Zulliger**
- **Github: https://github.com/benscha/KQLAdvancedHunting**
- **LinkedIn: https://www.linkedin.com/in/benjamin-zulliger/**

#### Possible false positives
- Legitimate software updates or installations that temporarily write to unusual locations or modify system files in non-standard ways.
- Custom scripts or administrative tools that interact with 'oahd' or its related files for legitimate system management or debugging purposes.
- Development or testing environments where non-standard configurations or file paths are used for 'oahd' or related services.
- Rosetta 2 translation cache writes for legitimate applications, if the rule's logic for cache writes is too broad.

## Defender XDR
```KQL
let SuspiciousOahdFileEvents = 
	DeviceFileEvents
	| where
		// Writes in den Rosetta Translation Cache
		(FolderPath startswith "/var/db/oah/" and ActionType in ("FileCreated", "FileModified"))
		// Drop einer gefakten oahd-Binary ausserhalb des legitimen Pfads
		or (FileName =~ "oahd" and FolderPath !startswith "/usr/libexec")
		// Manipulation der LaunchDaemon plist
		or (FileName =~ "com.apple.oahd.plist"
			and FolderPath !in ("/System/Library/LaunchDaemons/", "/Library/LaunchDaemons/"))
	| extend
		IsCacheWrite = FolderPath startswith "/var/db/oah/",
		IsFakeBinary = FileName =~ "oahd" and FolderPath !startswith "/usr/libexec",
		IsPlistHijack = FileName =~ "com.apple.oahd.plist"
			and FolderPath !in ("/System/Library/LaunchDaemons/", "/Library/LaunchDaemons/")
	| project
		TimeGenerated,
		DeviceName,
		ActionType,
		FileName,
		FolderPath,
		InitiatingProcessFileName,
		InitiatingProcessFolderPath,
		InitiatingProcessCommandLine,
		InitiatingProcessAccountName,
		IsCacheWrite,
		IsFakeBinary,
		IsPlistHijack;
let SuspiciousOahdProcessEvents =
	DeviceProcessEvents
	| where FileName =~ "oahd"
		or ProcessCommandLine has "com.apple.oahd"
	| extend
		IsLegitPath = FolderPath startswith "/usr/libexec/oahd"
			or FolderPath =~ "/usr/libexec/oahd",
		IsSuspiciousParent = InitiatingProcessFileName !in~ ("launchd", "xpcproxy"),
		HasSuspiciousArgs = ProcessCommandLine has_any (
			"/tmp/", "/Users/Shared/", "/var/tmp/", "../", "http://", "https://"),
		IsSuspiciousCachePath = ProcessCommandLine has "/var/db/oah/"
			and not(ProcessCommandLine has "/var/db/oah/com.apple")
	| where not(IsLegitPath)
		or IsSuspiciousParent
		or HasSuspiciousArgs
		or IsSuspiciousCachePath
	| project
		TimeGenerated,
		DeviceName,
		FileName,
		FolderPath,
		ProcessCommandLine,
		InitiatingProcessFileName,
		InitiatingProcessFolderPath,
		InitiatingProcessCommandLine,
		AccountName,
		IsLegitPath,
		IsSuspiciousParent,
		HasSuspiciousArgs,
		IsSuspiciousCachePath;
// Korrelation: File-Event gefolgt von Process-Event auf demselben Device
SuspiciousOahdFileEvents
| join kind=inner (
	SuspiciousOahdProcessEvents
	| project-rename ProcessTime = TimeGenerated
) on DeviceName
| where ProcessTime between (TimeGenerated .. (TimeGenerated + 15m))
| project
	FileEventTime = TimeGenerated,
	ProcessEventTime = ProcessTime,
	DeviceName,
	// File-Side
	ActionType,
	AffectedFile = strcat(FolderPath, FileName),
	IsCacheWrite,
	IsFakeBinary,
	IsPlistHijack,
	FileInitiator = InitiatingProcessFileName,
	FileInitiatorPath = InitiatingProcessFolderPath,
	FileInitiatorCmdLine = InitiatingProcessCommandLine,
	DroppingAccountName = InitiatingProcessAccountName,
	// Process-Side
	SpawnedBinary = strcat(FolderPath1, FileName1),
	SpawnCmdLine = ProcessCommandLine,
	SpawnParent = InitiatingProcessFileName1,
	SpawnParentPath = InitiatingProcessFolderPath1,
	SpawnParentCmdLine = InitiatingProcessCommandLine1,
	SpawnAccountName = AccountName,
	// Flags
	IsLegitPath,
	IsSuspiciousParent,
	HasSuspiciousArgs,
	IsSuspiciousCachePath
| sort by FileEventTime desc
```
