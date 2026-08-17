# *Suspicious Windows Defender Exclusion Added for Uncommon Files*

## Query Information

#### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1685	| Disable or Modify Tools | https://attack.mitre.org/techniques/T1685/ |
| T1564.012	| File/Path Exclusions	| https://attack.mitre.org/techniques/T1564/012/ | 


#### Description
This rule detects the addition of new exclusions to Windows Defender settings for files that are not globally prevalent. It monitors registry modifications related to Windows Defender exclusions, excludes known benign processes, and cross-references the excluded file name against recently observed file hashes and their global prevalence. This behavior is indicative of an attacker attempting to whitelist malicious binaries or scripts to evade security scanning.

#### Risk
Defense Evasion

#### Author <Optional>
- **Name: Benjamin Zulliger**
- **Github: https://github.com/benscha/KQLAdvancedHunting**
- **LinkedIn: https://www.linkedin.com/in/benjamin-zulliger/**

#### References
- Thx to Maurice Fielenbach for his Post: https://www.linkedin.com/posts/mauricefielenbach_threatintel-cybersecurity-blueteam-share-7489379589341786113-GwLN/?utm_source=share&utm_medium=member_desktop&rcm=ACoAAA3PxAIBcfr6M0unx3xMtHTyCNuehMi3uNQ
## Defender XDR
```KQL
let RegLookback          = 7d;
let FileLookback         = 30d;
let MinGlobalPrevalence  = 2500;
let MinGlobalAge         = 10d;
let TargetRegistryKeys = dynamic([
    @"SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions",
    @"SOFTWARE\Microsoft\Windows Defender\Exclusions"
]);
let LegitimateProcesses = dynamic(["MsMpEng.exe", "NisSrv.exe"]);
let ThereforePdfRegex = @"(?i)^(%USERPROFILE%\\AppData\\Local|C:\\Program Files(\s\(x86\))?)\\Therefore\\.*\.pdf$";
let Exclusions = materialize(
    DeviceRegistryEvents
    | where Timestamp > ago(RegLookback)
    | where RegistryKey has_any (TargetRegistryKeys)
    | where ActionType in ("RegistryValueSet", "RegistryKeyCreated")
    | where isnotempty(RegistryValueName)
    | where not(RegistryValueName matches regex ThereforePdfRegex)
    | where not(InitiatingProcessFileName in~ (LegitimateProcesses))
    | extend ExclusionScope   = tostring(split(RegistryKey, @"\")[-1])
    | extend ExcludedFileName = tolower(tostring(split(RegistryValueName, @"\")[-1]))
    | summarize arg_max(Timestamp, *) by RegistryValueName, DeviceId
);
let ExclusionNames = toscalar(
    Exclusions
    | where ExcludedFileName has "." and ExcludedFileName !has "*"
    | summarize make_set(ExcludedFileName, 1000)
);
let HashCandidates = materialize(
    union isfuzzy=true
        (DeviceProcessEvents   | where Timestamp > ago(FileLookback) | project DeviceId, FileName, FolderPath, SHA1, SHA256),
        (DeviceImageLoadEvents | where Timestamp > ago(FileLookback) | project DeviceId, FileName, FolderPath, SHA1, SHA256),
        (DeviceFileEvents      | where Timestamp > ago(FileLookback) | project DeviceId, FileName, FolderPath, SHA1, SHA256)
    | extend ExcludedFileName = tolower(FileName)
    | where ExcludedFileName in (ExclusionNames)
    | where isnotempty(SHA1)
    | summarize LocalDeviceCount = dcount(DeviceId), FolderPathSample = take_any(FolderPath)
        by ExcludedFileName, SHA1, SHA256
);
let Profiles =
    HashCandidates
    | distinct SHA1
    | take 1000
    | invoke FileProfile("SHA1", 1000)
    // Enforce schema explicitly, otherwise it gets lost during the join
    | project SHA1,
        ProfPrevalence   = tolong(GlobalPrevalence),
        ProfFirstSeen    = GlobalFirstSeen,
        ProfSigner       = Signer,
        ProfAvailability = ProfileAvailability;
let HashSets =
    HashCandidates
    | join kind=leftouter (Profiles) on SHA1
    | extend Prevalence     = coalesce(ProfPrevalence, long(0)) 
    | extend FirstObservedG = coalesce(ProfFirstSeen, now())
    // Exclusion criteria: globally widespread OR known for a long time
    | where not(Prevalence >= MinGlobalPrevalence and FirstObservedG <= ago(MinGlobalAge))   
| summarize
        FileHashes        = make_set(SHA1, 50),
        FileHashesSHA256  = make_set(SHA256, 50),
        FolderPaths       = make_set(FolderPathSample, 20),
        Signers           = make_set_if(ProfSigner, isnotempty(ProfSigner), 10),
        ProfileStates     = make_set(ProfAvailability, 5),
        HashCount         = dcount(SHA1),
        MinPrevalence     = min(Prevalence),
        MaxPrevalence     = max(Prevalence),
        FirstObserved     = min(FirstObservedG),
        LocalDeviceCount  = sum(LocalDeviceCount)
        by ExcludedFileName;
Exclusions
| join kind=inner (HashSets) on ExcludedFileName
| project
    Timestamp,
    DeviceName,
    ExclusionScope,
    RegistryValueName,
    ExcludedFileName,
    HashCount,
    FileHashes,
    FileHashesSHA256,
    FolderPaths,
    Signers,
    ProfileStates,
    MinPrevalence,
    MaxPrevalence,
    FirstObserved,
    LocalDeviceCount,
    InitiatingProcessFileName,
    InitiatingProcessAccountName,
    InitiatingProcessCommandLine,
    DeviceId
| order by HashCount desc, Timestamp desc
```

