# *Infostealer Browser Kill and Verify Sweep from Single Process*

## Query Information

#### MITRE ATT&CK Technique(s)

| Technique ID | Title | Link |
| --- | --- | --- |
| T1555.003 | Credentials from Web Browsers | <https://attack.mitre.org/techniques/T1555/003> |
| T1539 | Steal Web Session Cookie | <https://attack.mitre.org/techniques/T1539> |
| T1555 | Crendentials from Password Stores | <https://attack.mitre.org/techniques/T1555> |

#### Description

This query detects the browser termination sweep that commodity infostealers perform before harvesting credentials and cookies. Browsers keep their credential and cookie databases locked while running, so the stealer terminates them with taskkill, frequently through a burst of short-lived cmd.exe children, and confirms with tasklist that the process is gone before reading the files. The query parses taskkill and tasklist command lines in DeviceProcessEvents for browser image names, also covering renamed binaries via the original file name, and attributes every operation to its root process using process unique IDs, resolving the cmd.exe hop and falling back to parent PID and creation time when the cmd.exe event is missing. Sliding windows anchored on every operation group the activity per root, independent of whether verification happens before or after the kill. A result requires at least three distinct browsers targeted and at least two actually killed within the sweep window. Instead of filtering on the parent location, the root is scored: user-writable path, system binary name outside System32, known injection hosts such as RegAsm, MSBuild or AppLaunch, and missing signature. Together with complete kill and verify pairs this yields a Low, Medium or High confidence. Tune MinBrowserBrands, SweepWindow and ExcludeLowConfidence, and add known updaters or uninstallers to AllowedRootSHA1. Follow up on affected accounts, since stolen sessions are often resold to access brokers and reused for VPN or Entra ID sign-ins.

#### Author

- **Name: Benjamin Zulliger**
- **Github: <https://github.com/benscha/KQLAdvancedHunting>**
- **LinkedIn: <https://www.linkedin.com/in/benjamin-zulliger/>**

#### References

- Linkedin Post Maurice Fielenbach <https://www.linkedin.com/posts/mauricefielenbach_threathunting-dfir-blueteam-share-7516200082061467648-oUj0/?utm_source=share&utm_medium=member_ios&rcm=ACoAAA3PxAIBcfr6M0unx3xMtHTyCNuehMi3uNQ>

## Defender XDR

```KQL
// one root process terminates several browsers with taskkill (often through
// short-lived cmd.exe children) and checks with tasklist that they are gone, to release
// the locked credential and cookie databases before reading them.
let Lookback = 4h;
let ParentContext = 10m;            // cmd.exe may start shortly before the lookback window
let SweepWindow = 2m;               // maximum duration of one sweep
let MinBrowserBrands = 2;           // distinct targets (killed or verified)
let MinKilledBrands = 1;            // distinct targets actually killed
let ExcludeLowConfidence = false;   // true: only Medium and High results
let AllowedRootSHA1 = dynamic([]);  // known good updaters / uninstallers
let BrowserTerms = dynamic(["chrome", "chromium", "brave", "msedge", "opera", "vivaldi",
    "firefox", "browser", "dragon", "iridium", "waterfox", "librewolf", "thunderbird"]);
let RawOps = materialize(
    DeviceProcessEvents
    | where Timestamp >= ago(Lookback)
    | where FileName in~ ("taskkill.exe", "tasklist.exe")
        or ProcessVersionInfoOriginalFileName startswith "taskkill.exe"
        or ProcessVersionInfoOriginalFileName startswith "tasklist.exe"
    | where ProcessCommandLine has_any (BrowserTerms)
    | extend ImageName = tolower(iff(FileName in~ ("taskkill.exe", "tasklist.exe"),
        FileName, ProcessVersionInfoOriginalFileName))
    | extend Operation = iff(ImageName startswith "taskkill", "Kill", "Verify")
    | extend BrowserNames = iff(Operation == "Kill",
        extract_all(@"(?i)[/-]im\s+[""']?(chrome|chromium|brave|msedge|opera|vivaldi|firefox|browser|dragon|iridium|waterfox|librewolf|thunderbird)(?:\.exe|\*)?[""']?(?:\s|$|[&|)])", ProcessCommandLine),
        extract_all(@"(?i)[/-]fi\s+[""']?\s*imagename\s+eq\s+(chrome|chromium|brave|msedge|opera|vivaldi|firefox|browser|dragon|iridium|waterfox|librewolf|thunderbird)(?:\.exe|\*)?[""']?(?:\s|$|[&|)])", ProcessCommandLine))
    | where array_length(BrowserNames) > 0
    | mv-expand Browser = BrowserNames to typeof(string)
    | extend Browser = tolower(Browser),
        ViaCmd = InitiatingProcessFileName =~ "cmd.exe"
            or InitiatingProcessVersionInfoOriginalFileName startswith "cmd.exe",
        CmdKey = tostring(InitiatingProcessUniqueId)
);
// Resolve only the cmd.exe instances that are actually needed (semi-join)
let NeededCmdKeys =
    RawOps
    | where ViaCmd and isnotempty(CmdKey)
    | distinct DeviceId, CmdKey;
let CmdParents =
    DeviceProcessEvents
    | where Timestamp >= ago(Lookback + ParentContext)
    | where FileName =~ "cmd.exe" or ProcessVersionInfoOriginalFileName startswith "cmd.exe"
    | extend CmdKey = tostring(ProcessUniqueId)
    | join kind=inner NeededCmdKeys on DeviceId, CmdKey
    | project DeviceId, CmdKey,
        CmdRootKey = tostring(InitiatingProcessUniqueId),
        CmdRootFileName = InitiatingProcessFileName,
        CmdRootFolderPath = InitiatingProcessFolderPath,
        CmdRootCommandLine = InitiatingProcessCommandLine,
        CmdRootSHA1 = InitiatingProcessSHA1,
        CmdRootProcessId = InitiatingProcessId,
        CmdRootCreationTime = InitiatingProcessCreationTime,
        CmdRootSignatureStatus = InitiatingProcessSignatureStatus
    | summarize take_any(*) by DeviceId, CmdKey;
let Operations = materialize(
    RawOps
    | join kind=leftouter CmdParents on DeviceId, CmdKey
    | extend ResolvedRoot = iff(ViaCmd, CmdRootKey, tostring(InitiatingProcessUniqueId))
    | extend ParentResolved = isnotempty(ResolvedRoot)
    | extend FallbackPid = iff(ViaCmd, InitiatingProcessParentId, InitiatingProcessId),
        FallbackTime = iff(ViaCmd, InitiatingProcessParentCreationTime, InitiatingProcessCreationTime)
    // Do not merge unrelated processes when no attribution is possible.
    | extend RootKey = case(
        ParentResolved, ResolvedRoot,
        FallbackPid > 0 and isnotnull(FallbackTime), strcat("pp:", FallbackPid, "|", FallbackTime),
        "")
    | where isnotempty(RootKey)
    | extend
        RootFileName = case(not(ViaCmd), InitiatingProcessFileName,
            ParentResolved, CmdRootFileName, InitiatingProcessParentFileName),
        RootFolderPath = case(not(ViaCmd), InitiatingProcessFolderPath,
            ParentResolved, CmdRootFolderPath, ""),
        RootCommandLine = case(not(ViaCmd), InitiatingProcessCommandLine,
            ParentResolved, CmdRootCommandLine, ""),
        RootSHA1 = case(not(ViaCmd), InitiatingProcessSHA1,
            ParentResolved, CmdRootSHA1, ""),
        RootProcessId = case(not(ViaCmd), InitiatingProcessId,
            ParentResolved, CmdRootProcessId, InitiatingProcessParentId),
        RootCreationTime = case(not(ViaCmd), InitiatingProcessCreationTime,
            ParentResolved, CmdRootCreationTime, InitiatingProcessParentCreationTime),
        RootSignatureStatus = case(not(ViaCmd), InitiatingProcessSignatureStatus,
            ParentResolved, CmdRootSignatureStatus, "")
    | where isempty(RootSHA1) or RootSHA1 !in (AllowedRootSHA1)
    | extend UserWritableLocation = RootFolderPath matches regex
        @"(?i)^(?:[a-z]:\\(?:users|programdata|windows\\temp|windows\\tasks|windows\\tracing|perflogs|\$recycle\.bin)\\|\\\\)"
    | extend SystemNameOutsideSystemDirectory =
        RootFileName in~ (
            "svchost.exe", "lsass.exe", "services.exe", "winlogon.exe",
            "csrss.exe", "smss.exe", "wininit.exe", "dwm.exe", "spoolsv.exe",
            "rundll32.exe", "regsvr32.exe", "conhost.exe", "dllhost.exe",
            "taskhostw.exe", "cmd.exe", "powershell.exe", "explorer.exe")
        and isnotempty(RootFolderPath)
        and not(RootFolderPath matches regex @"(?i)^[a-z]:\\windows\\(?:system32|syswow64)\\")
        and not(RootFileName =~ "explorer.exe" and RootFolderPath matches regex @"(?i)^[a-z]:\\windows\\explorer\.exe$")
    // Common injection / proxy hosts used by commodity stealers
    | extend KnownStealerHost = RootFileName in~ (
            "regasm.exe", "regsvcs.exe", "msbuild.exe", "applaunch.exe", "installutil.exe",
            "aspnet_compiler.exe", "rundll32.exe", "regsvr32.exe", "mshta.exe",
            "wscript.exe", "cscript.exe", "powershell.exe", "pwsh.exe")
    | extend UnsignedRoot = isnotempty(RootSignatureStatus)
        and RootSignatureStatus !in~ ("Valid", "Unknown")
    | project Timestamp, DeviceId, DeviceName, ReportId, Operation, Browser, ImageName,
        ProcessCommandLine, RootKey, ParentResolved, RootFileName, RootFolderPath,
        RootCommandLine, RootSHA1, RootProcessId, RootCreationTime, RootSignatureStatus,
        UserWritableLocation, SystemNameOutsideSystemDirectory, KnownStealerHost, UnsignedRoot,
        AccountDomain, AccountName, AccountSid
);
let Anchors =
    Operations
    | project DeviceId, RootKey, AnchorTime = Timestamp
    | distinct DeviceId, RootKey, AnchorTime;
Operations
| join kind=inner Anchors on DeviceId, RootKey
| where Timestamp between (AnchorTime .. (AnchorTime + SweepWindow))
| summarize
    Killed = make_set_if(Browser, Operation == "Kill", 16),
    Verified = make_set_if(Browser, Operation == "Verify", 16),
    SweepStart = min(Timestamp),
    SweepEnd = max(Timestamp),
    OperationCount = count(),
    Accounts = make_set(strcat(AccountDomain, @"\", AccountName), 8),
    Evidence = make_set(bag_pack(
        "op", Operation, "browser", Browser, "time", Timestamp,
        "image", ImageName, "cmd", ProcessCommandLine), 40),
    arg_max(Timestamp, ReportId, DeviceName, ParentResolved,
        RootFileName, RootFolderPath, RootCommandLine, RootSHA1,
        RootProcessId, RootCreationTime, RootSignatureStatus,
        UserWritableLocation, SystemNameOutsideSystemDirectory, KnownStealerHost, UnsignedRoot,
        AccountDomain, AccountName, AccountSid)
    by DeviceId, RootKey, AnchorTime
| extend Brands = set_union(Killed, Verified), Paired = set_intersect(Killed, Verified)
| extend BrandCount = array_length(Brands),
    KilledCount = array_length(Killed),
    PairedCount = array_length(Paired)
| where BrandCount >= MinBrowserBrands and KilledCount >= MinKilledBrands
| extend RootScore = iff(UserWritableLocation, 1, 0)
    + iff(SystemNameOutsideSystemDirectory, 1, 0)
    + iff(KnownStealerHost, 1, 0)
    + iff(UnsignedRoot, 1, 0)
| extend Confidence = case(
    PairedCount >= MinBrowserBrands and RootScore > 0, "High",
    PairedCount >= MinBrowserBrands or RootScore > 0, "Medium",
    "Low")
| where not(ExcludeLowConfidence and Confidence == "Low")
// One result per root process: keep the widest sweep
| summarize arg_max(BrandCount, *) by DeviceId, RootKey
| project Timestamp, DeviceId, DeviceName, ReportId,
    Confidence, RootScore, BrandCount, KilledCount, PairedCount,
    Brands, Killed, Verified, Paired, SweepStart, SweepEnd, OperationCount,
    RootKey, ParentResolved, RootProcessId, RootCreationTime,
    RootFileName, RootFolderPath, RootCommandLine, RootSHA1, RootSignatureStatus,
    UserWritableLocation, SystemNameOutsideSystemDirectory, KnownStealerHost, UnsignedRoot,
    AccountDomain, AccountName, AccountSid, Accounts, Evidence
```
