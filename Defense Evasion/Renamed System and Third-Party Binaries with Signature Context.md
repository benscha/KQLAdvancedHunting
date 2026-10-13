# *Renamed System and Third-Party Binaries with Signature Context*

## Query Information

#### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1036.003 | Masquerading: Rename Legitimate Utilities | https://attack.mitre.org/techniques/T1036/003 |



#### Description

This query detects process creations in Microsoft Defender for Endpoint where the executed file name differs from the original file name stored in the PE metadata. Attackers frequently rename legitimate utilities to blend in or to evade name based detections, for example by running a copy of certutil.exe, rclone.exe or a Python interpreter under an unrelated name. The query compares the lowercased FileName with ProcessVersionInfoOriginalFileName and classifies matches into four categories: Renamed Python, Renamed Command Interpreter, Renamed Third-Party Software (remote access tools, archivers, tunneling and scanning tools) and Renamed LOLBAS.

To keep the query efficient, a cheap inequality filter removes the vast majority of events before any regex or list comparison runs. Known legitimate variants are excluded, such as the PsExec architecture variants, regular Python launchers and exception pairs of original and executed name. Exceptions are bound to the exact combination of both names, so a renamed binary cannot hide behind an unrelated allowlisted name.

Matches are then enriched with signature information from DeviceFileCertificateInfo via the SHA1 hash, using a longer lookback because certificate data can arrive later than the process event. The result contains the signing status, signer and issuer, and a severity: unsigned or untrusted files rate High, missing certificate data and signed LOLBAS or interpreters rate Medium, everything else Low. The signature is context and not a filter, because many LOLBAS are signed by Microsoft. Tune the lookback values and the AllowedPairs list using a baseline over 30 days. Binaries without PE metadata or with a modified original file name are a blind spot of this approach.

#### Author 
- **Name: Benjamin Zulliger**
- **Github: https://github.com/benscha/KQLAdvancedHunting**
- **LinkedIn: https://www.linkedin.com/in/benjamin-zulliger/**


## Defender XDR
```KQL
// Renamed binaries: Python, command interpreters, third-party software, LOLBAS
// Detects processes whose executed file name differs from the PE OriginalFileName
// and enriches them with signature information from DeviceFileCertificateInfo.

let Lookback = 24h;
// Certificate data can arrive later than the process event, so a larger window is used
let CertLookback = 30d;

let CommandInterpreterNames = dynamic([
    "bash.exe", "cmd.exe", "powershell.exe", "powershell_ise.exe",
    "pwsh.exe", "pwsh.dll", "sh.exe",
    "windowsterminal.exe", "wsl.exe", "wt.exe"
]);
// Covers psexec.exe, psexec64.exe, psexec64a.exe and similar
let CommandInterpreterWildcardRegex = @"^psexec.*\.(?:exe|c)$";

let ThirdPartyNames = dynamic([
    "7z.exe", "7zg.exe", "7zfm.exe", "7za.exe",
    "rar.exe", "unrar.exe", "peazip.exe", "anydesk.exe",
    "tv_w32.exe", "tv_x64.exe", "ateraagent.exe", "srserver.exe",
    "splashtopstreamer.exe", "lmiguardiansvc.exe", "logmein.exe",
    "basupsrvc.exe", "tcclient.exe", "action1_agent.exe",
    "rutserv.exe", "rfusclient.exe", "netscan.exe", "ipscan.exe",
    "processhacker.exe", "systeminformer.exe", "rclone.exe",
    "plink.exe", "mobaxterm.exe", "ngrok.exe", "cloudflared.exe",
    "chisel.exe", "webbrowserpassview.exe", "mailpv.exe",
    "autoit3.exe", "aut2exe.exe"
]);
let ThirdPartyWildcardRegex =
    @"^(?:winrar.*|teamviewer.*|screenconnect.*|advanced_ip_scanner.*|advanced_port_scanner.*|adfind.*|winscp.*|putty.*)\.exe$";

let LolbasNames = dynamic([
    "acccheckconsole.exe", "addinutil.exe", "adplus.exe",
    "agentexecutor.exe", "appcert.exe", "appinstaller.exe",
    "appvlp.exe", "aspnet_compiler.exe", "at.exe", "atbroker.exe",
    "bitsadmin.exe", "cdb.exe", "certoc.exe", "certreq.exe",
    "certutil.exe", "cmdkey.exe", "cmdl32.exe", "cmstp.exe",
    "colorcpl.exe", "conhost.exe", "control.exe", "csc.exe",
    "cscript.exe", "csi.exe", "curl.exe", "customshellhost.exe",
    "datasvcutil.exe", "desktopimgdownldr.exe",
    "devicecredentialdeployment.exe", "devinit.exe",
    "devtoolslauncher.exe", "dfsvc.exe", "diantz.exe",
    "diskshadow.exe", "dnscmd.exe", "dotnet.exe", "dsdbutil.exe",
    "dumpminitool.exe", "dxcap.exe", "esentutl.exe",
    "eventvwr.exe", "excel.exe", "expand.exe", "extexport.exe",
    "extrac32.exe", "findstr.exe", "finger.exe", "fltmc.exe",
    "forfiles.exe", "fsi.exe", "fsianycpu.exe", "fsutil.exe",
    "ftp.exe", "gfxdownloadwrapper.exe", "gpscript.exe", "hh.exe",
    "ie4uinit.exe", "iediagcmd.exe", "ieexec.exe", "ilasm.exe",
    "imewdbld.exe", "infdefaultinstall.exe", "installutil.exe",
    "jsc.exe", "ldifde.exe", "makecab.exe", "manage-bde.wsf",
    "mavinject.exe", "mftrace.exe",
    "microsoft.nodejstools.pressanykey.exe",
    "microsoft.workflow.compiler.exe", "mmc.exe", "msaccess.exe",
    "msbuild.exe", "msconfig.exe", "msdeploy.exe", "msdt.exe",
    "mshta.exe", "msiexec.exe", "msohtmed.exe", "mspub.exe",
    "netsh.exe", "ntdsutil.exe", "odbcconf.exe",
    "offlinescannershell.exe", "pcalua.exe", "pcwrun.exe",
    "pktmon.exe", "pnputil.exe", "powerpnt.exe",
    "presentationhost.exe", "print.exe", "printbrm.exe",
    "protocolhandler.exe", "provlaunch.exe", "psr.exe",
    "rasautou.exe", "rdrleakdiag.exe", "reg.exe", "regasm.exe",
    "regedit.exe", "regini.exe", "register-cimprovider.exe",
    "regsvcs.exe", "regsvr32.exe", "replace.exe", "rpcping.exe",
    "rundll32.exe", "runexehelper.exe", "runonce.exe", "sc.exe",
    "schtasks.exe", "scriptrunner.exe", "setres.exe",
    "settingsynchost.exe", "sqldumper.exe", "sqlps.exe",
    "sqltoolsps.exe", "stordiag.exe", "syncappvpublishingserver.exe",
    "tar.exe", "testwindowremoteagent.exe", "ttdinject.exe",
    "tttracer.exe", "unregmp2.exe", "vbc.exe", "verclsid.exe",
    "visualuiaverifynative.exe", "vsdiagnostics.exe", "vshadow.exe",
    "vsiisexelauncher.exe", "vsjitdebugger.exe", "vsls-agent.exe",
    "vstest.console.exe", "wab.exe", "wbadmin.exe", "wfc.exe",
    "winproj.exe", "winword.exe", "wlrmdr.exe", "wmic.exe",
    "workfolders.exe", "wscript.exe", "wsreset.exe", "wuauclt.exe",
    "xwizard.exe"
]);

let PythonOriginalRegex =
    @"^(?:py|pyw|python|pythonw|python32|python64|pythonw32|pythonw64|ipyw32|ipyw64|python3|pythonw3|python3\.\w+|pythonw3\.\w+)\.exe$";
let PythonAllowedNameRegex =
    @"^(?:py|pyw|pip|pip3|python|pythonw|python32|python64|pythonw32|pythonw64|ipyw32|ipyw64|python3|pythonw3|python3\.\w+|pythonw3\.\w+|pip3\.\w+|idle3\.\w+)\.exe$";

// Exceptions as pairs "OriginalName|ExecutedName": they only apply to exactly this combination.
// Verify the pairs against your own data with the baseline query at the end.
let AllowedPairs = dynamic([
    "excel.exe|excelcnv.exe",
    "installutil.exe|installutil64.exe",
    "vshadow.exe|vzshadow.exe",
    "python.exe|dwagent.exe",
    "python.exe|winutils.exe"
]);
// Original name unknown: move these into AllowedPairs after a baseline run and remove them here
let AllowedExecutedNameOnly = dynamic(["regwrite.exe", "protoc~1.exe"]);

// Determine candidates (cheap filters first, expensive regex operations afterwards)
let Candidates = materialize(
    DeviceProcessEvents
    | where Timestamp >= ago(Lookback)
    | where ActionType == "ProcessCreated"
    | where isnotempty(FileName) and isnotempty(ProcessVersionInfoOriginalFileName)
    // Pre-filter: for the vast majority of events both names are identical (case-insensitive)
    | where FileName !~ ProcessVersionInfoOriginalFileName
    | extend
        OriginalName = tolower(ProcessVersionInfoOriginalFileName),
        ExecutedName = tolower(FileName)
    | extend DetectionCategory = case(
        OriginalName matches regex PythonOriginalRegex,
            "Renamed Python",
        OriginalName in (CommandInterpreterNames)
            or OriginalName matches regex CommandInterpreterWildcardRegex,
            "Renamed Command Interpreter",
        OriginalName in (ThirdPartyNames)
            or OriginalName matches regex ThirdPartyWildcardRegex,
            "Renamed Third-Party Software",
        OriginalName in (LolbasNames),
            "Renamed LOLBAS",
        ""
    )
    | where isnotempty(DetectionCategory)
    // PE metadata sometimes contains a source or DLL name
    | extend ExpectedName = case(
        OriginalName == "pwsh.dll", "pwsh.exe",
        OriginalName matches regex @"^psexec.*\.c$",
            replace_regex(OriginalName, @"\.c$", ".exe"),
        OriginalName
    )
    | where ExecutedName != ExpectedName
    // Accept regular PsExec architecture variants only for PsExec original metadata
    | where not(
        DetectionCategory == "Renamed Command Interpreter"
        and OriginalName matches regex CommandInterpreterWildcardRegex
        and ExecutedName in ("psexec.exe", "psexec64.exe", "psexec64a.exe")
    )
    // Regular Python launchers and tools, only within the Python category
    | where not(
        DetectionCategory == "Renamed Python"
        and ExecutedName matches regex PythonAllowedNameRegex
    )
    // Exceptions bound to the combination of original and executed name
    | extend Pair = strcat(OriginalName, "|", ExecutedName)
    | where Pair !in (AllowedPairs)
    | where ExecutedName !in (AllowedExecutedNameOnly)
    | project-away Pair
);
// Load signature information only for the hashes found (small join set)
let CandidateHashes = Candidates
    | where isnotempty(SHA1)
    | distinct SHA1;
let CertInfo = DeviceFileCertificateInfo
    | where Timestamp >= ago(CertLookback)
    | where SHA1 in (CandidateHashes)
    | summarize arg_max(Timestamp, IsSigned, IsTrusted, SignatureType, Signer, Issuer) by SHA1;
// Enrich and rate
Candidates
| join kind=leftouter CertInfo on SHA1
| extend SigningStatus = case(
    isnull(IsSigned),                        "Unknown (no certificate data)",
    IsSigned == false,                       "Unsigned",
    IsSigned == true and IsTrusted == false, "Signed, not trusted",
    "Signed and trusted"
)
// The signature is context, not a filter: LOLBAS binaries are signed by Microsoft,
// so a renamed certutil.exe stays suspicious even when it is signed.
| extend Severity = case(
    SigningStatus in ("Unsigned", "Signed, not trusted"), "High",
    SigningStatus startswith "Unknown",                   "Medium",
    DetectionCategory in ("Renamed LOLBAS", "Renamed Command Interpreter"), "Medium",
    "Low"
)
| project
    Timestamp,
    DeviceId,
    DeviceName,
    ReportId,
    Severity,
    DetectionCategory,
    SigningStatus,
    Signer,
    Issuer,
    SignatureType,
    FileName,
    ProcessVersionInfoOriginalFileName,
    ExpectedName,
    FolderPath,
    ProcessCommandLine,
    ProcessId,
    AccountDomain,
    AccountName,
    AccountSid,
    ProcessIntegrityLevel,
    ProcessTokenElevation,
    InitiatingProcessFileName,
    InitiatingProcessCommandLine,
    InitiatingProcessFolderPath,
    InitiatingProcessAccountName,
    SHA1,
    SHA256
| extend SeverityRank = case(Severity == "High", 1, Severity == "Medium", 2, 3)
| order by SeverityRank asc, Timestamp desc
| project-away SeverityRank

// Baseline query (run separately with a lookback of e.g. 30d to maintain AllowedPairs):
// Use the same query up to "| where ExecutedName !in (AllowedExecutedNameOnly)" without the exceptions, then:
// | summarize Events = count(), Devices = dcount(DeviceId)
//     by DetectionCategory, OriginalName, ExecutedName
// | order by Events desc
```
