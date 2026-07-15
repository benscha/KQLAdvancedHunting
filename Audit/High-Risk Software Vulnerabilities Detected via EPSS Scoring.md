# *High-Risk Software Vulnerabilities Detected via EPSS Scoring*

## Query Information

#### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1190  | Exploit Public-Facing Application | https://attack.mitre.org/techniques/T1190/ |
| T1203  | Exploitation for Client Execution | https://attack.mitre.org/techniques/T1203/ |
| T1068  | Exploitation for Privilege Escalation | https://attack.mitre.org/techniques/T1068/ |


#### Description
This Audit rule identifies software installed on endpoints that is associated with known vulnerabilities, specifically filtering for vulnerabilities with an Exploit Prediction Scoring System (EPSS) score of 0.20 or higher. The rule correlates vulnerable software instances with their installation paths and registry keys, facilitating prioritization of patching and remediation efforts for high-risk exposures.

If you are looking for additional Informations as the EUVD please have a look on this Repo: https://github.com/benscha/EUVD2LogAnalytics/tree/main

#### Author <Optional>
- **Name: Benjamin Zulliger**
- **Github: https://github.com/benscha/KQLAdvancedHunting**
- **LinkedIn: https://www.linkedin.com/in/benjamin-zulliger/**

#### References

## Defender XDR
```KQL
// Lists all vulnerabilities with an EPSS score above the defined threshold,
// enriched with installation paths and registry keys from the evidence table.
let EpssThreshold = 0.20;
// Load CVE metadata from the knowledge base
let KbData = DeviceTvmSoftwareVulnerabilitiesKB
    | where isnotempty(CveId)
    | project
        CveId,
        CvssScore,
        EpssScore,
        IsExploitAvailable,
        PublishedDate,
        VulnerabilitySeverityLevel;
// Filter affected devices to those with EPSS above the threshold
let FilteredVulns = DeviceTvmSoftwareVulnerabilities
    | where isnotempty(CveId)
    | join kind=inner KbData on CveId
    | where EpssScore >= EpssThreshold
    | project
        DeviceId,
        DeviceName,
        CveId,
        EpssScore                   = round(EpssScore * 100, 2),
        CvssScore,
        VulnerabilitySeverityLevel,
        IsExploitAvailable,
        SoftwareName,
        SoftwareVersion,
        SoftwareVendor,
        RecommendedSecurityUpdate,
        RecommendedSecurityUpdateId,
        PublishedDate,
        OSPlatform,
        OSVersion;
// Restrict evidence lookup to affected devices only for better performance
let AffectedDeviceIds = FilteredVulns | distinct DeviceId;
let EvidenceData = DeviceTvmSoftwareEvidenceBeta
    | where DeviceId in (AffectedDeviceIds)
    | project
        DeviceId,
        SoftwareName,
        SoftwareVersion,
        SoftwareVendor,
        DiskPaths,
        RegistryPaths;
FilteredVulns
| join kind=leftouter EvidenceData on DeviceId, SoftwareName, SoftwareVersion, SoftwareVendor
| project-away
    DeviceId,
    DeviceId1,
    SoftwareName1,
    SoftwareVersion1,
    SoftwareVendor1
| sort by EpssScore desc, CvssScore desc
```
