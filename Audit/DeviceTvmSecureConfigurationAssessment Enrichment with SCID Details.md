# *DeviceTvmSecureConfigurationAssessment Enrichment with SCID Details*

## Query Information

#### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
|  |  |  |

#### Shout out 
A big THX to Kaido Järvemets for the Defender SCID Explorer. His SCID Explorer is the source of my ScidList CSV. The List will be freshly created on every monday
https://docs.kaidojarvemets.com/defender-scid-explorer

#### Description
This Query enriches 'DeviceTvmSecureConfigurationAssessment' data by joining it with an external list of Security Content IDs (SCIDs). The SCID list provides additional context such as platform, configuration name, function, compliant/non-compliant values, and descriptions for security configuration assessments. This helps in better understanding and prioritizing security posture findings.

#### Author <Optional>
- **Name: Benjamin Zulliger**
- **Github: https://github.com/benscha/KQLAdvancedHunting**
- **LinkedIn: https://www.linkedin.com/in/benjamin-zulliger/**

#### References
- https://docs.kaidojarvemets.com/defender-scid-explorer

## Defender XDR
```KQL
//thx to Kaido Järvemets for the Defender SCID Explorer
let ScidList = materialize(externaldata(line: string)
[@"https://raw.githubusercontent.com/benscha/KQLAdvancedHunting/main/MISC/scid.csv?v2"]
with (format="txt")
| where line !startswith "#" and line !startswith "SCID,"
| extend fields = split(line, '","')
| extend
	SCID = trim('"', tostring(fields[0])),
	Platform = trim('"', tostring(fields[1])),
	ConfigurationName = trim('"', tostring(fields[2])),
	Function = trim('"', tostring(fields[3])),
	CompliantValue = trim('"', tostring(fields[4])),
	NonCompliantValue = trim('"', tostring(fields[5])),
	CrossPlatformSCIDs = trim('"', tostring(fields[6])),
	Description = trim('"', tostring(fields[7]))
| project-away line, fields);
DeviceTvmSecureConfigurationAssessment 
| join kind=inner ScidList on $left.ConfigurationId == $right.SCID

```
