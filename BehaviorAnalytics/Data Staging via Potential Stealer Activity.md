# *Data Staging via Potential Stealer Activity*

## Query Information

#### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1005 | Data from Local System | https://attack.mitre.org/techniques/T1005/ |
| T1083 | File and Directory Discovery | https://attack.mitre.org/techniques/T1083/ |
| T1555.003 | Credentials from Web Browsers | https://attack.mitre.org/techniques/T1555/003/ |

#### Description

Detects the creation of multiple files associated with password-stealing malware behavior within a short window, suggesting data staging for potential exfiltration.

#### Author <Optional>
- **Name: Benjamin Zulliger**
- **Github: https://github.com/benscha/KQLAdvancedHunting**
- **LinkedIn: https://www.linkedin.com/in/benjamin-zulliger/**


## Defender XDR
```KQL
let Lookback = 24h;
let CorrelationWindow = 1h;
let MinimumScore = 24; 
let MinimumDistinctFiles = 3;
let MinimumCat3Files = 2;
let Cat1Weight = 1; // Points per distinct Cat-1 filename (nonspecific).
let Cat2Weight = 3; // Points per distinct Cat-2 filename (suspicious).
let Cat3Weight = 6; // Points per distinct Cat-3 filename (strongly associated with stealers).
let Cat1ScoreCap = 3; // Maximum Cat-1 contribution: 3 points, reached at 3 distinct filenames.
let Cat2ScoreCap = 12; // Maximum Cat-2 contribution: 12 points, reached at 4 distinct filenames.
let Cat3ScoreCap = 30; // Maximum Cat-3 contribution: 30 points, reached at 5 distinct filenames.
let FileIndicators = materialize(
	externaldata(IndicatorName:string, Category:int)
	[@"https://raw.githubusercontent.com/benscha/KQLAdvancedHunting/main/Indicators/Stealer-filename-indicators.csv"]
	with (format="csv", ignoreFirstRecord=true)
	| extend NormalizedFileName = tolower(IndicatorName)
	| project NormalizedFileName, Category
);
let MatchingEvents = materialize(
	DeviceFileEvents
	| where Timestamp >= ago(Lookback) and Timestamp <= now()
	| where ActionType == "FileCreated"
	| where FileName in~ ((FileIndicators | project NormalizedFileName))
	| extend NormalizedFileName = tolower(FileName), CollectionFolder = tolower(FolderPath)
	| lookup kind=inner FileIndicators on NormalizedFileName
	| extend ProcessUniqueId = tostring(column_ifexists("InitiatingProcessUniqueId", ""))
	| where isnotempty(CollectionFolder)
	| where isnotempty(ProcessUniqueId)
		or (InitiatingProcessId > 0 and isnotnull(InitiatingProcessCreationTime))
	| extend ProcessKey = iff(
		isnotempty(ProcessUniqueId),
		strcat("unique:", ProcessUniqueId),
		strcat("pid:", tostring(InitiatingProcessId), ":", tostring(InitiatingProcessCreationTime)))
	| project EventTime = Timestamp, DeviceId, DeviceName, ReportId,
		CollectionFolder, NormalizedFileName, Category, ProcessKey,
		InitiatingProcessFileName, InitiatingProcessFolderPath,
		InitiatingProcessCommandLine, InitiatingProcessSHA1,
		InitiatingProcessId, InitiatingProcessCreationTime,
		InitiatingProcessAccountDomain, InitiatingProcessAccountName
);
let WindowAnchors = MatchingEvents
	| distinct DeviceId, ProcessKey, CollectionFolder, WindowStart = EventTime
	| extend JoinBucket = bin(WindowStart, CorrelationWindow);
WindowAnchors
| join kind=inner (
	MatchingEvents
	| extend EventBucket = bin(EventTime, CorrelationWindow)
	| extend JoinBuckets = pack_array(EventBucket, EventBucket - CorrelationWindow)
	| mv-expand JoinBucket = JoinBuckets to typeof(datetime)
	| project-away EventBucket, JoinBuckets
) on DeviceId, ProcessKey, CollectionFolder, JoinBucket
| where EventTime >= WindowStart and EventTime <= WindowStart + CorrelationWindow
| summarize
	FirstFileCreated = min(EventTime),
	LastFileCreated = max(EventTime),
	Cat1Files = make_set_if(NormalizedFileName, Category == 1, 128),
	Cat2Files = make_set_if(NormalizedFileName, Category == 2, 128),
	Cat3Files = make_set_if(NormalizedFileName, Category == 3, 128),
	arg_max(EventTime, ReportId, DeviceName,
		InitiatingProcessFileName, InitiatingProcessFolderPath,
		InitiatingProcessCommandLine, InitiatingProcessSHA1,
		InitiatingProcessId, InitiatingProcessCreationTime,
		InitiatingProcessAccountDomain, InitiatingProcessAccountName)
	by DeviceId, ProcessKey, CollectionFolder, WindowStart
| extend Cat1Count = array_length(Cat1Files),
	Cat2Count = array_length(Cat2Files),
	Cat3Count = array_length(Cat3Files)
| extend Cat1Score = min_of(Cat1Count * Cat1Weight, Cat1ScoreCap),
	Cat2Score = min_of(Cat2Count * Cat2Weight, Cat2ScoreCap),
	Cat3Score = min_of(Cat3Count * Cat3Weight, Cat3ScoreCap),
	DistinctFileCount = Cat1Count + Cat2Count + Cat3Count
| extend Score = Cat1Score + Cat2Score + Cat3Score
| where Cat3Count >= MinimumCat3Files
	and DistinctFileCount >= MinimumDistinctFiles
	and Score >= MinimumScore
| summarize arg_max(Score, *) by DeviceId, ProcessKey, CollectionFolder
| project Timestamp = EventTime, DeviceId, DeviceName, ReportId,
	Score, DistinctFileCount, FirstFileCreated, LastFileCreated,
	WindowStart, WindowEnd = WindowStart + CorrelationWindow,
	CollectionFolder, Cat1Count, Cat2Count, Cat3Count,
	Cat1Score, Cat2Score, Cat3Score, Cat1Files, Cat2Files, Cat3Files,
	ProcessKey, InitiatingProcessFileName, InitiatingProcessFolderPath,
	InitiatingProcessCommandLine, InitiatingProcessSHA1,
	InitiatingProcessId, InitiatingProcessCreationTime,
	InitiatingProcessAccountDomain, InitiatingProcessAccountName
| order by Score desc, Timestamp desc

```
