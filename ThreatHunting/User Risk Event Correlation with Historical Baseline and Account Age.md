# *User Risk Event Correlation with Historical Baseline and Account Age*

## Query Information

#### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1078 | Valid Accounts | https://attack.mitre.org/techniques/T1078 |

#### Description

This rule detects potentially compromised accounts by identifying logins from new, previously unseen geographic locations (city or country) or new User-Agent strings. It establishes a 29-day baseline of known behaviors for each user and flags sign-in sessions that deviate from this historical pattern. It considers account age to reduce noise from new user onboarding.


#### Author <Optional>
- **Name: Benjamin Zulliger**
- **Github: https://github.com/benscha/KQLAdvancedHunting**
- **LinkedIn: https://www.linkedin.com/in/benjamin-zulliger/**

#### Possible false positives
- Users traveling to new locations.
- Users updating/changing browsers or operating systems.


## Defender XDR
```KQL
// Neue UserAgents / Locations je Anmeldesession – 29-Tage-Baseline + Account-Alter
// Aggregiert pro (User, CorrelationId): kollabiert Risk-Event-Lifecycle & Sub-Events
let lookback	 = 4h;
let historyStart = ago(29d);
let historyEnd   = ago(lookback);
let newAccountWindow = 60d;
let NormalizeUA = (ua:string) {
	tostring(
		replace_regex(
			replace_regex(ua, @'\d+\.\d+\.\d+\.\d+', "x.x.x.x"),
			@';\s*WebView/[\d\.]+', ""
		)
	)
};
let AffectedUsers = materialize(
	AADUserRiskEvents
	| where TimeGenerated >= ago(lookback)
	| where isnotempty(UserPrincipalName)
	| distinct UserPrincipalName
  );
let RiskEvents =
	AADUserRiskEvents
	| where TimeGenerated >= ago(lookback)
    | where RiskState !in ("remediated", "dismissed","confirmedCompromised")
	| extend _loc = parse_json(Location)
	| extend UserAgent = extract(@'"Key"\s*:\s*"userAgent"\s*,\s*"Value"\s*:\s*"([^"]+)"', 1, tostring(AdditionalInfo))
	| extend City    = tolower(trim(@'\s+', tostring(_loc.city))),
			 Country = toupper(tostring(_loc.countryOrRegion)),
			 State   = tostring(_loc.state)
	| extend UANorm  = NormalizeUA(UserAgent),
			 CityKey = strcat(tolower(trim(@'\s+', tostring(_loc.city))), "|", toupper(tostring(_loc.countryOrRegion))),
			 RiskLevelRank = case(RiskLevel =~ "high", 100, RiskLevel =~ "medium", 50, RiskLevel =~ "low", 10, 0)
	| where isnotempty(UserPrincipalName)
	| extend _upn = tolower(UserPrincipalName),
			 SessionId = iff(isnotempty(CorrelationId), CorrelationId, strcat("nocorr:", tostring(bin(TimeGenerated, 10m))))
	| project _upn, SessionId, CorrelationId, TimeGenerated, UserPrincipalName, IpAddress,
			  UserAgent, UANorm, City, Country, State, CityKey,
			  RiskEventType, RiskLevel, RiskLevelRank, RiskState, RiskDetail, Source, RiskEventId = Id;
let Baseline =
	EntraIdSignInEvents
	| where Timestamp between (historyStart .. historyEnd)
	| where AccountUpn in~ (AffectedUsers)
	| where ErrorCode == 0
	| extend UANorm     = NormalizeUA(UserAgent),
			 CityKey    = strcat(tolower(trim(@'\s+', City)), "|", toupper(Country)),
			 CountryKey = toupper(Country)
	| summarize
		KnownUAs        = make_set_if(UANorm, isnotempty(UANorm), 2000),
		KnownCities     = make_set_if(CityKey, isnotempty(City), 1000),
		KnownCountries  = make_set_if(CountryKey, isnotempty(Country), 250),
		BaselineSignins = count()
		by AccountUpn
	| extend _upn = tolower(AccountUpn);
let AccountAge = materialize(
	IdentityInfo
	| where AccountUpn in~ (AffectedUsers)
	| where isnotempty(CreatedDateTime)
	| summarize arg_max(Timestamp, CreatedDateTime) by AccountUpn
	| extend _upn = tolower(AccountUpn)
	| project _upn, AccountCreatedDateTime = CreatedDateTime
  );
RiskEvents
| join kind=leftouter hint.strategy=broadcast (Baseline) on _upn
| join kind=leftouter hint.strategy=broadcast (AccountAge) on _upn
| extend KnownUAs        = coalesce(KnownUAs, dynamic([])),
		 KnownCities     = coalesce(KnownCities, dynamic([])),
		 KnownCountries  = coalesce(KnownCountries, dynamic([])),
		 BaselineSignins = coalesce(BaselineSignins, 0)
| extend HasBaseline    = BaselineSignins > 0
| extend AccountAgeDays = iff(isnotempty(AccountCreatedDateTime), datetime_diff('day', now(), AccountCreatedDateTime), long(null))
| extend IsNewAccount   = iff(isnotempty(AccountCreatedDateTime), AccountCreatedDateTime >= ago(newAccountWindow), bool(null))
| extend UAIsNew        = iff(isempty(UANorm),  bool(null), not(set_has_element(KnownUAs, UANorm)))
| extend CountryIsNew   = iff(isempty(Country), bool(null), not(set_has_element(KnownCountries, Country)))
| extend CityIsNew      = iff(isempty(City),    bool(null), not(set_has_element(KnownCities, CityKey)))
// --- Aggregation pro Session: ein Datensatz statt n State-Snapshots ---
| summarize
	FirstSeen          = min(TimeGenerated),
	arg_max(TimeGenerated, RiskState, RiskDetail),
	DistinctRiskEvents = dcount(RiskEventId),
	RawSnapshots       = count(),
	MaxRiskRank        = max(RiskLevelRank),
	UAs                = make_set(UANorm, 25),
	NewUAs             = make_set_if(UANorm, UAIsNew == true, 25),
	IPs                = make_set(IpAddress, 25),
	Cities             = make_set(City, 25),
	Countries          = make_set(Country, 25),
	NewCities          = make_set_if(CityKey, CityIsNew == true, 25),
	NewCountries       = make_set_if(Country, CountryIsNew == true, 25),
	RiskEventTypes     = make_set(RiskEventType, 15),
	RiskStates         = make_set(RiskState, 15),
	HasBaseline        = take_any(HasBaseline),
	BaselineSignins    = take_any(BaselineSignins),
	IsNewAccount       = take_any(IsNewAccount),
	AccountAgeDays     = take_any(AccountAgeDays),
	AccountCreatedDateTime = take_any(AccountCreatedDateTime),
	KnownCountries     = take_any(KnownCountries)
	by UserPrincipalName, SessionId, CorrelationId
| project-rename LastSeen = TimeGenerated
| extend AnyUANew       = array_length(NewUAs) > 0,
		 AnyCountryNew  = array_length(NewCountries) > 0,
		 AnyCityNew     = array_length(NewCities) > 0
| extend AnyLocationNew = AnyCountryNew or AnyCityNew
| extend MaxRiskLevel   = case(MaxRiskRank >= 100, "high", MaxRiskRank >= 50, "medium", MaxRiskRank >= 10, "low", "none")
| extend Verdict = case(
	not(HasBaseline) and IsNewAccount == true,	"Review - neuer Account (<60d), Baseline-Lücke plausibel",
	not(HasBaseline) and IsNewAccount == false,	"Review - Account >60d ohne Baseline (verdächtig)",
	not(HasBaseline),							"Review - keine Baseline, Account-Alter unbekannt",
	AnyUANew and AnyCountryNew,					"High - neuer UA + neues Land",
	AnyUANew and AnyCityNew,					"High - neuer UA + neue Stadt",
	AnyCountryNew,								"Medium - neues Land",
	AnyUANew,									"Medium - neuer UserAgent",
	AnyCityNew,									"Low - neue Stadt (gleiches Land)",
												"Info - UA & Location bekannt"
  )
| sort by AnyUANew desc, AnyCountryNew desc, MaxRiskRank desc, LastSeen desc
| project FirstSeen, LastSeen, Verdict, UserPrincipalName,
		  AnyUANew, AnyCityNew, AnyCountryNew, AnyLocationNew, HasBaseline,
		  IsNewAccount, AccountAgeDays, AccountCreatedDateTime,
		  MaxRiskLevel, RiskState, RiskDetail, DistinctRiskEvents, RawSnapshots,
		  NewUAs, UAs, NewCountries, NewCities, Countries, Cities, IPs,
		  RiskEventTypes, RiskStates, BaselineSignins, KnownCountries,
		  CorrelationId, SessionId
//| where AnyUANew or AnyLocationNew or not(HasBaseline)
```
