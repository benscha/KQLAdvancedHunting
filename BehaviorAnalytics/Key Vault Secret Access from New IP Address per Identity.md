# *Key Vault Secret Access from New IP Address per Identity*

## Query Information

#### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1555.006 | Credentials from Password Stores: Cloud Secrets Management Stores | https://attack.mitre.org/techniques/T1555/006 |
| T1078.004 | Valid Accounts: Cloud Accounts | https://attack.mitre.org/techniques/T1078/004 |



#### Description

This query detects successful reads of sensitive Azure Key Vault objects (secrets, key unwrap operations and certificates) by an identity from an IP address that this identity has not used against the same vault before. It builds a 14 day baseline of successful SecretGet, KeyUnwrap and CertificateGet operations, ending one hour before the evaluation window, and reduces every actor to a stable identifier: the account object ID, falling back to the application ID and finally the UPN. The last hour of events is then compared with the baseline using a left anti join on actor, vault and source IP, so only combinations that never occurred during the baseline are returned. Only successful requests are considered, which keeps failed probing attempts out of the result and focuses the output on actual data access.

Such a pattern is typical for stolen service principal credentials, leaked managed identity tokens or a compromised user account that is used to harvest secrets, keys and certificates from an environment. The output lists the actor, account type, vault, requested URI and user agent to speed up triage. The lookback periods and the activity names can be adjusted. Expect false positives from legitimate workloads that scale out to new egress addresses, CI/CD agents with rotating IP ranges and newly onboarded identities, which have no baseline at all. These can be reduced with an allowlist of known IP ranges or by excluding identities younger than the baseline window.

#### Author
- **Name: Benjamin Zulliger**
- **Github: https://github.com/benscha/KQLAdvancedHunting**
- **LinkedIn: https://www.linkedin.com/in/benjamin-zulliger/**


## Sentinel
```KQL
let DetectionEnd = now();
let DetectionStart = DetectionEnd - 1h;
let LookbackStart = DetectionEnd - 14d;
let Baseline =
    CloudKeyVaultEvents
    | where TimeGenerated between (LookbackStart .. DetectionStart)
    | where ActivityName in~ ("SecretGet", "KeyUnwrap", "CertificateGet")
    | where tostring(HttpStatusCode) == "200" or ResultSignature =~ "OK"
    | extend ActorId = case(
        isnotempty(AccountObjectId), AccountObjectId,
        isnotempty(AccountApplicationId), AccountApplicationId,
        AccountUpn
    )
    | where isnotempty(ActorId) and isnotempty(IPAddress)
    | distinct ActorId, VaultName, IPAddress;
CloudKeyVaultEvents
| where TimeGenerated between (DetectionStart .. DetectionEnd)
| where ActivityName in~ ("SecretGet", "KeyUnwrap", "CertificateGet")
| where tostring(HttpStatusCode) == "200" or ResultSignature =~ "OK"
| extend ActorId = case(
    isnotempty(AccountObjectId), AccountObjectId,
    isnotempty(AccountApplicationId), AccountApplicationId,
    AccountUpn
)
| where isnotempty(ActorId) and isnotempty(IPAddress)
| join kind=leftanti Baseline on ActorId, VaultName, IPAddress
| project TimeGenerated, ActivityName, VaultName, ActorId,
          AccountType, AccountUpn, IPAddress, RequestUri, UserAgentHeader
```

Extended with UserAgent
```KQL
let DetectionEnd = now();
let DetectionStart = DetectionEnd - 1h;
let LookbackStart = DetectionEnd - 14d;
let Events = materialize(
    CloudKeyVaultEvents
    | where TimeGenerated between (LookbackStart .. DetectionEnd)
    | where ActivityName in~ ("SecretGet", "KeyUnwrap", "CertificateGet")
    | where tostring(HttpStatusCode) == "200"
        or ResultSignature =~ "OK"
    | extend ActorId = case(
        isnotempty(AccountObjectId),
            strcat("object:", tolower(AccountObjectId)),
        isnotempty(AccountApplicationId),
            strcat("app:", tolower(AccountApplicationId)),
        isnotempty(AccountUpn),
            strcat("upn:", tolower(AccountUpn)),
        ""
    )
    | extend ActorTenant = tolower(AccountTenantId),
             VaultId = tolower(AzureResourceId),
             UserAgent = trim(@"\s+", tostring(UserAgentHeader))
    | where isnotempty(ActorId)
        and isnotempty(ActorTenant)
        and isnotempty(VaultId)
);
let Baseline = Events
    | where TimeGenerated < DetectionStart;
let KnownActors = Baseline
    | distinct ActorTenant, ActorId, VaultId;
let KnownIPs = Baseline
    | where isnotempty(IPAddress)
    | distinct ActorTenant, ActorId, VaultId, IPAddress;
let KnownUserAgents = Baseline
    | where isnotempty(UserAgent)
    | distinct ActorTenant, ActorId, VaultId, UserAgent;
Events
| where TimeGenerated >= DetectionStart
| where isnotempty(IPAddress) and isnotempty(UserAgent)
| join kind=inner KnownActors
    on ActorTenant, ActorId, VaultId
| join kind=leftanti KnownIPs
    on ActorTenant, ActorId, VaultId, IPAddress
| join kind=leftanti KnownUserAgents
    on ActorTenant, ActorId, VaultId, UserAgent
| summarize
    FirstSeen = min(TimeGenerated),
    LastSeen = max(TimeGenerated),
    Calls = count(),
    Operations = make_set(ActivityName, 10),
    RequestUris = make_set(RequestUri, 50),
    AccountUpns = make_set(AccountUpn, 10)
    by ActorTenant, ActorId, VaultId, VaultName,
       IPAddress, UserAgent
```
