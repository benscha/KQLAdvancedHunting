# *Azure Key Vault Mass Secret Retrieval by Single Actor*

## Query Information

#### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1555.006 | Credentials from Password Stores: Cloud Secrets Management Stores | https://attack.mitre.org/techniques/T1555/006 |



#### Description

This query monitors Azure Key Vault data plane events and detects a single identity reading an unusually high number of different secrets, certificates or keys within a short time window. It only considers successful read operations (SecretGet, CertificateGet and KeyUnwrap) from the last ten minutes. The acting identity is resolved in a fixed order: the account object ID first, then the application ID and finally the UPN, so that users, service principals and managed identities are all covered. The accessed object is derived from the path of the request URI, which allows the number of distinct resources to be counted per actor.

Results are summarized in ten minute bins per vault, actor and source IP address. An alert row is produced when an actor performs at least 20 calls and touches at least 5 distinct resources. This pattern is typical for credential harvesting after a compromise of an identity with vault access, for example a stolen service principal secret or a hijacked managed identity, where an attacker enumerates and dumps everything that is readable. Legitimate applications usually read a small, stable set of secrets, so a sudden fan out across many objects is a strong signal.

The thresholds for calls and distinct resources should be tuned per environment. Known false positives are deployment pipelines, backup tools and applications that load many secrets at startup. Such identities can be excluded with an allowlist on ActorId. Because the lookback and the bin size are both ten minutes, activity that spans a bin boundary may be split and fall below the thresholds.


#### Author
- **Name: Benjamin Zulliger**
- **Github: https://github.com/benscha/KQLAdvancedHunting**
- **LinkedIn: https://www.linkedin.com/in/benjamin-zulliger/**


## Sentinel
```KQL
CloudKeyVaultEvents
| where TimeGenerated >= ago(10m)
| where ActivityName in~ ("SecretGet", "CertificateGet", "KeyUnwrap")
| where tostring(HttpStatusCode) == "200" or ResultSignature =~ "OK"
| extend ActorId = case(
    isnotempty(AccountObjectId), AccountObjectId,
    isnotempty(AccountApplicationId), AccountApplicationId,
    AccountUpn
)
| extend ResourcePath = tostring(parse_url(RequestUri).Path)
| where isnotempty(ActorId) and isnotempty(ResourcePath)
| summarize Calls = count(),
            DistinctResources = dcount(ResourcePath),
            Operations = make_set(ActivityName),
            UserAgents = make_set(UserAgentHeader)
    by bin(TimeGenerated, 10m), VaultName, ActorId, IPAddress
| where Calls >= 20 and DistinctResources >= 5
```
