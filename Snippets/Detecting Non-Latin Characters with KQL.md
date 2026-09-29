# *Detecting Non-Latin Characters with KQL*

## Query Information

I recently discovered how easy it is to detect characters from non-Latin writing systems using Unicode script categories:

A simple regular expression can identify scripts such as Chinese, Japanese, Korean, Arabic, Hebrew, and several Indic scripts. A small but useful insight for text analysis and data quality checks.
```KQL
let foreignCharPattern = @"[\p{Han}\p{Hiragana}\p{Katakana}\p{Hangul}\p{Arabic}\p{Hebrew}\p{Devanagari}\p{Bengali}\p{Tamil}\p{Thai}]";
````

#### Description Example Query

This query searches the EmailEvents table in Defender XDR for messages received during the last 30 days whose subject mentions a file sharing platform such as Teams or SharePoint and at the same time contains characters from a non-Latin script. The script list is defined once in a regex pattern based on Unicode script classes and covers Han, Hiragana, Katakana, Hangul, Arabic, Hebrew, Devanagari, Bengali, Tamil and Thai. The pattern is meant as a reusable building block that shows how Unicode properties can be used in KQL to spot foreign characters without listing individual code points.

The filter first reduces the data to subjects that contain one of the platform keywords, then applies the regex match to keep only subjects with at least one character from the listed scripts. In the last step, extract_all returns every matching character in a separate column, which makes it easy to see which script was used and how many foreign characters a subject contains.

Such subjects can be interesting when an organization normally communicates in Latin script only, because mixed script subjects are a common trait of phishing and lure mails that imitate sharing notifications. Mixed script content can also hint at homoglyph tricks or mass campaigns from unusual regions. Typical false positives are legitimate international senders and multilingual teams. The query is easy to tune by adjusting the SharingPlatform list, the time range or the set of Unicode scripts in the pattern, and it can be extended with sender domain, recipient or delivery action filters.


## Defender XDR SAMPLE QUERY
```KQL
let foreignCharPattern = @"[\p{Han}\p{Hiragana}\p{Katakana}\p{Hangul}\p{Arabic}\p{Hebrew}\p{Devanagari}\p{Bengali}\p{Tamil}\p{Thai}]";
let SharingPlatform = dynamic(["Teams", "Sharepoint"]);
EmailEvents
| where Timestamp > ago(30d)
| where Subject has_any (SharingPlatform)
| where Subject matches regex foreignCharPattern
| extend ForeignChars = extract_all(@"([\p{Han}\p{Hiragana}\p{Katakana}\p{Hangul}\p{Arabic}\p{Hebrew}\p{Devanagari}\p{Bengali}\p{Tamil}\p{Thai}])", Subject)
```
