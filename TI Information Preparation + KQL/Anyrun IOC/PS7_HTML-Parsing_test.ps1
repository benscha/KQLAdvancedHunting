$MalwareInfo = iwr -uri https://any.run/malware-trends/purelogs

$ContentIP = $MalwareInfo.Content | Select-String -Pattern '(?<=IPs:).*?(?=Hashes:)' -AllMatches | % { $_.Matches } | % { $_.Value.Trim() }