# Get Anyrun Malware Trends Information
$anyrunURLs = (Invoke-WebRequest -UseBasicParsing -Uri "https://any.run/malware-trends/").Links | Where-Object { $_.href -like "/malware-trends/*" } | select href
 
$staticURLPart = "https://any.run"
     
     
ForEach ($url in $($anyrunURLs.href)) {
        (Invoke-WebRequest -UseBasicParsing -Uri "$staticURLPart$url").Content | Out-File "$exports\any.txt"
    ForEach ($Line in Get-Content -Path "$exports\any.txt") {
        If ($Line -like "*ipData*") {
            $DataName = "ipData"
        }
        ElseIf ($Line -like "*hashData*") {
            $DataName = "hashData"
        }
        ElseIf ($Line -like "*domainData*") {
            $DataName = "domainData"
        }
        ElseIf ($Line -like "*urlData*") {
            $DataName = "urlData"
        }
        ElseIf ($Line -like "*list__item*") {
            $DataValue = $Line.Replace('<div class="list__item">', '').Replace('</div>', '').Trim()
            switch ($DataName) {
                "ipData" {
                    $ipData += $DataValue
                    $ipData += "`n"
                }
                "hashData" {
                    $hashData += $DataValue
                    $hashData += "`n"
                }
                "domainData" {
                    $domainData += $DataValue
                    $domainData += "`n"
                }
                "urlData" {
                    $urlData += $DataValue
                    $urlData += "`n"
                }
     
            }
        }
    }
    Remove-Item -Path "$exports\any.txt" -Force
}
    
$ipData = $ipData.Replace("No IP addresses found", "").Replace("`n`n", "")
$ipData | Out-File "$exports\anyrun-ips.txt" -encoding utf8
    
$urlData = $urlData.Replace("No URLs found", "").Replace("`n`n", "").Replace("http://", "").Replace("https://", "")
$urlData | Out-File "$exports\anyrun-url.txt" -encoding utf8
    
$domainData = $domainData.Replace("No Domain found", "").Replace("`n`n", "")
$domainData | Out-File "$exports\anyrun-domain.txt" -encoding utf8
    
$hashData = $hashData.Replace("No hashes found", "").Replace("`n`n", "").
$hashData | Out-File "$exports\anyrun-hash.txt" -encoding utf8