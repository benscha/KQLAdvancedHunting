#Get Anyrun Malware Trends Information


$anyrunURLs = ((Invoke-WebRequest –Uri ‘https://any.run/malware-trends/’).Links | Where-Object {$_.href -like “/malware-trends/*”})
$staticURLPart = "https://any.run"

ForEach ($url in $anyrunURLs.href ) 
    {

    $MalwareInfo = (Invoke-WebRequest –Uri $staticURLPart$url)

    #IPData
    $ContentIP = ($MalwareInfo.ParsedHTML.getElementById('ipData')).OuterText
    #MalwareFileHash
    $ContentHash = ($MalwareInfo.ParsedHTML.getElementById('hashData')).OuterText
    #DomainData
    $ContentDomain = ($MalwareInfo.ParsedHTML.getElementById('domainData')).OuterText
    #UrlData
    $ContentURL = ($MalwareInfo.ParsedHTML.getElementById('urlData')).OuterText

    $urlTxt = $url.Replace("/malware-trends/","`n#") 
    $urlTxt += "`n"

    $ips += $urlTxt
    $ips += $ContentIP
    $malfilehash += $urlTxt
    $malfilehash += $ContentHash
    $urls += $urlTxt
    $urls += $ContentURL
    $domains += $urlTxt
    $domains += $ContentDomain

    }


    #Output all ips
    $ips = $ips.Replace("No IP adresses found","").Replace("`n`n","")
    $ips = $ips | Select -Unique
    $ips | Out-File "anyrun-ips.txt"

    #Output all urls
    $urls = $urls.Replace("No URLs found","").Replace("`n`n","")
    $urls = $urls | Select -Unique
    $urls | Out-File "anyrun-url.txt"

    #Output all Domains
    $domains = $domains.Replace("No Domain found","").Replace("`n`n","")
    $domains = $domains | Select -Unique
    $domains | Out-File "anyrun-domain.txt"

    #Output all malware file hashes
    $malfilehash = $malfilehash.Replace("No hashes found","").Replace("`n`n","")
    $malfilehash = $malfilehash | Select -Unique
    $malfilehash | out-file  "anyrun-hash.txt"
