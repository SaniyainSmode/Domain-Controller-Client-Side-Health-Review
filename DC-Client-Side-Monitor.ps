<#
External DC Health Monitor (Outside-In) - Ninja-safe

Exit codes:
- 2 = Primary DC unhealthy OR discovery failed
- 1 = Any DC unhealthy
- 0 = All OK
#>

# ---------- CONFIG ----------
$MonitorHost  = $env:COMPUTERNAME
$RunTimestamp = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")

$DomainFqdn = (Get-CimInstance Win32_ComputerSystem).Domain

# ---------- DISCOVERY (Ninja-safe / PS 5.1-safe) ----------

# DNS servers the client is using (debug)
$dnsServers = @(
    Get-DnsClientServerAddress -AddressFamily IPv4 |
    ForEach-Object { $_.ServerAddresses } |
    Where-Object { $_ } |
    ForEach-Object { $_ } |
    Select-Object -Unique
)

# Try to locate a DC for the domain
$PrimaryDC = $null
try {
    $PrimaryDC = @(
        (nltest /dsgetdc:$DomainFqdn 2>&1) |
        Select-String 'DC:\s*\\\\' |
        ForEach-Object { ($_ -replace '.*DC:\s*\\\\','').Trim() } |
        Where-Object { $_ } |
        Select-Object -First 1
    )[0]
} catch { }

# Discover all DCs via DNS SRV records (most consistent)
$DCs   = @()
$srvErr = $null
$srvName = "_ldap._tcp.dc._msdcs.$DomainFqdn"

try {
    $DCs = @(
        Resolve-DnsName -Type SRV -Name $srvName -ErrorAction Stop |
        Where-Object { $_.NameTarget } |
        ForEach-Object { $_.NameTarget.TrimEnd('.') } |
        Select-Object -Unique
    )
} catch {
    $srvErr = $_.Exception.Message
}

# If dsgetdc failed but SRV succeeded, pick a primary from the list
if (-not $PrimaryDC -and $DCs.Count -gt 0) {
    $PrimaryDC = $DCs | Select-Object -First 1
}

# Fail closed if discovery fails (with diagnostics)
if (-not $DCs -or $DCs.Count -eq 0) {
    $dnsTxt  = if ($dnsServers -and $dnsServers.Count -gt 0) { $dnsServers -join "," } else { "None" }
    $pdcTxt  = if ($PrimaryDC) { $PrimaryDC } else { "None" }
    $errTxt  = if ($srvErr) { $srvErr } else { "None" }

    Write-Output ("RESULT=FAIL MonitorHost={0} Timestamp={1} Domain={2} PrimaryDC={3} PrimaryStatus=UNKNOWN BadDCs=None WarnDCs=None Reason=NoDCsDiscovered DnsServers={4} SrvLookup={5} SrvError={6}" -f `
        $MonitorHost, $RunTimestamp, $DomainFqdn, $pdcTxt, $dnsTxt, $srvName, $errTxt
    )
    exit 2
}

# Normalize primary for comparisons
$PrimaryDCNorm = if ($PrimaryDC) { $PrimaryDC.ToLower() } else { "" }

# Optional discovery breadcrumb
$dnsTxt = if ($dnsServers -and $dnsServers.Count -gt 0) { $dnsServers -join "," } else { "None" }
Write-Output ("DISCOVERY Domain={0} PrimaryDC={1} DCs={2} DnsServers={3}" -f `
    $DomainFqdn, $PrimaryDC, ($DCs -join ","), $dnsTxt
)

# ---------- THRESHOLDS ----------
$LookbackMinutes      = 20
$MaxReplicationAgeMin = 60
$MaxDnsQueryMs        = 1500
$MaxUncResponseMs     = 2500

# Optional ports
$CheckLDAPS = $false   # 636
$CheckGC    = $false   # 3268

# ---------- HELPERS ----------
function Test-TcpPort {
    param(
        [string]$TargetHost,
        [int]$Port,
        [int]$TimeoutMs = 1500
    )
    try {
        $client = New-Object System.Net.Sockets.TcpClient
        $iar = $client.BeginConnect($TargetHost, $Port, $null, $null)
        if (-not $iar.AsyncWaitHandle.WaitOne($TimeoutMs, $false)) { $client.Close(); return $false }
        $client.EndConnect($iar) | Out-Null
        $client.Close()
        return $true
    } catch { return $false }
}

function Measure-DnsQuery {
    param([string]$Name,[string]$Server)
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    try {
        Resolve-DnsName -Name $Name -Server $Server -DnsOnly -NoHostsFile -ErrorAction Stop | Out-Null
        $sw.Stop()
        return [pscustomobject]@{ Ok=$true; Ms=$sw.ElapsedMilliseconds }
    } catch {
        $sw.Stop()
        return [pscustomobject]@{ Ok=$false; Ms=$sw.ElapsedMilliseconds }
    }
}

function Test-UncFast {
    param([string]$Path,[int]$TimeoutMs=2500)

    $job = Start-Job -ScriptBlock {
        param($p)
        try { Get-ChildItem -Path $p -ErrorAction Stop | Select-Object -First 1 | Out-Null; $true }
        catch { $false }
    } -ArgumentList $Path

    if (Wait-Job $job -Timeout ($TimeoutMs/1000.0)) {
        $result = Receive-Job $job -ErrorAction SilentlyContinue
        Remove-Job $job -Force | Out-Null
        return [bool]$result
    } else {
        Stop-Job $job -Force | Out-Null
        Remove-Job $job -Force | Out-Null
        return $false
    }
}

function Get-RecentEventCount {
    param([string]$Computer,[string[]]$Logs,[int[]]$Ids,[datetime]$Start)
    try {
        $filter = @{ LogName=$Logs; Id=$Ids; StartTime=$Start }
        $ev = Get-WinEvent -ComputerName $Computer -FilterHashtable $filter -ErrorAction Stop
        return ($ev | Measure-Object).Count
    } catch { return -1 }
}

function Get-ReplicationMaxAgeMin {
    param([string]$TargetDC)
    try {
        $out = & repadmin /showrepl $TargetDC /csv 2>$null
        if (-not $out) { return $null }
        $rows = $out | ConvertFrom-Csv
        $ages = @()
        foreach ($r in $rows) {
            $t = $r.'Last Success Time'
            if ([string]::IsNullOrWhiteSpace($t)) { continue }
            $dt = $null
            if ([datetime]::TryParse($t,[ref]$dt)) {
                $ages += (New-TimeSpan -Start $dt -End (Get-Date)).TotalMinutes
            }
        }
        if ($ages.Count -eq 0) { return $null }
        return [math]::Round(($ages | Measure-Object -Maximum).Maximum,1)
    } catch { return $null }
}

# ---------- MAIN ----------
$startTime = (Get-Date).AddMinutes(-$LookbackMinutes)

$results = foreach ($dc in $DCs) {
    $failures = New-Object System.Collections.Generic.List[string]
    $signals  = New-Object System.Collections.Generic.List[string]

    $ping = Test-Connection -ComputerName $dc -Count 1 -Quiet -ErrorAction SilentlyContinue
    if (-not $ping) { $failures.Add("Ping") }

    # Ports / Protocol reachability
    if (-not (Test-TcpPort -TargetHost $dc -Port 53  -TimeoutMs 1200)) { $failures.Add("DNS:53") }
    if (-not (Test-TcpPort -TargetHost $dc -Port 88  -TimeoutMs 1200)) { $failures.Add("Kerberos:88") }
    if (-not (Test-TcpPort -TargetHost $dc -Port 389 -TimeoutMs 1200)) { $failures.Add("LDAP:389") }
    if (-not (Test-TcpPort -TargetHost $dc -Port 445 -TimeoutMs 1200)) { $failures.Add("SMB:445") }

    if ($CheckLDAPS -and -not (Test-TcpPort -TargetHost $dc -Port 636 -TimeoutMs 1200)) { $failures.Add("LDAPS:636") }
    if ($CheckGC    -and -not (Test-TcpPort -TargetHost $dc -Port 3268 -TimeoutMs 1200)) { $failures.Add("GC:3268") }

    # DNS function (query against that DC)
    $q1 = Measure-DnsQuery -Name $DomainFqdn -Server $dc
    if (-not $q1.Ok) { $failures.Add("DNSQuery($DomainFqdn)") }
    elseif ($q1.Ms -gt $MaxDnsQueryMs) { $failures.Add("DNSLatency>${MaxDnsQueryMs}ms($($q1.Ms)ms)") }

    $q2 = Measure-DnsQuery -Name $srvName -Server $dc
    if (-not $q2.Ok) { $failures.Add("DNSQuery($srvName)") }
    elseif ($q2.Ms -gt $MaxDnsQueryMs) { $failures.Add("DNSLatency>${MaxDnsQueryMs}ms($($q2.Ms)ms)") }

    # SYSVOL / NETLOGON (only if SMB is reachable)
    $sysvolOk   = $null
    $netlogonOk = $null
    if (-not $failures.Contains("SMB:445")) {
        $sysvolOk   = Test-UncFast "\\$dc\SYSVOL"   $MaxUncResponseMs
        $netlogonOk = Test-UncFast "\\$dc\NETLOGON" $MaxUncResponseMs
        if (-not $sysvolOk)   { $failures.Add("SYSVOL") }
        if (-not $netlogonOk) { $failures.Add("NETLOGON") }
    }

    # Replication age (best effort)
    $repAge = Get-ReplicationMaxAgeMin -TargetDC $dc
    if ($repAge -ne $null -and $repAge -gt $MaxReplicationAgeMin) {
        $failures.Add("ReplAge>${MaxReplicationAgeMin}min($repAge)")
    }

    # Event signals (best effort)
    $logs = @("System","Directory Service","DNS Server","Application")
    $power41  = Get-RecentEventCount -Computer $dc -Logs @("System") -Ids @(41) -Start $startTime
    $net5719  = Get-RecentEventCount -Computer $dc -Logs $logs -Ids @(5719) -Start $startTime
    $dns4013  = Get-RecentEventCount -Computer $dc -Logs $logs -Ids @(4013,4015) -Start $startTime
    $dns1014  = Get-RecentEventCount -Computer $dc -Logs $logs -Ids @(1014) -Start $startTime
    $gp1129   = Get-RecentEventCount -Computer $dc -Logs $logs -Ids @(1129) -Start $startTime
    $timeSvc4 = Get-RecentEventCount -Computer $dc -Logs $logs -Ids @(4)    -Start $startTime
    $dfsr2213 = Get-RecentEventCount -Computer $dc -Logs $logs -Ids @(2213) -Start $startTime

    if ($power41  -gt 0) { $signals.Add("Evt41") }
    if ($net5719  -gt 0) { $signals.Add("Evt5719") }
    if ($dns4013  -gt 0) { $signals.Add("Evt4013/4015") }
    if ($dns1014  -gt 0) { $signals.Add("Evt1014") }
    if ($gp1129   -gt 0) { $signals.Add("Evt1129") }
    if ($timeSvc4 -gt 0) { $signals.Add("EvtTime4") }
    if ($dfsr2213 -gt 0) { $signals.Add("EvtDFSR2213") }

    # Health decision logic
    $hardSignals = @("Evt5719","Evt4013/4015","EvtDFSR2213")
    $hasHardSignal = ($signals | Where-Object { $hardSignals -contains $_ } | Select-Object -First 1) -ne $null
    $unhealthy = ($failures.Count -ge 2) -or (($failures.Count -ge 1) -and $hasHardSignal)

    [pscustomobject]@{
        DC          = $dc
        Ping        = $ping
        DnsMs       = $q1.Ms
        SrvMs       = $q2.Ms
        SysvolOk    = $sysvolOk
        NetlogonOk  = $netlogonOk
        RepAgeMin   = $repAge
        Failures    = ($failures -join ";")
        Signals     = ($signals -join ";")
        Unhealthy   = $unhealthy
    }
}

# ---------- OUTPUT ----------
$badDcs     = @($results | Where-Object Unhealthy)
$warnDcs    = @($results | Where-Object { -not $_.Unhealthy -and $_.Failures -and $_.Failures -ne "" })
$overall    = if ($badDcs.Count -gt 0) { "FAIL" } elseif ($warnDcs.Count -gt 0) { "WARN" } else { "OK" }

$primaryObj = $results | Where-Object { $_.DC.ToLower() -eq $PrimaryDCNorm } | Select-Object -First 1

$badList  = if ($badDcs.Count  -gt 0) { ($badDcs.DC  -join ",") } else { "None" }
$warnList = if ($warnDcs.Count -gt 0) { ($warnDcs.DC -join ",") } else { "None" }

Write-Output ("RESULT={0} MonitorHost={1} Timestamp={2} Domain={3} PrimaryDC={4} PrimaryStatus={5} BadDCs={6} WarnDCs={7}" -f `
    $overall, $MonitorHost, $RunTimestamp, $DomainFqdn, $PrimaryDC, `
    ($(if ($primaryObj -and $primaryObj.Unhealthy) { "UNHEALTHY" } else { "OK" })), `
    $badList, $warnList
)

foreach ($r in $results) {
    $status  = if ($r.Unhealthy) { "UNHEALTHY" } else { "OK" }
    $failTxt = if ($r.Failures) { $r.Failures } else { "None" }
    $sigTxt  = if ($r.Signals)  { $r.Signals }  else { "None" }
    $sev     = if ($r.Unhealthy) { "CRIT" } elseif ($failTxt -ne "None") { "WARN" } else { "INFO" }

    Write-Output ("DC={0} Severity={1} Status={2} Ping={3} DnsMs={4} SrvMs={5} SysvolOk={6} NetlogonOk={7} ReplAgeMin={8} Failures={9} Signals={10}" -f `
        $r.DC, $sev, $status, $r.Ping, $r.DnsMs, $r.SrvMs, $r.SysvolOk, $r.NetlogonOk, $r.RepAgeMin, $failTxt, $sigTxt
    )
}

# ---------- EXIT CODES ----------
$primary = $results | Where-Object { $_.DC.ToLower() -eq $PrimaryDCNorm }
$anyBad  = ($results | Where-Object Unhealthy).Count -gt 0

if ($primary -and $primary.Unhealthy) { exit 2 }
if ($anyBad) { exit 1 }
exit 0
