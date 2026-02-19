External DC Health Monitor (Outside-In) — NinjaRMM Safe

A PowerShell 5.1 compatible outside-in Domain Controller health monitor designed specifically for NinjaRMM environments.

This script runs from a domain-joined workstation or server, discovers all Domain Controllers using DNS SRV records, and performs layered health checks per DC — including connectivity, DNS responsiveness, SYSVOL/NETLOGON availability, replication freshness, and critical event signals.

It outputs clean, parseable results and exits with Ninja-friendly exit codes for alerting.

For each Domain Controller, the script checks:

Connectivity & Ports

ICMP Ping

TCP Port checks:

DNS (53)

Kerberos (88)

LDAP (389)

SMB (445)

Optional:

LDAPS (636)

Global Catalog (3268)

DNS Health (Query + Latency)

Per DC, it performs DNS lookups against that DC directly:

Domain lookup: yourdomain.com

SRV lookup: _ldap._tcp.dc._msdcs.yourdomain.com

It flags:

Failed DNS responses

DNS latency over threshold

SYSVOL / NETLOGON (Fast UNC Validation)

Checks:

\\DC\SYSVOL

\\DC\NETLOGON

Uses a timeout-safe job method so it won’t hang in Ninja.

Replication Health (Best Effort)

Uses:

repadmin /showrepl <dc> /csv

Calculates max replication “last success” age in minutes.

Event Log Signals (Best Effort)

Checks recent event counts from:

System

Directory Service

DNS Server

Application

Signals include:

Event 41 (unexpected reboot)

Event 5719 (NETLOGON issues)

Event 4013/4015 (DNS issues)

Event 2213 (DFSR issues)

Event 1129 (Group Policy issues)

Event 1014 (DNS client timeouts)

Time Service event 4

Health Logic (How It Decides FAIL/WARN/OK)

A DC is marked UNHEALTHY if:

It has 2 or more failures, OR

It has 1 failure + a “hard” event signal

Hard signals:

Evt5719

Evt4013/4015

EvtDFSR2213

| Exit Code | Meaning                                     |
| --------: | ------------------------------------------- |
|       `0` | All DCs OK                                  |
|       `1` | One or more DCs unhealthy                   |
|       `2` | Primary DC unhealthy OR DC discovery failed |


Discovery line

Example:
1) DISCOVERY Domain=corp.example.com PrimaryDC=DC01 DCs=DC01,DC02 DnsServers=10.0.0.10,10.0.0.11

2) Summary RESULT line
RESULT=FAIL MonitorHost=WS-123 Timestamp=2026-02-19 10:42:11 Domain=corp.example.com PrimaryDC=DC01 PrimaryStatus=UNHEALTHY BadDCs=DC01 WarnDCs=DC02

3) Per-DC detail lines
DC=DC01 Severity=CRIT Status=UNHEALTHY Ping=True DnsMs=44 SrvMs=60 SysvolOk=True NetlogonOk=False ReplAgeMin=120 Failures=NETLOGON;ReplAge>60min(120) Signals=EvtDFSR2213

Requirements

PowerShell 5.1 compatible

Must run on a domain-joined machine

Requires access to:

DNS SRV records for the domain

SMB shares on DCs (SYSVOL/NETLOGON)

repadmin available (usually on domain systems; otherwise replication check will return null)

This script is designed to fail safely and still provide useful output even if some checks can’t be performed.

Configuration

At the top of the script you can adjust:
Thresholds
$LookbackMinutes      = 20
$MaxReplicationAgeMin = 60
$MaxDnsQueryMs        = 1500
$MaxUncResponseMs     = 2500
Optional Ports
$CheckLDAPS = $false   # 636
$CheckGC    = $false   # 3268



Exit codes:
- 2 = Primary DC unhealthy OR discovery failed
- 1 = Any DC unhealthy
- 0 = All OK

External DC Health Monitor (Outside-In) — NinjaRMM Safe
A PowerShell 5.1 compatible outside-in Domain Controller health monitor designed for NinjaRMM.

This script runs from a workstation/server joined to the domain, discovers all Domain Controllers via DNS SRV records, and performs multiple health checks per DC — including connectivity, DNS responsiveness, SYSVOL/NETLOGON availability, and replication freshness.

It outputs clean, parseable results and exits with Ninja-friendly exit codes.

What This Script Checks
For each Domain Controller, the script checks:

Connectivity & Ports
ICMP Ping

TCP Port checks:

DNS (53)

Kerberos (88)

LDAP (389)

SMB (445)

Optional:

LDAPS (636)

Global Catalog (3268)

DNS Health (Query + Latency)
Per DC, it performs DNS lookups against that DC directly:

Domain lookup: yourdomain.com

SRV lookup: _ldap._tcp.dc._msdcs.yourdomain.com

It flags:

Failed DNS responses

DNS latency over threshold

SYSVOL / NETLOGON (Fast UNC Validation)
Checks:

\\DC\SYSVOL

\\DC\NETLOGON

Uses a timeout-safe job method so it won’t hang in Ninja.

Replication Health (Best Effort)
Uses:

repadmin /showrepl <dc> /csv

Calculates max replication “last success” age in minutes.

Event Log Signals (Best Effort)
Checks recent event counts from:

System

Directory Service

DNS Server

Application

Signals include:

Event 41 (unexpected reboot)

Event 5719 (NETLOGON issues)

Event 4013/4015 (DNS issues)

Event 2213 (DFSR issues)

Event 1129 (Group Policy issues)

Event 1014 (DNS client timeouts)

Time Service event 4

Health Logic (How It Decides FAIL/WARN/OK)
A DC is marked UNHEALTHY if:

It has 2 or more failures, OR

It has 1 failure + a “hard” event signal

Hard signals:

Evt5719

Evt4013/4015

EvtDFSR2213

Exit Codes (Ninja-Friendly)
Exit Code	Meaning
0	All DCs OK
1	One or more DCs unhealthy
2	Primary DC unhealthy OR DC discovery failed
This makes it easy to build Ninja alerting rules with severity.

Output Format
The script outputs:

1) Discovery line
Example:

DISCOVERY Domain=corp.example.com PrimaryDC=DC01 DCs=DC01,DC02 DnsServers=10.0.0.10,10.0.0.11
2) Summary RESULT line
Example:

RESULT=FAIL MonitorHost=WS-123 Timestamp=2026-02-19 10:42:11 Domain=corp.example.com PrimaryDC=DC01 PrimaryStatus=UNHEALTHY BadDCs=DC01 WarnDCs=DC02
3) Per-DC detail lines
Example:

DC=DC01 Severity=CRIT Status=UNHEALTHY Ping=True DnsMs=44 SrvMs=60 SysvolOk=True NetlogonOk=False ReplAgeMin=120 Failures=NETLOGON;ReplAge>60min(120) Signals=EvtDFSR2213
Requirements
PowerShell 5.1 compatible

Must run on a domain-joined machine

Requires access to:

DNS SRV records for the domain

SMB shares on DCs (SYSVOL/NETLOGON)

repadmin available (usually on domain systems; otherwise replication check will return null)

This script is designed to fail safely and still provide useful output even if some checks can’t be performed.

Configuration
At the top of the script you can adjust:

Thresholds
$LookbackMinutes      = 20
$MaxReplicationAgeMin = 60
$MaxDnsQueryMs        = 1500
$MaxUncResponseMs     = 2500
Optional Ports
$CheckLDAPS = $false   # 636
$CheckGC    = $false   # 3268
Recommended NinjaRMM Setup
Add the script in Ninja as a scheduled script

Run it from:

A domain-joined server, OR

A stable workstation (recommended: an always-on system)

Create alert conditions based on exit code:

Exit code 2 = Critical alert

Exit code 1 = Warning/Critical (your choice)

Exit code 0 = Healthy

Why “Outside-In” Monitoring?

This script monitors DCs from the perspective of a real client, which catches issues that DC-local scripts can miss:

DC services up but DNS broken externally

SYSVOL reachable slowly/hanging

Kerberos/LDAP ports reachable but logon events showing failures

Replication stale but DC “looks fine” locally

Notes / Design Choices

Uses DNS SRV record discovery because it’s the most consistent method.

Uses timeout-safe UNC checks to prevent long hangs.

Event log checks are best-effort and won’t fail the whole run.

Discovery failure fails closed with diagnostics.

Contributing

PRs welcome. Suggestions especially encouraged for:

Additional event IDs worth checking

Better replication heuristics

Better detection of DFSR/SYSVOL issues

Adding optional WMI/LDAP health checks
