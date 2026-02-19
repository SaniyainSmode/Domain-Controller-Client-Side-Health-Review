External DC Health Monitor (Outside-In) — NinjaRMM Safe

A PowerShell 5.1 compatible outside-in Domain Controller health monitor designed for NinjaRMM.

This script runs from a workstation/server joined to the domain, discovers all Domain Controllers via DNS SRV records, and performs multiple health checks per DC — including connectivity, DNS responsiveness, SYSVOL/NETLOGON availability, and replication freshness.

It outputs clean, parseable results and exits with Ninja-friendly exit codes.
