# Detection Pipeline Status

> Auto-generated from state machine on 2026-04-01 13:05 UTC
> Run `cd autonomous && python3 orchestration/cli.py export-status` to regenerate

## Summary

| Metric | Count |
|--------|-------|
| Total rules | 95 |
| Sigma | 88 |
| EQL | 3 |
| Threshold | 4 |
| MONITORING | 20 |
| DEPLOYED | 0 |
| VALIDATED | 13 |
| AUTHORED | 23 |
| Needs rework | 0 |

## By State

### MONITORING (20)

- T1016: Detection for T1016 — Network interface configuration (F1=1.0)
- T1021.006: Detection for T1021.006 — Remote WMI execution for lateral movement (F1=1.0)
- T1027: Obfuscated Files or Information (F1=1.0)
- T1027.001: Detection for T1027.001 — Pad binary to exceed AV scan size limit (F1=1.0)
- T1046: Network Service Discovery (F1=1.0)
- T1053.005: Scheduled Task Creation for Persistence (F1=1.0)
- T1059.001: PowerShell Execution with Bypass Flags (F1=0.95)
- T1070.001: Clear Windows Event Logs (F1=1.0)
- T1071.001: C2 Beaconing via HTTP/HTTPS from Unusual Process (F1=1.0)
- T1078.004: Cloud Account Abuse (F1=1.0)
- T1083: File and Directory Discovery (F1=1.0)
- T1105: Ingress Tool Transfer (F1=1.0)
- T1134.001: LSASS Process Access for Token Theft (F1=1.0)
- T1219: Remote Access Software (F1=1.0)
- T1486: Data Encrypted for Impact (F1=1.0)
- T1490: Inhibit System Recovery (F1=1.0)
- T1547.001: Registry Run Key Persistence (F1=1.0)
- T1562.001: AMSI Bypass via CLR Load in Unsigned Process (F1=1.0)
- T1562.006: Impair Defenses: Indicator Blocking (F1=1.0)
- T1566.004: Spearphishing Voice (Vishing) (F1=1.0)

### VALIDATED (13)

- T1003.001: OS Credential Dumping: LSASS Memory (F1=0.8)
- T1016.001: Detection for T1016.001 — ARP table (host discovery) (F1=0.8)
- T1021.001: Remote Services: Remote Desktop Protocol (F1=0.857)
- T1033: Detection for T1033 — Current user and privileges (F1=0.857)
- T1055.001: Process Injection via CreateRemoteThread (F1=1.0)
- T1059.003: Command and Scripting Interpreter: Windows Command Shell (F1=0.75)
- T1082: System Information Discovery (F1=0.75)
- T1133: External Remote Services (F1=0.857)
- T1190: Exploit Public-Facing Application (F1=0.75)
- T1204.002: User Execution: Malicious File (F1=0.75)
- T1543.003: Create or Modify System Process: Windows Service (F1=0.857)
- T1562.004: Impair Defenses: Disable or Modify System Firewall (F1=0.857)
- T1569.002: System Services: Service Execution (F1=1.0)

### AUTHORED (23)

- T1047: Detection for T1047 — Remote/local WMI execution
- T1049: Detection for T1049 — Active network connections (netstat)
- T1053.003: Detection for T1053.003 — Add crontab entry (Linux)
- T1055.004: APC Injection - Suspicious QueueUserAPC Pattern
- T1055.012: Detection for T1055.012 — DLL function pointer overwrite (no new thread)
- T1055.013: Detection for T1055.013 — Ctrl-C handler chain / KernelCallbackTable hijack
- T1055.015: Detection for T1055.015 — 8 variants abusing Windows thread pool internals
- T1055_EQL: Process Injection Sequence - Handle Open Then Remote Thread Creation (EQL)
- T1056.001: Detection for T1056.001 — Low-level keyboard hook via SetWindowsHookEx
- T1057: Detection for T1057 — List running processes (tasklist)
- T1059.001_T1547.001_EQL: PowerShell Execution Followed by Registry Persistence (EQL)
- T1068: Exploitation for Privilege Escalation
- T1070.006: Detection for T1070.006 — Modify file timestamps to hide activity
- T1087.001: Detection for T1087.001 — Enumerate local/domain users and groups
- T1087.002_EQL: Rapid Reconnaissance Command Burst (EQL)
- T1087.002_THRESHOLD: Discovery Command Burst - Recon Tool Threshold
- T1110.001: Brute Force Login - Failed Logon Threshold
- T1134.003: Detection for T1134.003 — Create new token with provided credentials (LogonUser)
- T1135: Detection for T1135 — Enumerate network shares
- T1486_THRESHOLD: Rapid File Modification Burst - Ransomware Indicator (Threshold)
- T1489: Mass Service Stop - Pre-Ransomware Indicator
- T1518.001: Detection for T1518.001 — Detect installed AV/EDR products
- T1562.006: Impair Defenses: Indicator Blocking (F1=1.0)

### REQUESTED (39)

- T1003.003: OS Credential Dumping: NTDS
- T1003.006: OS Credential Dumping: DCSync
- T1018: Remote System Discovery
- T1021.002: Remote Services: SMB/Windows Admin Shares
- T1036.003: Masquerading: Rename System Utilities
- T1036.005: Masquerading: Match Legitimate Name or Location
- T1039: Data from Network Shared Drive
- T1048: Exfiltration Over Alternative Protocol
- T1048.003: Exfiltration Over Unencrypted Non-C2 Protocol
- T1069.002: Permission Groups Discovery: Domain Groups
- T1078.002: Valid Accounts: Domain Accounts
- T1087.002: Detection for T1087.002 — Enumerate local/domain users and groups
- T1090.001: Detection for T1090.001 — Start SOCKS5 proxy listener on agent
- T1090.004: Detection for T1090.004 — Route C2 traffic through CDN
- T1098: Account Manipulation
- T1102: Web Service
- T1110.003: Brute Force: Password Spraying
- T1113: Detection for T1113 — Capture screen
- T1115: Detection for T1115 — Capture clipboard contents
- T1136.001: Create Account: Local Account
- T1136.002: Create Account: Domain Account
- T1189: Drive-by Compromise
- T1218.003: Signed Binary Proxy Execution: Certutil
- T1482: Domain Trust Discovery
- T1497.003: Detection for T1497.003 — Jitter-based sleep to evade beacon detection
- T1543.001: Detection for T1543.001 — macOS LaunchAgent plist creation
- T1552.001: Unsecured Credentials: Credentials in Files
- T1552.004: Detection for T1552.004 — Read private SSH keys from disk
- T1553.002: Subvert Trust Controls: Code Signing
- T1555: Credentials from Password Stores
- T1555.001: Detection for T1555.001 — macOS keychain credential access
- T1560.001: Archive Collected Data: Archive via Utility
- T1560.002: Detection for T1560.002 — Download files from target
- T1567: Exfiltration Over Web Service
- T1568.002: Dynamic Resolution: Domain Generation Algorithms
- T1572: Protocol Tunneling
- T1573.002: Detection for T1573.002 — Encrypted C2 with pinned certificate
- T1574.002: Hijack Execution Flow: DLL Side-Loading
- T1620: Detection for T1620 — Load and execute .NET assembly in-memory

