# MITRE ATT&CK Detection Coverage Matrix

**Last updated**: 2026-03-29 (auto-generated)
**Total rules**: 53
**Tactics covered**: 10

## Collection (1 rules, 1 Fawkes-tagged)

| File | Technique | Title | Severity | Fawkes |
|------|-----------|-------|----------|--------|
| t1056_001.yml | attack.t1056.001 | Potential Keylogger - Suspicious Process Loading user32.dll | high | Y |

## Command And Control (1 rules, 0 Fawkes-tagged)

| File | Technique | Title | Severity | Fawkes |
|------|-----------|-------|----------|--------|
| t1071_001.yml | attack.t1071.001 | C2 Beaconing via HTTP/HTTPS from Unusual Process [T1071.001] | high |   |

## Credential Access (3 rules, 2 Fawkes-tagged)

| File | Technique | Title | Severity | Fawkes |
|------|-----------|-------|----------|--------|
| t1003_001.yml | attack.t1003.001 | LSASS Credential Dumping Activity Detected | high |   |
| t1110_001_brute_force_threshold.yml | attack.t1110.001 | Brute Force Login - Failed Logon Threshold | medium | Y |
| t1134_001_lsass_token_theft.yml | attack.t1134.001 | LSASS Process Access for Token Theft | critical | Y |

## Defense Evasion (9 rules, 4 Fawkes-tagged)

| File | Technique | Title | Severity | Fawkes |
|------|-----------|-------|----------|--------|
| t1027.yml | attack.t1027 | Obfuscated PowerShell Execution With Encoded Command and Suspicious Indicators | high |   |
| t1027_001.yml | attack.t1027.001 | Fawkes Binary Inflation via PowerShell WriteAllBytes Null Byte Padding | high |   |
| t1070_001.yml | attack.t1070.001 | Clear Windows Event Logs [T1070.001] | high |   |
| t1070_006.yml | attack.t1070.006 | Suspicious File Timestamp Modification (Timestomping) | high | Y |
| t1078_004.yml | attack.t1078.004 | Cloud Account Abuse [T1078.004] | medium |   |
| t1562_001.yml | attack.t1562.001 | AMSI Bypass via CLR Load in Unsigned Process [T1562.001] | high | Y |
| t1562_004.yml | attack.t1562.004 | Windows Firewall Disabled via Netsh or Registry Modification | high |   |
| t1562_006.yml | attack.t1562.006 | Indicator Blocking via Audit Policy Disable [T1562.006] | high | Y |
| t1562_006_registry.yml | attack.t1562.006 | Indicator Blocking via Sysmon or ETW Registry Tampering [T1562.006] | critical | Y |

## Discovery (8 rules, 6 Fawkes-tagged)

| File | Technique | Title | Severity | Fawkes |
|------|-----------|-------|----------|--------|
| t1046.yml | attack.t1046 | Network Service Discovery via Port Scanning from Suspicious Location | medium |   |
| t1049.yml | attack.t1049 | Network Connection Enumeration from Suspicious Parent | medium | Y |
| t1057.yml | attack.t1057 | Process Discovery via Tasklist/WMIC from Suspicious Parent | medium | Y |
| t1083.yml | attack.t1083 | Recursive File and Directory Discovery via Suspicious Parent | medium |   |
| t1087_001.yml | attack.t1087.001 | Local Account Discovery via Net/WMIC Commands | medium | Y |
| t1087_002_discovery_burst_eql.yml | attack.t1087.002 | Rapid Reconnaissance Command Burst | high | Y |
| t1087_002_discovery_threshold.yml | attack.t1087.002 | Discovery Command Burst - Recon Tool Threshold | high | Y |
| t1518_001.yml | attack.t1518.001 | Security Software Discovery via WMI or Service Queries [T1518.001] | medium | Y |

## Execution (17 rules, 4 Fawkes-tagged)

| File | Technique | Title | Severity | Fawkes |
|------|-----------|-------|----------|--------|
| t1016.yml | attack.t1016 | Network Configuration Discovery via Suspicious Parent Process | medium |   |
| t1016_001.yml | attack.t1016.001 | ARP Cache Enumeration by Suspicious Parent Process | medium |   |
| t1021_001.yml | attack.t1021.001 | RDP Client Lateral Movement Activity | high |   |
| t1021_006.yml | attack.t1021.006 | Remote WMI Process Execution via WMIC /node and process call create | high |   |
| t1033.yml | attack.t1033 | System Owner Discovery via Suspicious Parent Process | high |   |
| t1047.yml | attack.t1047 | Remote WMI Process Creation via WMIC | critical | Y |
| t1059_001_powershell_bypass.yml | attack.t1059.001 | PowerShell Execution with Bypass Flags | high | Y |
| t1059_001_t1547_001_persistence_after_exec_eql.yml | attack.t1059.001 | PowerShell Execution Followed by Registry Persistence | high | Y |
| t1059_003.yml | attack.t1059.003 | Suspicious CMD.exe Execution with Chained Reconnaissance Commands | medium |   |
| t1082.yml | attack.t1082 | System Information Discovery Command Burst via Suspicious Parent | medium |   |
| t1105.yml | attack.t1105 | Executable Dropped or C2 Network Activity from Suspicious Directory - Ingress Tool Transfer | high |   |
| t1133.yml | attack.t1133 | Suspicious Remote Service Binary Launched From User Directory | high |   |
| t1190.yml | attack.t1190 | Suspicious Child Process Spawned by Web Server Application | critical |   |
| t1204_002.yml | attack.t1204.002 | Office Application Spawning Process from Suspicious Directory | high |   |
| t1486.yml | attack.t1486 | Ransomware File Extension Modification Indicating Data Encryption for Impact | critical |   |
| t1490.yml | attack.t1490 | Inhibit System Recovery via Shadow Copy Deletion or Recovery Disable | high |   |
| t1569_002.yml | attack.t1569.002 | Service Execution via sc.exe with Suspicious Binary Path [T1569.002] | high | Y |

## Impact (2 rules, 2 Fawkes-tagged)

| File | Technique | Title | Severity | Fawkes |
|------|-----------|-------|----------|--------|
| t1486_file_encryption_threshold.yml | attack.t1486 | Rapid File Modification Burst - Ransomware Indicator | critical | Y |
| t1489_mass_service_stop_threshold.yml | attack.t1489 | Mass Service Stop - Pre-Ransomware Indicator | high | Y |

## Initial Access (2 rules, 0 Fawkes-tagged)

| File | Technique | Title | Severity | Fawkes |
|------|-----------|-------|----------|--------|
| t1219.yml | attack.t1219 | Remote Access Software [T1219] | high |   |
| t1566_004.yml | attack.t1566.004 | Spearphishing Voice (Vishing) [T1566.004] | medium |   |

## Persistence (4 rules, 3 Fawkes-tagged)

| File | Technique | Title | Severity | Fawkes |
|------|-----------|-------|----------|--------|
| t1053_003.yml | attack.t1053.003 | Suspicious Crontab Modification with Persistence Indicators | high | Y |
| t1053_005.yml | attack.t1053.005 | Scheduled Task Creation for Persistence [T1053.005] | high | Y |
| t1543_003.yml | attack.t1543.003 | Suspicious Windows Service Creation via Sc.exe with User-Writable Binary Path | high |   |
| t1547_001_registry_run_key.yml | attack.t1547.001 | Registry Run Key Persistence | high | Y |

## Privilege Escalation (7 rules, 7 Fawkes-tagged)

| File | Technique | Title | Severity | Fawkes |
|------|-----------|-------|----------|--------|
| t1055_001.yml | attack.t1055.001 | CreateRemoteThread from Suspicious Process [T1055.001] | high | Y |
| t1055_004_apc_injection.yml | attack.t1055.004 | APC Injection - Suspicious QueueUserAPC Pattern | high | Y |
| t1055_012.yml | attack.t1055.012 | Threadless Process Injection - Suspicious Handle with Write Access | critical | Y |
| t1055_013.yml | attack.t1055.013 | Opus Injection - Suspicious Full Access to Console Host Process | critical | Y |
| t1055_015.yml | attack.t1055.015 | PoolParty Injection - Full Access to svchost from User-Writable Path | critical | Y |
| t1055_sequence_eql.yml | attack.t1055.001 | Process Injection Sequence - Handle Open Then Remote Thread Creation | critical | Y |
| t1068.yml | attack.t1068 | Suspicious Process Accessing Privileged System Process with Full Access | critical | Y |

