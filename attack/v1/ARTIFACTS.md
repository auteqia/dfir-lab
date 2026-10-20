# Tenenbaum lab – artifacts to produce and collect (run v1)

> [!abstract] What this file is
> Every forensic artifact the official run must leave behind, grouped by **the question it answers** during the investigation. Each row says which attack action produces it, on which host, and how it is collected. The blog posts must recover **every** row.

## Overview: 9 questions

1. **Who logged on, and how?** — logon types, failed logons, Kerberos/NTLM, stolen credentials, new accounts
2. **What was executed?** — 4688, Sysmon 1, Prefetch, Amcache, ShimCache, BAM, UserAssist, RunMRU, PCA, SRUM, PowerShell
3. **Which files and folders were seen or opened?** — LNK, Jump Lists, RecentDocs, Office Trust Records, ShellBags, Recycle Bin, Chrome, Mark of the Web
4. **What does the file system say?** — $MFT, $UsnJrnl, $LogFile, $I30, ADS, shadow copies
5. **What talked on the network?** — SRUM network, Sysmon 3/22, RDP client traces, RDP bitmap cache
6. **How did the attacker stay?** — Run key, Winlogon, Startup, service, task, DLL side-loading, unquoted path, WMI + MOF, BITS
7. **What did the attacker try to hide?** — log clearing, audit change, Defender tampering, timestomping, wiping, VSS deletion
8. **How did the attacker move?** — PsExec, Impacket, WMI, WinRM, RDP (2 hops), remote service, remote task — source **and** destination
9. **What only memory shows** — injection, beacon and its configuration, live connections, credentials in LSASS

Annexes: A. timing traps · B. known lab noise

## Legend

- **Hosts**: `WKS01` (patient zero, `henry.sherman`) · `WKS02` (Royal's session) · `DC01` · `kali` (attacker, VLAN 99)
- **Phases** (see [RUNBOOK.md](RUNBOOK.md)): `P1` initial access · `P2` beaconing · `P3` injection · `P4` defense evasion · `P5` code-signing hunt · `P6` persistence · `P7` credential access · `P8` lateral movement · `P9` objective + exfiltration · `U` benign user activity · `R` reboot / logon during the run
- **Collect**: `ORC` = DFIR-ORC triage · `LOG` = event logs (inside ORC) · `MEM` = memory dump · `LIVE` = only on the running system
- **Dry run** ☑ = seen on the VM during the rehearsal (the action and the logging work) · **Found** ☑ = recovered from the collected evidence during the analysis

---

## 1. Who logged on, and how?

### Logon types (Security 4624 / 4625)

| Type | Meaning | Action that produces it | Phase | Host | Dry run | Found |
|---|---|---|---|---|---|---|
| 2 | Interactive | Autologon of Henry (WKS01) and Royal (WKS02); `psexec -u` (also creates a type 2 on the target) | R, P8 | WKS01, WKS02 | ☐ | ☐ |
| 3 | Network | PsExec, WMIC, WinRM, SMB share access, pass-the-hash | P8 | destinations | ☐ | ☐ |
| 4 | Batch | Scheduled task running as a user with stored password | P6 | WKS01 | ☐ | ☐ |
| 5 | Service | Persistence service starts at boot | P6, R | WKS01 | ☐ | ☐ |
| 7 | Unlock | Henry locks (Win+L) and unlocks his session | U | WKS01 | ☐ | ☐ |
| 9 | NewCredentials | `runas /netonly`, or pass-the-hash (logon process `seclogo`) | P7 | source of PtH | ☐ | ☐ |
| 10 | RemoteInteractive (RDP) | RDP to DC01 as Royal; Pagoda's "support" RDP to WKS01 | P9, U | DC01, WKS01 | ☐ | ☐ |
| 11 | CachedInteractive | *(optional)* interactive logon while the DC is unreachable | — | WKS | ☐ | ☐ |
| 4625 | Failed logon | Wrong password during spraying / a typo by the attacker | P7, P8 | targets | ☐ | ☐ |

Read together with **4648** (explicit credentials, on the **source**) · **4672** (admin logon) · **4634/4647** (logoff) · **4778/4779** (RDP reconnect/disconnect).

### Domain authentication, stolen credentials, new accounts

| Artifact | Where | Produced by | Phase | Host | Collect | Dry run | Found |
|---|---|---|---|---|---|---|---|
| 4768 / 4769 / 4771 / 4776 (TGT / service ticket / pre-auth failed / NTLM) | Security | Domain logons, Kerberoasting, PtH | P7, P8 | DC01 | LOG | ☐ | ☐ |
| Kerberoasting `svc_lindbergh` | Security 4769 with encryption type `0x17` (RC4) for `MSSQLSvc/DB01…` | Service ticket request for the SPN | P7 | DC01 | LOG | ☐ | ☐ |
| Pass-the-hash | Source: 4624 type 9 (`seclogo`) · destination: 4624 type 3 NTLM · DC: 4776 | Reuse of a stolen NTLM hash | P7 | src, dest, DC01 | LOG | ☐ | ☐ |
| Password spraying | 4625 / 4771 burst | A few accounts, one password | P7 | DC01 | LOG | ☐ | ☐ |
| LSASS dump (`comsvcs.dll MiniDump`) | Sysmon 10 (`TargetImage=lsass.exe`, `GrantedAccess`), 4688 command line, the `.dmp` in $MFT / USN | Credential dumping | P7 | WKS01, WKS02 | LOG + ORC | ☐ | ☐ |
| Royal's credentials taken on WKS02 | Same on WKS02 (autologon session = Royal in LSASS) | Credential dumping | P7 | WKS02 | LOG + MEM | ☐ | ☐ |
| 4720 / 4728 / 4732 (account created / added to group) | Security | Backdoor account created as Royal | P9 | DC01 | LOG | ☐ | ☐ |

---

## 2. What was executed?

| Artifact | Where | Produced by | Phase | Host | Collect | Dry run | Found |
|---|---|---|---|---|---|---|---|
| **4688 / 4689** (process create / exit, with command line) | Security | Every execution | all | all | LOG | ☐ | ☐ |
| **Sysmon** 1, 3, 7, 8, 10, 11, 13, 15, 17/18, 19/20/21, 22, 23/26 | Sysmon/Operational | All phases (process, network, image load, remote thread, LSASS access, files, registry, ADS, pipes, WMI, DNS, deletes) | all | all | LOG | ☐ | ☐ |
| **Prefetch** | `C:\Windows\Prefetch\*.pf` | Every binary run (stager, LOLBins, `PSEXEC`, `PSEXESVC`, `WMIPRVSE`, `WSMPROVHOST`, `SCRCONS`, `MOFCOMP`, `SDELETE`) | all | WKS01, WKS02 (**disabled by default on servers**: none on DC01) | ORC | ☐ | ☐ |
| **Amcache** | `C:\Windows\appcompat\Programs\Amcache.hve` (`InventoryApplicationFile`: path + SHA1) | Every new executable dropped (stager, renamed tool, side-loaded EXE/DLL) | P1, P6, P8 | all | ORC | ☐ | ☐ |
| **ShimCache** (AppCompatCache) | `SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache` | Same; **written to the hive only at shutdown** | all | all | ORC + MEM | ☐ | ☐ |
| **BAM / DAM** | `SYSTEM\CurrentControlSet\Services\bam\State\UserSettings\<SID>` | Executables run in a user session | P1, P9 | WKS01, DC01 | ORC | ☐ | ☐ |
| **UserAssist** | `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{GUID}\Count` (ROT13) | GUI launches (Henry opening Word, attacker over RDP) | U, P9 | WKS01, DC01 | ORC | ☐ | ☐ |
| **RunMRU** | `NTUSER.DAT\...\Explorer\RunMRU` | Attacker uses Win+R during the RDP session | P9 | DC01 | ORC | ☐ | ☐ |
| **PCA** (Windows 11 22H2+) | `C:\Windows\appcompat\pca\PcaAppLaunchDic.txt`, `PcaGeneralDb0.txt` | Programs launched from Explorer | P1, U | WKS01, WKS02 | ORC | ☐ | ☐ |
| **SRUM – application usage** | `C:\Windows\System32\sru\SRUDB.dat` (Application Resource Usage) | The beacon and tools running for a while | P2 | WKS01 | ORC | ☐ | ☐ |
| **Jump Lists** | `%APPDATA%\Microsoft\Windows\Recent\AutomaticDestinations\` | Word opening the lure; `mstsc` (RDP targets) | P1, P8 | WKS01, WKS02 | ORC | ☐ | ☐ |
| **PowerShell script blocks** 4103 / 4104, 40961/40962, 53504 | PowerShell/Operational | Every PowerShell use, obfuscated cradle | P1, P8 | all | LOG | ☐ | ☐ |
| **PowerShell engine** 400 / 403 / 800 | Windows PowerShell | Remoting (`HostName=ServerRemoteHost`), local use | P1, P8 | src + dest | LOG | ☐ | ☐ |
| **PowerShell history** | `%APPDATA%\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt` | Commands typed interactively (not inside remote sessions) | P8, P9 | WKS02, DC01 | ORC | ☐ | ☐ |
| **Services / tasks as execution proof** | 7045, 4698 + `C:\Windows\System32\Tasks\` | See questions 6 and 8 | P6 | WKS01 | ORC | ☐ | ☐ |

---

## 3. Which files and folders were seen or opened?

| Artifact | Where | Produced by | Phase | Host | Collect | Dry run | Found |
|---|---|---|---|---|---|---|---|
| **Chrome history + downloads** | `%LOCALAPPDATA%\Google\Chrome\User Data\Default\History` | Henry downloads the lure from the "supplier" site (Kali web server) | P1 | WKS01 | ORC | ☐ | ☐ |
| **Mark of the Web** | `<file>:Zone.Identifier` (`ZoneId=3`, `HostUrl`) | Chrome download of the lure | P1 | WKS01 | ORC | ☐ | ☐ |
| **LNK files** | `%APPDATA%\Microsoft\Windows\Recent\*.lnk` | Henry opens the invoice | P1 | WKS01 | ORC | ☐ | ☐ |
| **RecentDocs** | `NTUSER.DAT\...\Explorer\RecentDocs` | Same | P1 | WKS01 | ORC | ☐ | ☐ |
| **OpenSave / LastVisited MRU** | `NTUSER.DAT\...\Explorer\ComDlg32\{OpenSavePidlMRU,LastVisitedPidlMRU}` | "Save as" of the attachment, file dialogs | P1, U | WKS01 | ORC | ☐ | ☐ |
| **Office MRU + Trust Records** | `NTUSER.DAT\Software\Microsoft\Office\16.0\Word\{File MRU, Security\Trusted Documents\TrustRecords}` | Henry clicks **Enable Content** on the lure | P1 | WKS01 | ORC | ☐ | ☐ |
| **Recycle Bin** | `C:\$Recycle.Bin\<SID>\$I*, $R*` | Henry deletes the invoice after opening it | U | WKS01 | ORC | ☐ | ☐ |
| **ShellBags** | `UsrClass.dat\Local Settings\Software\Microsoft\Windows\Shell\BagMRU` (+ `NTUSER.DAT\...\Shell\BagMRU`) | Attacker browses folders in Explorer over RDP (`C:\Windows\NTDS`, shares, staging folder) | P9 | DC01 (Royal's hives) | ORC | ☐ | ☐ |
| **TypedPaths / WordWheelQuery** | `NTUSER.DAT\...\Explorer\{TypedPaths, WordWheelQuery}` | Attacker types a UNC path / searches in Explorer | P9 | DC01 | ORC | ☐ | ☐ |

---

## 4. What does the file system say?

| Artifact | Where | Produced by | Phase | Host | Collect | Dry run | Found |
|---|---|---|---|---|---|---|---|
| **$MFT** | `C:\$MFT` | Every file created; **timestomped stager** ($SI ≠ $FN, `.0000000` nanoseconds) | P1, P4 | all | ORC | ☐ | ☐ |
| **$UsnJrnl:$J** | `C:\$Extend\$UsnJrnl:$J` | Create / rename / delete: stager deleted after use, `sdelete` renames (`AAAA…`), `.mof` deleted after compile | P1, P4, P6 | WKS01 | ORC | ☐ | ☐ |
| **$LogFile** | `C:\$LogFile` | Last minutes of NTFS activity only (circular): the anti-forensics just before collection | P4, P9 | WKS01 | ORC | ☐ | ☐ |
| **$I30** (directory index slack) | Directory INDX records | Names of deleted files in the staging folder | P4 | WKS01 | ORC | ☐ | ☐ |
| **ADS** | `file:stream` | `certutil` writing into an ADS; Zone.Identifier | P1 | WKS01 | ORC | ☐ | ☐ |
| **Volume Shadow Copies** | `\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy*` | A restore point before the attack, then `vssadmin delete shadows` | P4 | WKS01 | LIVE / disk image | ☐ | ☐ |

---

## 5. What talked on the network?

| Artifact | Where | Produced by | Phase | Host | Collect | Dry run | Found |
|---|---|---|---|---|---|---|---|
| **SRUM – network data usage** | `SRUDB.dat` (bytes sent / received per app) | Beacon traffic, exfiltration | P2, P9 | WKS01, DC01 | ORC | ☐ | ☐ |
| **SRUM – network connectivity** | `SRUDB.dat` (interfaces, connection durations) | Normal activity | — | all | ORC | ☐ | ☐ |
| **Sysmon 3 / 22** (connections / DNS) | Sysmon/Operational | LOLBin reaching Kali, beacon, DNS lookups | P1, P2 | WKS01 | LOG | ☐ | ☐ |
| **RDP client traces** | `NTUSER.DAT\Software\Microsoft\Terminal Server Client\{Default, Servers\<host>\UsernameHint}`, `Documents\Default.rdp` | `mstsc` to DC01 (RDP hop 2) | P8 | WKS02 | ORC | ☐ | ☐ |
| **RDP bitmap cache** | `%LOCALAPPDATA%\Microsoft\Terminal Server Client\Cache\{bcache24.bmc, Cache0000.bin}` | Screen tiles of the DC01 session (bmc-tools) | P8 | WKS02 | ORC | ☐ | ☐ |
| **Network connections in RAM** | `windows.netscan` | Beacon, remote sessions | P2, P8 | all | MEM | ☐ | ☐ |
| **Kali-side capture** *(optional)* | `tcpdump` on the router / Kali | Beacon periodicity (sleep / jitter) | P2 | kali | pcap | ☐ | ☐ |

---

## 6. How did the attacker stay? (all planted in P6, on WKS01)

| Mechanism | Where | Fires on | Collect | Dry run | Found |
|---|---|---|---|---|---|
| Run key | `NTUSER.DAT\...\CurrentVersion\Run` (+ key LastWrite) | Henry's logon | ORC | ☐ | ☐ |
| Winlogon Userinit | `SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\Userinit` | Any logon | ORC | ☐ | ☐ |
| Startup folder | `%APPDATA%\...\Start Menu\Programs\Startup\*.lnk` | Henry's logon | ORC | ☐ | ☐ |
| Service | `SYSTEM\CurrentControlSet\Services\<name>` + System 7045 / Security 4697 | Boot | ORC + LOG | ☐ | ☐ |
| Scheduled task | `C:\Windows\System32\Tasks\<name>` + `SOFTWARE\...\Schedule\TaskCache\{Tree,Tasks}` + Security 4698/4699/4702 | Trigger | ORC + LOG | ☐ | ☐ |
| Scheduled task events | TaskScheduler/Operational 106 / 140 / 141 / 200 / 201 | Registration, runs | LOG | ☐ | ☐ |
| DLL side-loading | Signed EXE + DLL in `C:\ProgramData\<vendor>\`; Sysmon 7 `Signed=false` | Launch of the EXE | ORC + LOG | ☐ | ☐ |
| Unquoted service path | `ImagePath` without quotes + `C:\Program.exe` | Service start | ORC | ☐ | ☐ |
| WMI subscription | `C:\Windows\System32\wbem\Repository\OBJECTS.DATA` + WMI-Activity **5861** + Sysmon 19/20/21 | Boot (+4 min) | ORC + LOG | ☐ | ☐ |
| MOF autorecover | `SOFTWARE\Microsoft\Wbem\CIMOM\Autorecover MOFs` (path survives deletion of the `.mof`) | Repository rebuild | ORC | ☐ | ☐ |
| BITS job | `C:\ProgramData\Microsoft\Network\Downloader\qmgr.db` + Bits-Client 3 / **59** (URL) / 60 / 4 | Job completion | ORC + LOG | ☐ | ☐ |
| **Autoruns stacking** | `autorunsc -a * -c -h -s -t '*'` on all hosts, compared to the baseline | — | LIVE | ☐ | ☐ |

> [!important] A persistence mechanism only leaves **execution** artifacts if it fires: plan at least one reboot (`R`) and one new logon between P6 and the collection.

---

## 7. What did the attacker try to hide? (P4, on WKS01)

| Action | Artifact | Collect | Dry run | Found |
|---|---|---|---|---|
| Clear Security / System logs | Security **1102**, System **104**, and **the gap** before them | LOG | ☐ | ☐ |
| Audit policy change | Security **4719** | LOG | ☐ | ☐ |
| Defender detection before the bypass | Defender **1116 / 1117**, quarantine folder | LOG + ORC | ☐ | ☐ |
| Defender real-time off + exclusion | Defender **5001 / 5007**, `...\Windows Defender\Exclusions\Paths`, `MPLog-*.log` in `C:\ProgramData\Microsoft\Windows Defender\Support\` | LOG + ORC | ☐ | ☐ |
| PowerShell v2 downgrade | Windows PowerShell 400 `EngineVersion=2.0` | LOG | ☐ | ☐ |
| `certutil -urlcache * delete` | Command line (4688 / Sysmon 1); `CryptnetUrlCache\{Content,MetaData}` before/after | LOG + ORC | ☐ | ☐ |
| Timestomp the stager | $SI vs $FN in $MFT, Sysmon 2 (file creation time changed) | ORC + LOG | ☐ | ☐ |
| `sdelete` a tool | Prefetch `SDELETE*.pf`, USN renames, $I30 slack | ORC | ☐ | ☐ |
| Delete shadow copies | `vssadmin` / `wmic shadowcopy delete` command line | LOG | ☐ | ☐ |
| Delete the stager | USN delete record, $MFT entry (unallocated), Amcache / ShimCache still list it | ORC | ☐ | ☐ |

---

## 8. How did the attacker move? (P8)

Run each technique once; record source → destination in [GROUND-TRUTH.md](GROUND-TRUTH.md).
Tools run from Kali (Impacket, `xfreerdp`) go **through the beacon's SOCKS proxy**, as a real external attacker would: the destination sees a compromised host as the source, never `10.1.99.1`.

| Technique | Source artifacts | Destination artifacts | Path | Dry run | Found |
|---|---|---|---|---|---|
| PsExec (current token) | Prefetch `PSEXEC`, `EulaAccepted`, Amcache | 4624 t3, 4672, 7045 `PSEXESVC`, Prefetch `PSEXESVC`, pipes `PSEXESVC-<src>-…`, `C:\Windows\PSEXESVC.exe` | WKS01 → WKS02 | ☐ | ☐ |
| PsExec `-u -p` | + 4648 | + 4624 **type 2**, creds cached in LSASS | WKS01 → WKS02 | ☐ | ☐ |
| Impacket `psexec.py` | Nothing on Windows (runs on Kali) | Random 4-letter service, random `.exe` in `ADMIN$`, `RemCom_*` pipes | kali via WKS01 (SOCKS) → WKS02 | ☐ | ☐ |
| Impacket `smbexec.py` | — | Service `BTOBTO` per command, `%COMSPEC% … __output` | kali via WKS01 (SOCKS) → WKS02 | ☐ | ☐ |
| WMIC `/node` | 4648, Prefetch `WMIC` | `WmiPrvSE.exe` → child, WMI-Activity 5857, Prefetch `WMIPRVSE` | WKS02 → DC01 | ☐ | ☐ |
| PowerShell Remoting | WinRM **6** (contains the destination), 4104, `ConsoleHost_history.txt` | `wsmprovhost.exe`, WinRM **91 / 168**, 4103/4104, Prefetch `WSMPROVHOST` | WKS02 → DC01 | ☐ | ☐ |
| RDP hop 1 (`xfreerdp` on Kali through the SOCKS proxy) | **None on WKS01**: no `mstsc`, no bitmap cache — only the proxied connection (Sysmon 3 from the beacon process to WKS02:3389) | Source IP = WKS01. Royal's console session taken over: 4624 t10, **4778 reconnect**, LSM 25, RCM 1149 | WKS01 (proxy) → WKS02 | ☐ | ☐ |
| RDP hop 2 (`mstsc` inside the hop-1 session) | `mstsc` Jump List, `Terminal Server Client` keys, **bitmap cache**, RDPClient **1024 / 1102** | 4624 t10, 4778/4779, LSM **21/22/24/25**, RCM **1149**, Royal's ShellBags / RunMRU | WKS02 → DC01 | ☐ | ☐ |
| Remote service (`sc \\host create`) | 4648 | 7045 / 4697 without `PSEXESVC` | WKS01 → WKS02 | ☐ | ☐ |
| Remote scheduled task (`schtasks /s`) | 4648 | 4698, TaskScheduler 106/200, `Tasks\` file | WKS02 → DC01 | ☐ | ☐ |
| Share access | — | Security **5140 / 5145** (`ADMIN$`, `C$`, `IPC$`, exfil share) | all destinations | ☐ | ☐ |
| Service events | — | System **7045 / 7036 / 7040**, Security 4697 (PsExec, Impacket, remote service) | all destinations | ☐ | ☐ |

> [!tip] The comparison is the lesson: stack all 7045 and all 4624 type 3 + 4648 pairs across the three hosts.

---

## 9. What only memory shows

| What | Plugin / tool | Expected finding | Dry run | Found |
|---|---|---|---|---|
| Process tree vs normal | `windows.pstree`, `windows.cmdline` | Office → LOLBin → stager; spawn-to `rundll32` without arguments | ☐ | ☐ |
| Injection / hollowing | `windows.malfind`, `windows.ldrmodules`, `windows.hollowprocesses`, `windows.vadinfo` | RWX private memory, PEB/VAD mismatch | ☐ | ☐ |
| Beacon network | `windows.netscan` | Connection to `10.1.99.1:443` | ☐ | ☐ |
| Beacon configuration | C2 config extraction on the dumped process | C2 address, sleep, jitter | ☐ | ☐ |
| Named pipes / handles | `windows.handles` | C2 pipes, `PSEXESVC-*` | ☐ | ☐ |
| Services | `windows.svcscan` | Persistence service, `PSEXESVC` | ☐ | ☐ |
| ShimCache in memory | `windows.shimcachemem` | Entries not yet flushed to SYSTEM | ☐ | ☐ |
| Credentials | `windows.hashdump`, `windows.lsadump`, `windows.cachedump` | Royal on WKS02, LSA secrets (autologon) | ☐ | ☐ |
| WMI in memory | strings / `windows.vadyarascan` on `WmiPrvSE` | Consumer command line | ☐ | ☐ |
| Remote sessions | `wsmprovhost.exe`, `PSEXESVC.exe` processes | Lateral movement still running | ☐ | ☐ |

---

## Annex A. Timing traps

| Artifact | Trap | What to do |
|---|---|---|
| ShimCache | Written to disk only at shutdown | Reboot WKS01 once after P6; also compare with memory |
| SRUM | Flushed to `SRUDB.dat` roughly every hour | Let the beacon run > 1 h before collecting |
| $LogFile | Circular, covers minutes to hours | Collect soon after the last anti-forensic action |
| Prefetch | Written ~10 s after execution | Wait before dumping / collecting |
| Persistence | No execution artifacts until it fires | Reboot + logon between P6 and collection |
| Event logs | A full log overwrites the start of the intrusion | Sizes set by `tenenbaum_logging`; check `RecordCount` vs max before P1 |
| Collection itself | DFIR-ORC creates processes, Prefetch and 4688 | Memory first, then ORC; record the exact start time in GROUND-TRUTH |

## Annex B. Known lab noise (not attacker activity)

Documented in `scenario/LAB-NOISE.md`. Do not "discover" these during the analysis:

- Ludus autologon on every Windows VM (`Winlogon\AutoAdminLogon`, `DefaultPassword` in clear text) — overridden by `tenenbaum_workstation`
- `C:\LabSetup\` (Sysmon installer, `kb5020044.msu`) and the KB5020044 installation + reboot on WKS01/WKS02
- Sysmon service and driver, audit policy changes (4719) made by `tenenbaum_logging` before the baseline
- Ansible/WinRM logons from the Ludus server (4624 type 3, `wsmprovhost.exe`) during provisioning
- Time jump on the workstations at domain join
