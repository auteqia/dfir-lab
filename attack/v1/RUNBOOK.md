# Tenenbaum lab – run v1 scenario

> [!warning] Scope
> Everything here runs **only inside the isolated Ludus range** (`ludus testing start` active, Windows VMs cut from the internet). The intrusion exists to produce the forensic artifacts listed in [ARTIFACTS.md](ARTIFACTS.md).

> [!abstract] How to use this file
> - This is the **scenario**: who does what, where, when, with which ATT&CK technique and which family of tool. **Procedures** (exact tools and commands) are chosen and written by the operator during the dry run, mostly from Atomic Red Team tests and the tools' own documentation, and kept in the command log.
> - One **official run** over 3 days. Before it, rehearse each phase on its own from the previous checkpoint snapshot, until every artifact it owns is ticked "Dry run" in `ARTIFACTS.md`.
> - Every action of the official run goes into [GROUND-TRUTH.md](GROUND-TRUTH.md).

---

## Story

**Royal Tenenbaum's household runs on a small Windows domain, `royal.tenenbaums`.** Henry Sherman, the family accountant, receives an invoice from a "supplier". He downloads it and opens it. The attacker gets a foothold on Henry's workstation (WKS01), blinds the local antivirus, digs in, steals the Helpdesk credentials, moves to WKS02 where Royal — a Domain Admin — is always logged on, takes his session, and reaches the domain controller. There, they create a backdoor account, stage data and exfiltrate it. The household's normal life (Henry working, Pagoda doing IT support) continues around the intrusion.

## Defender: on (decision)

Defender stays **enabled** on every Windows VM at baseline. It is expected to **detect** part of the activity before phase 4: those detections (1116/1117) are part of the dataset, and can be the "alert" the investigation starts from. In phase 4 the attacker, now local admin on WKS01, **turns it off and adds exclusions** (5001/5007). WKS02 and DC01 keep Defender on: what it sees there is evidence too.

---

## Rules of the official run

1. Time is always written in **UTC** (VMs are on Eastern time: convert).
2. **No cleanup** that is not part of the story (no Atomic `-Cleanup`). A failed or blocked action is realistic: write it in GROUND-TRUTH and continue.
3. Tools launched from Kali reach the internal network **through the beacon's SOCKS proxy**, never directly.
4. A checkpoint snapshot is a rewind button for **re-acquiring** evidence, never for changing the story.
5. `ludus testing stop` only after **all** evidence is copied out and hashed.

---

## Day 0 — Preparation (before the baseline)

| Step | What | Notes |
|---|---|---|
| 0.1 | Roles applied: logging, AD, workstation, tooling | Tooling = what the scenario needs on Windows, installed while internet is still available |
| 0.2 | Benign-activity routine ready (Henry, Pagoda) | See phase U |
| 0.3 | Restore point (VSS) created on WKS01 | So that phase 4 has a shadow copy to delete |
| 0.4 | Attacker infrastructure on Kali: C2 listener (HTTPS 443), fake "supplier" web site hosting the invoice | Record the SHA256 of every payload |
| 0.5 | `ludus testing start` → snapshot `baseline` | Check log sizes / `RecordCount` before starting |

---

## The scenario, action by action

| # | When | Host | Account | Action in the story | ATT&CK | Tool family | ARTIFACTS § |
|---|---|---|---|---|---|---|---|
| **U** | **all days** | | | **Benign activity** | | | |
| U1 | D1–D3 office hours | WKS01 | henry.sherman | Works in Word / Excel, browses, saves and deletes files, locks and unlocks his session | — | normal use | 1, 3 |
| U2 | D1 morning, D2 | WKS01 | pagoda | IT support session over RDP | — | `mstsc` | 1, 8 |
| **P1** | **Day 1 morning** | | | **Initial access** | | | |
| P1.1 | D1 09:00 | WKS01 | henry.sherman | Henry downloads the "invoice" from the supplier site with Chrome | T1566.002, T1204.002 | browser + lure document | 3 |
| P1.2 | D1 09:05 | WKS01 | henry.sherman | He opens it and enables content; a signed Windows binary is used to fetch and launch the first stage | T1218, T1105 | LOLBin | 2, 3, 4 |
| P1.3 | D1 09:05 | WKS01 | henry.sherman | Defender detects and quarantines part of the first attempt; the operator tries again with another LOLBin | — | LOLBin | 7 |
| P1.4 | D1 09:15 | WKS01 | henry.sherman | A download goes through BITS | T1197 | LOLBin (`bitsadmin`) | 2, 6 |
| **P2** | **Day 1** | | | **Command and control** | | | |
| P2.1 | D1 09:20 → D3 | WKS01 | henry.sherman | The implant checks in over HTTPS with sleep and jitter | T1071.001 | C2 framework | 5, 9 |
| P2.2 | D1 10:00 | WKS01 | henry.sherman | Discovery: host, users, groups, domain, shares | T1082, T1087, T1069, T1135 | C2 + built-in commands | 2 |
| **P3** | **Day 1** | | | **Privilege escalation and injection** | | | |
| P3.1 | D1 10:30 | WKS01 | → local admin | The attacker gains local admin on WKS01 | T1548 / T1068 *(operator's choice)* | — | 1, 2 |
| P3.2 | D1 10:45 | WKS01 | SYSTEM / admin | The implant moves into a legitimate process | T1055, T1055.012 | C2 feature | 9 |
| CP1 | D1 11:00 | WKS01 | | **Checkpoint**: memory dump #1 + snapshot `cp1` | | | |
| **P4** | **Day 1 afternoon** | | | **Defense evasion and anti-forensics** | | | |
| P4.1 | D1 14:00 | WKS01 | admin | Turns Defender real-time protection off, adds exclusions | T1562.001 | PowerShell / built-in | 7 |
| P4.2 | D1 14:10 | WKS01 | admin | Changes the audit policy, clears the Security and System logs | T1562.002, T1070.001 | built-in | 7 |
| P4.3 | D1 14:20 | WKS01 | admin | Cleans the download cache, timestomps and wipes tools, deletes the first stager | T1070.004, T1070.006 | LOLBin + Sysinternals | 4, 7 |
| P4.4 | D1 14:30 | WKS01 | admin | Deletes the shadow copies | T1490 | built-in | 4, 7 |
| **P5** | **Day 1** | | | **Defender-side hunt** (not attacker activity) | | | |
| P5.1 | D1 15:00 | WKS01 | analyst | Code-signing hunt to spot the unsigned stager | — | Sysinternals `sigcheck` | — |
| **P6** | **Day 1 evening** | | | **Persistence** | | | |
| P6.1 | D1 16:00 | WKS01 | henry.sherman | Run key in Henry's hive | T1547.001 | built-in | 6 |
| P6.2 | D1 16:05 | WKS01 | henry.sherman | Shortcut in Henry's Startup folder | T1547.001 | built-in | 6 |
| P6.3 | D1 16:10 | WKS01 | admin | Winlogon Userinit value modified | T1547.004 | built-in | 6 |
| P6.4 | D1 16:15 | WKS01 | admin | New auto-start service | T1543.003 | built-in | 6, 8 |
| P6.5 | D1 16:20 | WKS01 | admin | Scheduled task running as a user with stored credentials | T1053.005 | built-in | 1, 6 |
| P6.6 | D1 16:30 | WKS01 | admin | Signed executable + malicious DLL side-loaded from `ProgramData` | T1574.002 | custom DLL | 6 |
| P6.7 | D1 16:40 | WKS01 | admin | Service with an unquoted path + binary dropped on the writable prefix | T1574.009 | built-in | 6 |
| P6.8 | D1 16:50 | WKS01 | admin | WMI event subscription, then the same through a MOF file compiled with autorecover, MOF deleted | T1546.003 | PowerShell + `mofcomp` | 6 |
| P6.9 | D1 17:00 | WKS01 | admin | BITS job used as persistence | T1197 | LOLBin | 6 |
| CP2 | D1 17:30 | WKS01 | | **Checkpoint**: snapshot `cp2` | | | |
| **R** | **Night 1** | WKS01 | | **Reboot**, Henry logs on again: persistence fires, ShimCache flushed to disk | | | 2, 6 |
| **P7** | **Day 2 morning** | | | **Credential access** | | | |
| P7.1 | D2 09:00 | WKS01 | admin | LSASS dump → Helpdesk credentials (`pagoda`) | T1003.001 | LOLBin | 1 |
| P7.2 | D2 09:30 | WKS01 | henry.sherman | Password spraying against a few domain accounts (fails) | T1110.003 | network tool via proxy | 1 |
| P7.3 | D2 09:45 | WKS01 | henry.sherman | Kerberoasting of `svc_lindbergh` | T1558.003 | network tool via proxy | 1 |
| **P8** | **Day 2** | | | **Lateral movement WKS01 → WKS02 → DC01** | | | |
| P8.1 | D2 10:00 | WKS01 → WKS02 | pagoda | Remote execution with PsExec, current token then explicit credentials | T1021.002, T1569.002 | Sysinternals | 1, 8 |
| P8.2 | D2 10:30 | via WKS01 → WKS02 | pagoda | Remote execution with Impacket-style tools through the SOCKS proxy | T1021.002, T1090 | Impacket | 8 |
| P8.3 | D2 11:00 | WKS01 → WKS02 | pagoda | Remote service creation | T1569.002 | built-in (`sc`) | 8 |
| P8.4 | D2 11:30 | WKS02 | pagoda → admin | LSASS dump on WKS02 → Royal's credentials (Domain Admin) | T1003.001 | LOLBin | 1, 9 |
| P8.5 | D2 12:00 | src → WKS02 | royal.tenenbaum | Pass-the-hash with Royal's hash | T1550.002 | network tool | 1 |
| P8.6 | D2 14:00 | via WKS01 → WKS02 | royal.tenenbaum | **RDP hop 1** through the SOCKS proxy: Royal's console session taken over | T1021.001, T1090 | RDP client on Kali | 1, 8 |
| CP3 | D2 14:30 | WKS02 | | **Checkpoint**: memory dump #2 of WKS02 (sessions open) | | | |
| P8.7 | D2 15:00 | WKS02 → DC01 | royal.tenenbaum | WMI remote process creation | T1047 | built-in (`wmic`) | 8 |
| P8.8 | D2 15:30 | WKS02 → DC01 | royal.tenenbaum | PowerShell Remoting | T1021.006 | PowerShell | 2, 8 |
| P8.9 | D2 16:00 | WKS02 → DC01 | royal.tenenbaum | Remote scheduled task | T1053.005 | built-in (`schtasks`) | 6, 8 |
| P8.10 | D2 16:30 | WKS02 → DC01 | royal.tenenbaum | **RDP hop 2** with `mstsc` from inside the hop-1 session | T1021.001 | `mstsc` | 3, 5, 8 |
| **P9** | **Day 3** | | | **Objective and exfiltration** | | | |
| P9.1 | D3 09:00 | DC01 | royal.tenenbaum | Browses folders in Explorer, uses Win+R, types UNC paths | T1083 | GUI over RDP | 2, 3 |
| P9.2 | D3 09:30 | DC01 | royal.tenenbaum | Creates a backdoor account and adds it to a privileged group | T1136.002, T1098 | built-in | 1 |
| P9.3 | D3 10:00 | DC01 | royal.tenenbaum | Stages data in a folder, compresses it | T1074.001, T1560.001 | archiver | 3, 4 |
| P9.4 | D3 10:30 | DC01 → Kali | royal.tenenbaum | Exfiltrates the archive over the C2 channel | T1041 | C2 framework | 5 |
| P9.5 | D3 11:00 | WKS01 | admin | Last anti-forensic action before leaving | T1070 | built-in | 4, 7 |

---

## Collection (Day 3, right after P9)

Order of volatility, see `capture/`:

1. Memory dump #3 of every Windows VM from Proxmox (`dump-guest-memory`, no footprint inside the VM).
2. Write in GROUND-TRUTH: **attack ends / collection starts** (UTC).
3. DFIR-ORC on each host, writing to the attached collection disk (`/TempDir` on that disk).
4. Copy everything out, SHA256 → `evidence/MANIFEST.md`.
5. Only then: `ludus testing stop`.

---

## Coverage check

Before the official run, every row of [ARTIFACTS.md](ARTIFACTS.md) has its **Dry run** box ticked. After the analysis, every **Found** box is ticked by the blog series.
