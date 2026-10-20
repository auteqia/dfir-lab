# Tenenbaum lab – run v1 runbook

> [!warning] Scope
> Everything here runs **only inside the isolated Ludus range** (`ludus testing start` active, Windows VMs cut from the internet). The intrusion exists to produce the forensic artifacts listed in [ARTIFACTS.md](ARTIFACTS.md).

> [!abstract] How to use this file
> - **One official run** covers every phase below, over 3 days.
> - Before it, **rehearse each phase on its own** (dry run), starting from the checkpoint snapshot of the previous phase. Repeat a phase until every artifact it owns is ticked "Dry run" in `ARTIFACTS.md`.
> - Each phase uses the same template. **Procedure** is filled in during the dry run, from the Atomic Red Team test or the tool's documentation, and copied into the command log.
> - Every action of the official run goes into [GROUND-TRUTH.md](GROUND-TRUTH.md) (UTC time, host, account, action).

---

## Rules of the official run

1. Time is always written in **UTC** (the VMs are on Eastern time: convert).
2. **No cleanup** that is not part of the story (no Atomic `-Cleanup`, no reverting a mistake). A mistake is realistic: write it in GROUND-TRUTH and continue.
3. Tools launched from Kali go **through the beacon's SOCKS proxy**, never directly.
4. A checkpoint snapshot is a rewind button for **re-acquiring** evidence, never for changing the story.
5. `ludus testing stop` only after **all** evidence is copied out of the range and hashed.

---

## Timeline of the run

| Day | Phases | End of day |
|---|---|---|
| **Day 0** (before) | Baseline: workstation role, tooling, benign activity script running, VSS restore point on WKS01, `ludus testing start` | Snapshot `baseline` (all VMs) |
| **Day 1** | U, P1 → P6 on WKS01 | Checkpoint `cp1` after P3 (+ memory dump #1), `cp2` after P6 |
| **Night 1** | **R**: reboot WKS01, Henry logs on again → persistence fires, ShimCache flushed | — |
| **Day 2** | P7, P8 (WKS01 → WKS02 → DC01) | Memory dump #2 of WKS02 while the sessions are open |
| **Day 3** | P9 objective + exfiltration, last anti-forensics | Memory dumps #3 (all), then DFIR-ORC on all hosts |

---

## Phase template

```
## Phase N — <name>                                   ATT&CK: Txxxx
Story          : what the attacker wants, in one sentence
Host / account : where it runs, as whom
Prerequisites  : state expected before starting (previous phase done, checkpoint)
Procedure      : (filled during the dry run) Atomic test ID / tool doc reference
Verify now     : ARTIFACTS.md rows to check immediately on the VM
Checkpoint     : snapshot / memory dump, if any
Ground truth   : line(s) to write in GROUND-TRUTH.md
```

---

## Phase U — Benign activity (Day 0 → Day 3)

- **Story**: Henry works normally (Word, Excel, browsing, files saved and deleted); Pagoda connects over RDP for "support"; Henry locks and unlocks his session.
- **Host / account**: WKS01 (`henry.sherman`, `pagoda`)
- **Verify now**: ARTIFACTS §1 (types 2, 7, 10), §4 (LNK, RecentDocs, Recycle Bin, Chrome history)
- **Why**: the analyst must separate normal from malicious.

## Phase 0 — Attacker infrastructure (Kali)

- **Story**: C2 listener (HTTPS 443) and a fake "supplier" web site hosting the lure.
- **Verify now**: WKS01 reaches Kali on 80/443/8080 only.
- **Ground truth**: SHA256 of every payload.

## Phase 1 — Initial access (WKS01, `henry.sherman`)

- **Story**: Henry downloads an invoice from the supplier site with Chrome, opens it; a living-off-the-land binary pulls the stager.
- **ATT&CK**: T1566 (lure), T1218.005, T1105, T1197
- **Verify now**: ARTIFACTS §2 (4688, Sysmon 1/3, BITS 59), §3 (Prefetch, Amcache, PCA), §4 (Chrome downloads, Mark of the Web, Office Trust Records, LNK)
- **Open question**: Office macro blocking for internet files — test first (see ARTIFACTS §4 note in the session log).

## Phase 2 — Beaconing (WKS01)

- **Story**: the implant checks in with sleep + jitter; a post-exploitation job uses a spawn-to process.
- **ATT&CK**: T1071.001
- **Verify now**: ARTIFACTS §2 (Sysmon 3, 17/18), §6 (SRUM after > 1 h)

## Phase 3 — Injection (WKS01)

- **Story**: the implant moves into a legitimate-looking process.
- **ATT&CK**: T1055, T1055.012
- **Verify now**: ARTIFACTS §2 (Sysmon 8, 10)
- **Checkpoint**: memory dump #1 + snapshot `cp1`

## Phase 4 — Defense evasion and anti-forensics (WKS01)

- **Story**: the attacker trips Defender once, then blinds it and cleans up behind himself.
- **ATT&CK**: T1562.001, T1070.001, T1070.006, T1490
- **Verify now**: ARTIFACTS §8 (every row), §5 ($SI/$FN, USN, $I30)

## Phase 5 — Code-signing hunt (defender side)

- **Story**: not an attack step — a hunt run on the dirty host to find the unsigned stager.
- **Verify now**: sigcheck output saved for the blog.

## Phase 6 — Persistence (WKS01)

- **Story**: the attacker plants several footholds, from the obvious to the stealthy.
- **ATT&CK**: T1547.001, T1547.004, T1543.003, T1053.005, T1574.002, T1574.009, T1546.003, T1197
- **Verify now**: ARTIFACTS §7 (every row), §1 (types 4, 5)
- **Checkpoint**: snapshot `cp2`, then **reboot + logon (R)**

## Phase 7 — Credential access (WKS01, then WKS02)

- **Story**: the attacker dumps credentials, finds the Helpdesk account, then Royal's session on WKS02; Kerberoasts the SQL service account; a few spraying attempts fail.
- **ATT&CK**: T1003.001, T1558.003, T1550.002, T1110.003
- **Verify now**: ARTIFACTS §9 (every row), §1 (types 9, 4625)

## Phase 8 — Lateral movement (WKS01 → WKS02 → DC01)

- **Story**: the attacker tries several remote execution methods (some fail), then RDPs in two hops to the DC.
- **ATT&CK**: T1021.002, T1047, T1021.006, T1021.001, T1569.002, T1053.005, T1090
- **Verify now**: ARTIFACTS §10 (every row, source **and** destination), §6 (RDP client traces, bitmap cache)
- **Checkpoint**: memory dump #2 of WKS02 while the sessions are open

## Phase 9 — Objective and exfiltration (DC01)

- **Story**: as Royal on DC01, the attacker creates a backdoor account, browses and stages data, exfiltrates it.
- **ATT&CK**: T1136.002, T1074, T1560, T1041
- **Verify now**: ARTIFACTS §2 (4720/4728), §4 (ShellBags, RunMRU, TypedPaths on DC01), §6 (SRUM network)

---

## Collection (end of Day 3)

Order of volatility, see `capture/CAPTURE-PLAN.md`:

1. Memory dump #3 of every Windows VM from Proxmox (no footprint inside the VM).
2. Write the exact time in GROUND-TRUTH: **attack ends, collection starts**.
3. DFIR-ORC on each host, writing to the attached evidence disk.
4. Copy everything out, SHA256 → `evidence/MANIFEST.md`.
5. Only then: `ludus testing stop`.

---

## Coverage check

At the end of the dry run, every row of [ARTIFACTS.md](ARTIFACTS.md) has its **Dry run** box ticked. Do not start the official run before that.
