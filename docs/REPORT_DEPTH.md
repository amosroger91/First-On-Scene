# Maximizing Report Value (Without Breaking the Rules)

A design note for the "Suspect a machine is compromised?" path
(`deploy/standalone/Invoke-FosTriage.ps1` and the `scripts/win` + `scripts/nix`
collectors that feed it).

**Status:** proposal / backlog. This document changes no code. It catalogs every
artifact we could add to pack *more useful, decision-grade information* into a
report while staying inside First-On-Scene's hard constraints and keeping the
Windows and Linux paths at parity.

---

## 1. The guardrails (non-negotiable)

Every idea below is measured against these. If a candidate artifact fails any
row, it does not ship.

| # | Rule | Practical test for a new artifact |
|---|------|-----------------------------------|
| R1 | **Read-only collection.** No process kill, no Defender toggle, no registry/file writes, no runtime downloads. | Does it only *read* state? `Get-*`/`stat`/`cat` yes; `Set-*`/`Stop-*`/`reg add` no. |
| R2 | **Zero network egress** (except optional loopback AI). | Does it touch the network? DNS lookups, WHOIS, reputation APIs = **no**. Reading the local ARP/DNS *cache* = yes. |
| R3 | **Zero dependencies on the endpoint.** Pure PS 5.1 on Windows; pure bash + jq + coreutils on nix. | Does it shell out to something not guaranteed present? If yes, it must degrade to empty, never abort. |
| R4 | **Never abort.** A single failed artifact -> `metadata.errors[]`, keep going. | Wrapped in try/catch (PS) or `|| echo '[]'` (bash)? |
| R5 | **Collection does no analysis.** The collector normalizes; the rule engine decides. | New data lands in `bundle.json`; verdict logic lives in `rules/detections.json` or the `builtin` correlators. |
| R6 | **Deterministic verdict.** Same bundle -> same verdict, score, exit code. | No timestamps/randomness in scoring; AI stays advisory. |
| R7 | **ASCII-only PowerShell**, **UTF-8 no-BOM JSON**, **append-only logs.** | New PS code is 7-bit ASCII; new JSON written via `Write-FosJsonFile`. |
| R8 | **Win/Linux parity.** Same rules, scoring, verdicts, exit codes. | Every Windows artifact has a Linux analogue (or an explicit, documented N/A). |
| R9 | **Informational != verdict** for ambient MSP tooling (RMM/remote-access). | New "context" signals are surfaced but do not move the score unless they are genuine attack indicators. |
| R10 | **Fast by default.** Sub-minute default pass; heavier work gated behind `-Deep`. | Per-process disk hashing, module walks, etc. go in `-Deep`. |

Two corollaries that shape *how* we add value:

- **More signal, not more noise.** The product's stated philosophy is
  "skepticism over alarmism ... keep false positives from crying wolf." Extra
  data should mostly enrich *context and evidence* on findings that already
  fire, and add new detections only where the false-positive story is clean.
- **Collect raw, decide in rules.** Adding a field to `bundle.json` is cheap and
  safe (R5). Most of the proposals below are "collect the artifact now; write
  the detection rule later," which keeps the collector honest and the verdict
  deterministic.

---

## 2. Where the easy wins are: close the parity gap first

The single biggest jump in report value costs us almost nothing because the
data is *already collected on Windows and simply missing on Linux*. Closing this
gap (R8) roughly doubles what a Linux report can say, and it is the highest-ROI
work in this document.

| Capability | Windows today | Linux today | Linux parity source (read-only, zero-dep) |
|------------|---------------|-------------|--------------------------------------------|
| Remote-access / RMM inventory | yes (`remoteAccess.tools`) | **missing** | match process names / `systemd` unit paths / `dpkg -l`+`rpm -qa` (if present) against the same `RemoteToolDefs` regex table |
| Security-product posture | Defender health/tamper/exclusions | **missing** | `systemctl is-active` + presence of `clamd`, `auditd`, `apparmor`/`selinux` status (`getenforce`, `aa-status`), `ufw`/`firewalld` state |
| Access-control context | local admins, RDP, shares | **missing** | members of `sudo`/`wheel` groups (`getent group`), `sshd` `PermitRootLogin`/`PasswordAuthentication` (read `sshd_config`), exported shares (`/etc/exports`, `smb.conf`) |
| Log-tamper evidence | Security 1102 / System 104 | **missing** | wtmp/btmp gaps, `journalctl --verify`, truncated/rotated-away `auth.log`, `/var/log` files with zero size or recent `mtime` regressions |
| Process signature / integrity | Authenticode + SHA-256 | **missing** | SHA-256 via `sha256sum`/`shasum`; package-ownership check (`dpkg -S`/`rpm -qf`) as the Linux analogue of "is this a known-good signed binary" |
| Image-deleted process | `imageDeleted` flag | **missing** | `/proc/<pid>/exe` symlink ends in `(deleted)` -> classic in-memory/ELF-unlinked malware tell |
| Autostart hijacks (ASEP) | IFEO/AppInit/Winlogon/sticky-keys | partial (`autostartFiles`) | `LD_PRELOAD`/`/etc/ld.so.preload`, modified `/etc/profile.d`, `~/.bashrc` & `~/.bash_profile` payloads, `systemd` user units, `@reboot` cron |
| Prefetch-equivalent exec evidence | `prefetch` (`-Deep`) | **missing** | `atime` on binaries, `~/.bash_history`/`~/.zsh_history` tail, `lastlog`, `/var/log/btmp` |

> The Linux collector already proves the pattern is safe: it reads `cron`,
> `systemd`, `ps`, `ss`, `auth.log`, autostart files, and key file `stat` data
> with pure coreutils. Everything in the table is the same shape of read.

**Result for the report:** a Linux case gains the same "Remote access," "Security
posture," "Access control," and "Process integrity" sections the Windows report
already prints, instead of today's thin process/network/cron view.

---

## 3. New artifacts that add the most report value

Grouped by ATT&CK-style category to match `bundle.json`. Each row lists the
read-only source on both platforms and which guardrails it must respect. **Bold**
items are the high-value picks.

### 3.1 Host & identity snapshot (cheap context, big readability win)

The console already prints a host snapshot (make/model, serial, OS, CPU/RAM,
disk, logged-on users). Persisting that and a few neighbors into the bundle lets
the **HTML report** carry the same at-a-glance header the console does.

| Artifact | Why it helps the reader | Windows source | Linux source | Notes |
|----------|------------------------|----------------|--------------|-------|
| **Host snapshot block** (make/model/serial/OS build/CPU/RAM/uptime/domain/disks/logged-on users) | Every report opens with "what machine am I even looking at." | `Win32_ComputerSystem`, `Win32_BIOS`, `Win32_OperatingSystem`, `Win32_LogicalDisk`, `quser` | `dmidecode` (if present, else `/sys/class/dmi/id/*`), `/etc/os-release`, `uptime`, `df`, `who` | R3: `dmidecode` may be absent -> fall back to `/sys` files, never abort. |
| **Boot time / install date** | Anchors "is this recent activity" and "was the box reimaged." | `Win32_OperatingSystem.InstallDate`/`LastBootUpTime` | `/proc/stat btime`, `stat /` ctime, `/var/log/installer` | Pure read. |
| **Time sync / timezone** | Forensic timestamps are worthless if the clock is wrong; flag skew. | `w32tm /query /status` (read), `Get-TimeZone` | `timedatectl` (read), `/etc/timezone` | R2: reads local NTP *state*, makes no NTP call. |
| Pending reboot / patch level | Unpatched + reboot-pending is a real exposure signal. | `Get-HotFix`, CBS/WU reg *read* | `/var/run/reboot-required`, last `apt`/`dnf` history *read* | Context, not verdict (R9). |

### 3.2 Network (richest under-collected area, all local reads)

We collect TCP connections. The local network *state* tells a far bigger story
and is entirely cache/state reads — **no egress (R2)**.

| Artifact | Why | Windows | Linux |
|----------|-----|---------|-------|
| **Listening ports + owning process** | A new listener is how most implants phone-home-ready themselves. | `Get-NetTCPConnection -State Listen` + `Get-NetUDPEndpoint` | `ss -lntup` |
| **DNS client cache** | Shows beaconing domains *without* making a lookup — pure local read. | `Get-DnsClientCache` | `resolvectl statistics`/`/var/cache` if present; else N/A (document) |
| **ARP / neighbor table** | Lateral-movement and rogue-host context. | `Get-NetNeighbor` | `ip neigh` |
| **Routing table + interfaces** | Rogue routes, unexpected VPN/tun adapters. | `Get-NetRoute`, `Get-NetAdapter` | `ip route`, `ip -o link` |
| **hosts file contents** | Cheap, classic redirect/hijack tell. | `%windir%\System32\drivers\etc\hosts` | `/etc/hosts` (already `stat`'d; add contents) |
| **Firewall posture** | "Is the host's firewall off / wide open" is decision-grade. | `Get-NetFirewallProfile` (read) | `ufw status`, `firewall-cmd --list-all`, `iptables -S` (read) |
| **Proxy / WPAD config** | Malware loves a sneaky system proxy. | WinHTTP/IE proxy reg *read* | `env`, `/etc/environment`, `http_proxy` |

> **Resolve the connection -> process -> signature chain.** We already have
> connections, processes, and (Windows) signatures. Persisting them so the report
> can render "this unsigned binary from `%TEMP%` holds an ESTABLISHED connection
> to `185.x.x.x:443`" is the single most compelling evidence sentence a triage
> report can print, and it is pure correlation over data already in the bundle
> (R5 — done in rules, not the collector).

### 3.3 Persistence (broaden coverage; deviations only)

| Artifact | Why | Windows | Linux |
|----------|-----|---------|-------|
| **Startup folder contents** | Already `stat`'d for file metadata; capture the *targets* of `.lnk`/scripts. | parse Startup `.lnk` targets | `~/.config/autostart` exec lines (have paths; add `Exec=`) |
| **More ASEP coverage** | Print Spooler/COM-hijack/`Image File Execution`/Browser-helper objects are common. | known-key *reads* (BHO, ContextMenuHandlers, LSA packages, netsh helpers) | `LD_PRELOAD`, PAM module list, `~/.ssh/authorized_keys` additions |
| **Services pointing at user-writable paths** | Unquoted-path / `%TEMP%` service binaries = persistence. | already have `services.pathName`; flag in rules | already have `systemd.execStart`; flag in rules |
| **Browser extensions inventory** | Malicious extension = quiet persistence + cred theft. | enumerate extension manifest paths (`fileSystem.browserArtifacts`) | same paths under `~/.config`/`~/.mozilla` |
| **SSH authorized_keys / known_hosts** | Top Linux persistence; also relevant for Win OpenSSH. | `%ProgramData%\ssh`, per-user `.ssh` | `~/.ssh/authorized_keys`, root's keys |

### 3.4 Execution & integrity (mostly `-Deep`, R10)

| Artifact | Why | Windows | Linux |
|----------|-----|---------|-------|
| **Loaded driver / kernel module list** | Closest live signal to a rootkit; unsigned drivers are gold. | `Get-CimInstance Win32_SystemDriver` + signature | `lsmod`, `/proc/modules`, taint flags in `/proc/sys/kernel/tainted` |
| **`imageDeleted` on Linux** | In-memory ELF / unlinked-binary malware. | already have it | `/proc/<pid>/exe -> (deleted)` |
| **Parent/child process tree** | We have PPIDs; render the tree so Office->LOLBin chains read at a glance. | have PPID | have PPID |
| **Recently modified executables in exec paths** | Freshly written binary in `System32`/`/usr/bin` is suspicious. | `Get-ChildItem` mtime (read) | `find -newermt` style mtime read |
| **Named-pipe inventory** | Many C2 frameworks (Cobalt Strike) leave telltale pipes. | `Get-ChildItem \\.\pipe\` | N/A (document) — Linux uses sockets already captured |

### 3.5 Credential access & logs

| Artifact | Why | Windows | Linux |
|----------|-----|---------|-------|
| **Failed-logon bursts / 4625** | Brute-force / spray context next to the 4624/4672 we already pull. | add 4625, 4634, 4648, 4688 (if enabled) | already grep `auth.log` fails; structure them |
| **RDP session history (TerminalServices logs)** | Who came in over RDP and from where. | `Microsoft-Windows-TerminalServices-*` channels | `last`, `lastb`, `journalctl _COMM=sshd` |
| **Audit-policy / logging state** | "Were the logs even on?" makes absence meaningful instead of a blind spot. | `auditpol /get` (read), channel enablement | `auditctl -l` (read), `journald` config |
| **WDAC/AppLocker or equivalent posture** | Allow-listing gaps are real exposure. | policy *read* | `aa-status`, `getenforce` |

### 3.6 Malware / quick indicators (already in spirit; deepen)

| Artifact | Why | Windows | Linux |
|----------|-----|---------|-------|
| **Ransom-note sweep** | The README already advertises ransom-note indicators — make the file sweep explicit and bounded. | bounded `Get-ChildItem` for `*ransom*`, `*recover*`, `*_readme*.txt` in user dirs | same `find`, bounded |
| **Existing AV/EDR quarantine read** | We read Defender detections; read ClamAV/quarantine logs too. | already do Defender | `clamav` log read (already stubbed) |
| **Suspicious scheduled-task/cron command lint** | base64, `-enc`, `curl|bash`, `IEX`, download cradles — flag in rules. | rules over `scheduledTasks.actions` | rules over `cronJobs.command` |

---

## 4. Make the report itself say more (presentation, not collection)

Even with today's bundle, `Write-Report.ps1` can surface far more of what we
already collect. These are deterministic (R6), zero-egress, and Windows/Linux
identical because they read `findings.json` + `bundle.json`.

1. **Host snapshot header** — render the §3.1 block at the top of the HTML, the
   same one the console prints. Biggest perceived-value bump for zero new risk.
2. **Remote-access / RMM section** — the report currently shows only detections.
   Add the `[expected]` / `[undeclared]` table from the bundle so the HTML
   matches the console (R9: clearly labeled "informational — does not affect
   verdict").
3. **Security & access posture panel** — Defender/AV health, tamper state,
   exclusions, local admins, RDP, shares, firewall. All already in the bundle on
   Windows; lights up on Linux once §2 lands.
4. **Evidence appendix / "everything we saw"** — a collapsible raw-artifact dump
   (counts + top-N per category) so the report is self-contained proof, not just
   the findings the engine chose to score. Pairs with the manifest for "show me
   the data behind the verdict."
5. **Connection -> process -> signature evidence lines** (§3.2) wherever a
   network or execution rule fires.
6. **Collection-coverage / blind-spot banner** — surface `metadata.errors[]`,
   non-elevated runs, and disabled log channels ("Script-block logging was OFF —
   PowerShell findings may be incomplete"). Honest gaps *increase* trust and tell
   the reader when to escalate.
7. **"What we did NOT inspect" footer** — restate the honest ceiling (kernel
   rootkit, memory image, disk/`$MFT`, firmware) so the report sets correct
   expectations and points to the heavy-DFIR escalation path.

None of these touch the verdict, the network, or the endpoint.

---

## 5. Parity tracker

Use this as the acceptance checklist: a feature is "done" only when both columns
are real or the N/A is documented in the report's coverage banner.

| Capability | Win | Linux | If Linux N/A, why |
|------------|-----|-------|--------------------|
| Remote-access inventory | have | **add** | — |
| Security posture | have | **add** | — |
| Access control | have | **add** | — |
| Process SHA-256 | have | **add** | — |
| Image-deleted process | have | **add** | — |
| ASEP / autostart hijack | have | **extend** | — |
| Listening ports | **add** | **add** | — |
| DNS cache | **add** | partial | no universal local cache on all distros — banner it |
| ARP / routes / firewall | **add** | **add** | — |
| Driver / kernel module list | **add** | **add** | — |
| Named pipes | **add** | N/A | Linux has no named-pipe C2 equiv; sockets already covered |
| Prefetch exec evidence | have | **add (atime/history)** | no Prefetch on Linux — use access-time/history analogue |

---

## 6. Explicitly out of scope (keeps the ceiling honest)

These would add data but violate a guardrail or the fast-triage mission. Listing
them prevents scope creep and matches the README's "honest ceiling."

- **Anything requiring egress** — IP/hash/domain reputation, VirusTotal, WHOIS,
  threat-intel enrichment. Violates R2. (A future *offline* analyzer-side
  enrichment against a pre-staged local feed could be a separate opt-in tool.)
- **Anything that modifies the host** — running a fresh AV scan, quarantining,
  killing processes, dumping LSASS. Violates R1. We *read* existing detections
  only.
- **Heavy DFIR** — full memory image (Volatility), disk imaging / `$MFT` /
  super-timeline, firmware/UEFI. Deliberately offline and out of the sub-minute
  live triage (R10). The report's job is to make the live call and tell you when
  to escalate to these.
- **New endpoint dependencies** — Sysmon, osquery, Python. Violates R3. We may
  *read* Sysmon's channel if it happens to be present, but never require it.

---

## 7. Suggested sequencing

1. **Parity catch-up (§2)** — most value per line of code; makes Linux reports
   first-class. Pure reads already proven safe in the existing nix collector.
2. **Report presentation (§4)** — surfaces data already in the bundle; no new
   collection risk; immediate "the report says so much more now" effect.
3. **Network state (§3.2)** — high signal, all local reads, clean FP story.
4. **Persistence/execution breadth (§3.3–3.4)** under `-Deep` — driver/module
   lists, broader ASEP, browser extensions.
5. **Rules to match** — for each new artifact, add detections to
   `rules/detections.json` (or a `builtin` correlator in *both* analyzers) with a
   documented false-positive story, so new data becomes new *findings* without
   crying wolf.

Every step keeps the collector read-only, offline, dependency-free, ASCII/UTF-8
clean, and Windows/Linux symmetric — more proof in the report, none of the rules
bent.
