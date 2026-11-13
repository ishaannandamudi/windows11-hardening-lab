# Windows 11 hardening lab

PowerShell automation for a standalone Windows 11 Pro/Education/Enterprise VM. Current profile: **Arc Foundry & Aerospace, Introductory Round / Round 2 README supplied November 13, 2026**, with required RDP. It is not a universal workstation baseline. Download the current repository again; the previous scenario's ZIP disables RDP and has different accounts/apps.

## Before the first run

Enter the valid Unique Identifier through the provided desktop icon if needed. Securely save the README's sign-in credentials outside Git. Read the desktop forensic questions before making changes, including before password rotation or an antivirus scan. Take a VM snapshot when available. Run at the VM console as an authorized administrator using **64-bit Windows PowerShell 5.1**, not a remote PowerShell/RDP session. Confirm that `lab.config.json` matches your VM before applying it.

The profile preserves the passwords of `pparker`, the account running the script, and any configured auto-login account. It does not change the system time, time zone, Windows release, JavaScript, CCS Client, authorized home directories, or required application installations. The attached source README and its plaintext passwords are deliberately excluded from this repository.

The GitHub workflow runs three regression suites in Windows PowerShell 5.1. They cover the original runtime fixes, optional advanced audit, and required/non-required RDP plans, group membership, deny rights, services, firewall readback, reports and installer flags using harmless stubs. They never run the hardening entrypoint or modify real accounts/services/firewall rules. A passing workflow does not replace an Audit and supervised Apply in the VM or an actual employee RDP sign-in test.

## Fixes from the first lab run

| Observed issue | Correction |
| --- | --- |
| Removing administrator rights failed because a SID object could not bind to `Member` | Pass the existing `LocalPrincipal` object in both administrator and other privileged-group removals |
| Reports failed with `Argument types do not match` | Convert the generic lists with `ToArray()` before serializing; test empty and populated reports |
| An empty path caused a cryptic `Join-Path` error | Resolve the default config beside the saved script after parameter binding; accept an explicit literal path and explain missing files |
| Security Center configuration returned access denied even though it was already Running/Automatic | Inspect the service first, avoid unnecessary configuration writes, preserve automatic/delayed automatic startup, and verify its final state |

Apply now prints `[Applying]` before each action and its result afterward, so long optional-feature servicing is easier to follow. The final console output includes each failed action's ID, target and error. Real service configuration/start failures remain failures.

## Reliability checks for future labs

- Profile validation rejects missing/misspelled fields, incorrect JSON types, duplicate accounts/list entries, invalid policy ranges, and wildcard service/feature names before remediation. Lists must remain JSON arrays, including `[]` and single-item arrays. Numbers and booleans must not be quoted.
- Preflight checks that baseline commands exist and adds optional command checks only when their switches are requested. A missing dependency produces one list of unavailable commands before accounts or policies are changed; no component is installed automatically.
- Schema 2 requires the explicit boolean `EnableRemoteDesktop`. When true, coordinated RDP policy, group, rights, service and firewall actions run; validation rejects contradictory service disabling. When false, RDP is disabled and its group is cleared as in the first scenario. WinRM remains unsupported as a required service. Required IIS services are checked against the feature-disable list. These checks catch known conflicts; they do not prove every possible application combination is compatible.
- Native Windows tools retain stdout/stderr and are checked using their exit codes. Harmless stderr from a successful command does not become a PowerShell 5.1 false failure; unsuccessful exits remain failures.
- Each report folder includes `run-info.json` with script/config SHA-256 hashes, Windows/PowerShell versions and requested switches. This helps distinguish old extracted copies and different run options without collecting passwords.
- Regression tests use synthetic account names instead of requiring the first lab's five admins and thirteen users. The actual profile still must pass validation whenever it changes.

The original reliability fixes remain in place. Required RDP and interactive updates are scenario adaptations described below; no automatic file/app removal or hardware-dependent protections were added. Start each new scenario by supplying its full README and forensic questions, adapting the profile and affected modules, then running Audit before Apply.

## First run in the Windows VM

Download the repository ZIP while signed in to GitHub, extract it, and open **Windows PowerShell as Administrator** in its extracted folder. Alternatively, clone the repository if Git is installed.

Keep the complete repository, including the `.ps1` file, `lab.config.json`, `modules` and `tests` folders, together; run the saved file instead of pasting its body into the console. For a different lab, update the scenario-specific account lists, protected applications, services and features before running Audit or Apply.

```powershell
git clone https://github.com/ishaannandamudi/windows11-hardening-lab.git
cd windows11-hardening-lab
```

Validate the package and collect an audit/plan:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\tests\Validate-Package.ps1
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\tests\Validate-RdpScenario.ps1
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\Invoke-Windows11LabHardening.ps1 -ConfigPath .\lab.config.json -Mode Audit -AdvancedAudit
```

`-ExecutionPolicy Bypass` affects only the new PowerShell process. Audit exports settings and writes reports but does not apply the hardening actions. Its plan lists intended operations, including re-enforcement of settings that may already comply; it is not a claim that every listed operation represents a vulnerability.

Review the printed report folder, especially `changes.json`, `before-users.json`, `applications.json`, `before-rdp.json`, `before-tasks.json`, `before-exclusions.json`, `advanced-review.txt` and `warnings.json`. Add `-ScanFiles` only when ready for the optional, potentially lengthy filename inventory; read the forensic questions first. The following optional audit command is the same deeper inspection shown above:

For deeper inspection, add `-AdvancedAudit` to the Audit command:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\Invoke-Windows11LabHardening.ps1 -ConfigPath .\lab.config.json -Mode Audit -AdvancedAudit
```

Open `advanced-review.txt` first. The optional module compares stored registry values with the existing profile, inspects execution/logon/WMI hooks, existing BITS jobs, port forwarding, hosts/DNS/proxies, and Defender state. It writes evidence and review findings without changing settings or executing discovered commands. `High` means review first; `Unknown` means a check failed. Missing registry settings may select secure defaults. Only loaded user hives are inspected. These are observations **before** remediation, not proof of malware, points, or full compliance. Run a fresh Audit after changes. See [coverage and next priorities](docs/Coverage-Roadmap.md) for the basic coverage matrix, exact limitations and researched additions. The existing fixes and scenario settings remain in place; this switch is off by default.

Apply the baseline and rotate authorized local-user passwords, preserving the protected login accounts:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\Invoke-Windows11LabHardening.ps1 -ConfigPath .\lab.config.json -Mode Apply -RotatePasswords
```

Optional update flags may be added to that Apply command:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\Invoke-Windows11LabHardening.ps1 -ConfigPath .\lab.config.json -Mode Apply -RotatePasswords -UpdateDefender -UpdateApps -InstallSecurityUpdates
```

Updates can take a long time. App installers are interactive and use x64 packages. When prompted, choose **Do not close applications. A reboot will be required to complete the setup**, and defer any installer restart. The script does not pass WinGet's allow-reboot option or restart Windows itself. OpenRocket requires a separate vendor update (see below). Restart manually when ready, then run Audit again and verify business applications, sign-in and RDP. Exit code 2 means one or more requested actions failed; inspect `changes.json`. A preflight/terminating error returns a PowerShell failure. Nonzero WinGet results need review, including the ordinary case where an app has no available upgrade. A successful updater command does not prove all per-user installations are current.

Do not repeat Apply just to retry a few failures: it resets passwords again (including hhogan even without `-RotatePasswords`). Correct and verify individual failed actions instead. Group removal passes the existing local principal object, rather than a raw SID object. Monitoring actions check the service first and preserve an existing automatic/delayed automatic startup setting. An access-denied configuration error alone does not establish whether Security Center is stopped; inspect `Get-Service wscsvc | Format-List Name,Status,StartType` before deciding what needs repair.

`-WhatIf` with `-Mode Apply` also prevents remediation. `-ScanFiles` adds an optional file inventory; it does not delete findings. `-QuickScan` requests a Defender scan, **whose existing antivirus policy can quarantine detections**. Review protected lab components and forensic evidence before requesting a scan. This flag is off by default. Enabling real-time Defender protection can also trigger normal antivirus remediation independently of a requested scan.

## Scenario profile

| Setting | Value |
| --- | --- |
| Administrators | pparker, tstark, ppotts, hhogan, nfury, mhill, pcoulson |
| Standard users | bbanner, swilson, sstrange, slang, cdanvers, okoye, kbishop, ybelova, jfoster, nleeds, mjwatson, jtorres, pcarter |
| New accounts to invent/create | None; absent authorized accounts are reported for review |
| Required applications | Latest stable Google Chrome, Notepad++, LibreOffice, Mozilla Thunderbird, OpenRocket and 7-Zip |
| Required business service | Remote Desktop (RDP) for authorized employees |
| Password policy | Minimum 14 characters; complexity; history 24; minimum age 1 day; maximum age 60 days |
| Lockout | Five failures; 30-minute lockout and reset window |
| Session lock | 600 seconds of inactivity |

The supplied checklists conflict on password values. This profile selects one consistent machine-wide local policy. A standalone local password policy cannot assign different length/age requirements to administrators and standard users through `secpol.msc` alone. It uses 14 characters for both. Password expiration follows the lab requirement; it is not offered here as a universal recommendation.

`EnableRemoteDesktop=true` makes RDP an explicit exception to the former remote-access restrictions. It permits RDP in both listener/global and policy settings, requires NLA/TLS/high encryption, maintains authorized standard users in Remote Desktop Users, and grants remote interactive logon to Administrators and Remote Desktop Users. Conflicting direct/broad/nested-group network/RDP deny assignments are removed only for authorized employees; Guest denials and unrelated denials remain. Removed assignments are recorded in `rdp-deny-adjustments.json`. Local-console deny assignments remain preserved.

TermService is kept Running/Automatic; SessionEnv and UmRdpService are restored to Manual only if disabled. An already-running TermService is not restarted. Only the existing built-in RDP user-mode TCP/UDP firewall rules are enabled/adjusted to the configured listener port. Existing source-address, profile, program and service restrictions remain; custom blocking rules and policy precedence still require review. The script does not create router port forwards or a broad replacement firewall rule. WinRM, Remote Assistance, discovery and unrelated remote-management exceptions remain restricted.

`RequiredServiceNames`/`RequiredFeatureNames` by themselves remain exact-name exemptions, not general role configuration. Future WinRM/IIS/sharing requirements still need coordinated adaptation. Future RDP scenarios requiring only a subset of employees also need adaptation; this README authorizes employees generally.

## What is automated

| Area | Apply behavior |
| --- | --- |
| Accounts | Enable authorized users; disable unauthorized human accounts and built-in Guest/Administrator; preserve system accounts and authorized home directories |
| Groups | Correct Administrators and RDP membership; add authorized accounts to Users; clear unneeded Power Users, Backup Operators and guest memberships |
| Passwords | Require passwords and expiration; reset hhogan by default; `-RotatePasswords` resets other authorized local accounts except protected login accounts |
| User rights | Restrict network/interactive/debug/backup/restore/take-ownership rights; allow required RDP; keep Guest/unrelated denials and service global-object identities |
| UAC and sign-in | Enable UAC and secure desktop, require Ctrl+Alt+Delete, hide last username, enforce inactivity lock |
| Authentication | NTLMv2-only policy, no LM hash storage, no WDigest plaintext credential caching, restrict anonymous/blank-password network access |
| Firewall | Enable all profiles, block unsolicited inbound traffic, allow outbound traffic, log drops; disable named sharing/discovery/remote-management rule families |
| Remote access | Preserve/secure required RDP; disable Remote Assistance and explicitly listed unnecessary optional services |
| Optional components | Disable SMB1, PowerShell 2, Telnet/TFTP/Simple TCP/IP, IIS/FTP/NFS components when present |
| SMB | Retain SMB2/3, require signing, reject insecure guest logons |
| Shares | Remove non-system shares not on the profile allowlist; preserve backing files and Windows system shares |
| Monitoring | Enable audit subcategories and script/module logging; start security/event monitoring; retain existing event logs |
| Defender | Enable normal protection features and potentially unwanted application blocking; preserve exclusions for review |
| Browser | Set Chrome Safe Browsing, malicious-download, popup and location policies; retain JavaScript |
| Updates | Enable notifications; optional interactive x64 exact-ID app upgrades and security/critical/definition Windows updates only; OpenRocket vendor update is manual |

Windows updates exclude feature/upgrade classifications, feature packs, preview/Insider titles, optional/browse-only updates and updates requiring a new EULA acceptance. Missing applications and unaccepted package/source agreements require manual attention. WinGet does not run an unrestricted `upgrade --all` or install a missing package. Per-user installations belonging to other users may require updating in those accounts.

## Reports, credentials and recovery

Each run creates an access-restricted folder under:

```text
C:\ProgramData\Windows11HardeningLab\Runs\<timestamp-id>
```

It contains inventories, the chosen profile, firewall/audit/local-security exports, registry value snapshots, results and warnings. Passwords generated for successful creation/reset operations are stored as `<username>.credential.xml`. The generated passwords are unique 24-character cryptographic random values, not a shared hard-coded password.

Windows `Export-Clixml` uses DPAPI for credential objects: decrypt them as the **same Windows user on the same VM**. To retrieve hhogan's generated password, replace the folder placeholder with the exact printed run folder:

```powershell
(Import-Clixml 'C:\ProgramData\Windows11HardeningLab\Runs\<timestamp-id>\hhogan.credential.xml').GetNetworkCredential().Password
```

This command intentionally displays that one password. Do not commit reports or credential exports. A `.pending.credential.xml` file means an operation did not reach its successful final save; check its action result and the account's actual state before relying on it.

Configuration exports are **not a complete rollback**. They do not undo password resets, account creation, installed updates, every service dependency, or all policy effects. Use your VM snapshot for a complete rollback. Enabling expiry without changing an old protected password can make it due at the next sign-in. Keep the known primary login and snapshot available.

## Manual work that remains

[Coverage and time-saving priorities](docs/Coverage-Roadmap.md) documents the optional advanced audit and remaining work; its original coverage matrix predates this required-RDP update. [Original Windows 11 research](docs/Hardening-Research.md) retains the earlier scenario's proposals and compatibility requirements. Proposed cleanup and additional enforcement settings are not enabled.

- Set **Google Chrome as the default** under Settings > Apps > Default apps in each account and verify the latest stable version. The script does not bypass Windows UserChoice protection. Some Chrome enterprise policies may depend on browser/device management state; verify `chrome://policy`.
- Read forensic questions first. Examine suspicious tasks, startup entries, listening processes, event logs, user rights and files before changing or deleting them.
- Verify all six required applications still work and are current. **Update OpenRocket through [its official download page](https://openrocket.info/downloads.html)** using the Windows x64 package; it bundles its required Java runtime. On November 13, 2026, the vendor's release was 24.12 while the WinGet manifest offered 23.09, so OpenRocket is deliberately excluded from the automated update IDs. Recheck the vendor rather than pinning an old version. Keep runtime dependencies. LibreOffice/Thunderbird and other users' installations can require manual vendor/account-specific updates.
- Review unauthorized software in `applications.json`, including portable apps and other users' installs. Wireshark/Npcap are no longer protected requirements; Nmap, Burp Suite, Jellyfin and remote-control tools are also review candidates. A review match does not automatically authorize every dependency's removal. Finish relevant forensics, confirm authorization/dependencies, then use supported uninstallers. The script does not uninstall apps or delete archives/media.
- After Apply, inspect `after-rdp.json` and test an actual RDP sign-in from another computer using an authorized employee account and its current password. Confirm NLA remains enabled and unauthorized users cannot sign in. The stored configuration/local listener report cannot prove end-to-end access; a restart or targeted correction may still be needed.
- Review Defender exclusions, tamper-protection failures and any third-party antivirus. The script does not disable tamper protection or silently clear exclusions.
- Review administrative shares (such as C$, ADMIN$ and IPC$), share permissions, proxy/DNS configuration, browser extensions and per-user startup settings. System shares are not automatically removed.
- Review the accessibility signature/hash/IFEO report. Compare suspect files against a trusted source for the **same Windows build**, then repair through supported servicing. A filename, timestamp or hash without a trusted reference is not proof of a backdoor.
- Memory integrity, Controlled Folder Access and individual exploit mitigations require VM/application compatibility checks. They are not blindly enabled. PowerShell transcription is not enabled by default because transcripts can contain sensitive data; script-block and module logging are enabled.
- File/object-access auditing additionally requires appropriate SACLs. Enabling an audit subcategory alone does not audit every file access.

## Commit and push from your Mac

Clone once, then copy this package's files into the cloned folder (including `.github`, `.gitignore` and `.gitattributes):

```bash
git clone https://github.com/ishaannandamudi/windows11-hardening-lab.git
cd windows11-hardening-lab
git status
git add README.md Invoke-Windows11LabHardening.ps1 lab.config.json modules docs tests .github .gitignore .gitattributes
git diff --cached --stat
git commit -m "Add Windows 11 lab hardening automation"
git push -u origin HEAD
```

For later edits, run the add/commit/push lines again with a useful commit message. On an already cloned repo, use `git pull --ff-only` before starting new edits. If another commit arrives before your push, commit your changes, run `git pull --rebase` and then `git push`; resolve any conflicts before continuing. Do not force-push as a shortcut.

If GitHub authentication fails, sign in using your credential manager or run `gh auth login --hostname github.com --web`, then `gh auth setup-git`, and retry. No token belongs in this repository. If Git asks for author identity, configure your real name and the exact commit email shown under GitHub Settings > Emails; do not invent an email address.

## Technical references

- [Microsoft: Set-LocalUser](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.localaccounts/set-localuser)
- [Microsoft: encrypted credential exports](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/export-clixml?view=powershell-5.1)
- [Microsoft: secedit export](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/secedit-export)
- [Microsoft: auditpol](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/auditpol)
- [Microsoft: inactivity-limit policy range](https://learn.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/interactive-logon-machine-inactivity-limit)
- [Microsoft: account-lockout duration range](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/account-lockout-duration)
- [PowerShell: redirected-stderr behavior](https://github.com/PowerShell/PowerShell/issues/4002)
- [Microsoft: WinGet upgrade](https://learn.microsoft.com/en-us/windows/package-manager/winget/upgrade)
- [Microsoft: WUA installer properties](https://learn.microsoft.com/en-us/windows/win32/wua_sdk/iupdateinstaller-properties)
- [Microsoft: Remote Desktop prerequisites and authorized users](https://learn.microsoft.com/en-us/windows-server/remote/remote-desktop-services/remotepc/remote-desktop-allow-access)
- [Microsoft: RDP allow/deny rights](https://learn.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/allow-log-on-through-remote-desktop-services)
- [Microsoft: RDP authentication/security policies](https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-admx-terminalserver)
- [Microsoft: existing firewall rule configuration](https://learn.microsoft.com/en-us/powershell/module/netsecurity/set-netfirewallrule)
- [Google: default browser configuration](https://support.google.com/chrome/a/answer/7009292)
- [Google: download restriction policy](https://support.google.com/chrome/a/answer/7579271)
