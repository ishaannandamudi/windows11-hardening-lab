# Windows 11 hardening lab

PowerShell automation for a personal, standalone Windows 11 Pro/Education/Enterprise VM. This profile is tailored to the supplied lab scenario. It is not a universal workstation baseline.

## Before the first run

Take a VM snapshot. Read any forensic questions before making changes. Run at the VM console as an authorized administrator using **64-bit Windows PowerShell 5.1**, not a remote PowerShell/RDP session. Confirm that `lab.config.json` matches your VM before applying it.

The profile preserves the passwords of `pparker`, the account running the script, and any configured auto-login account. It does not change the system time, time zone, Windows release, JavaScript, CCS Client, authorized home directories, or required application installations. The attached source README and its plaintext passwords are deliberately excluded from this repository.

The GitHub workflow runs parsing and regression checks in Windows PowerShell 5.1. It tests config paths, profile validation, password helpers, report serialization, native group-member parameter binding and service actions with harmless stubs. It never runs the hardening entrypoint or modifies accounts/services. A passing workflow does not replace an Audit and supervised Apply in the VM.

## Fixes from the first lab run

| Observed issue | Correction |
| --- | --- |
| Removing administrator rights failed because a SID object could not bind to `Member` | Pass the existing `LocalPrincipal` object in both administrator and other privileged-group removals |
| Reports failed with `Argument types do not match` | Convert the generic lists with `ToArray()` before serializing; test empty and populated reports |
| An empty path caused a cryptic `Join-Path` error | Resolve the default config beside the saved script after parameter binding; accept an explicit literal path and explain missing files |
| Security Center configuration returned access denied even though it was already Running/Automatic | Inspect the service first, avoid unnecessary configuration writes, preserve automatic/delayed automatic startup, and verify its final state |

Apply now prints `[Applying]` before each action and its result afterward, so long optional-feature servicing is easier to follow. The final console output includes each failed action's ID, target and error. Real service configuration/start failures remain failures.

## First run in the Windows VM

Download the repository ZIP while signed in to GitHub, extract it, and open **Windows PowerShell as Administrator** in its extracted folder. Alternatively, clone the repository if Git is installed.

Keep the complete `.ps1` file, `lab.config.json` and `tests` folder together; run the saved file instead of pasting its body into the console. For a different lab, update the scenario-specific account lists, protected applications, services and features before running Audit or Apply.

```powershell
git clone https://github.com/ishaannandamudi/windows11-hardening-lab.git
cd windows11-hardening-lab
```

Validate the package and collect an audit/plan:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\tests\Validate-Package.ps1
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\Invoke-Windows11LabHardening.ps1 -ConfigPath .\lab.config.json -Mode Audit -RotatePasswords -ScanFiles
```

`-ExecutionPolicy Bypass` affects only the new PowerShell process. Audit exports settings and writes reports but does not apply the hardening actions. Its plan lists intended operations, including re-enforcement of settings that may already comply; it is not a claim that every listed operation represents a vulnerability.

Review the printed report folder, especially `changes.json`, `before-users.json`, `applications.json`, `review-files.json`, `before-tasks.json`, `before-exclusions.json`, and `warnings.json`.

Apply the baseline and rotate authorized local-user passwords, preserving the protected login accounts:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\Invoke-Windows11LabHardening.ps1 -ConfigPath .\lab.config.json -Mode Apply -RotatePasswords
```

Optional update flags may be added to that Apply command:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\Invoke-Windows11LabHardening.ps1 -ConfigPath .\lab.config.json -Mode Apply -RotatePasswords -UpdateDefender -UpdateApps -InstallSecurityUpdates
```

Updates can take a long time. No restart is requested. Restart manually when ready, then run Audit again and verify business applications and sign-in. Exit code 2 means one or more requested actions failed; inspect `changes.json`. A preflight/terminating error returns a PowerShell failure. Nonzero WinGet results need review, including the ordinary case where an app has no available upgrade.

Do not repeat Apply just to retry a few failures: it resets passwords again (including hhogan even without `-RotatePasswords`). Correct and verify individual failed actions instead. Group removal passes the existing local principal object, rather than a raw SID object. Monitoring actions check the service first and preserve an existing automatic/delayed automatic startup setting. An access-denied configuration error alone does not establish whether Security Center is stopped; inspect `Get-Service wscsvc | Format-List Name,Status,StartType` before deciding what needs repair.

`-WhatIf` with `-Mode Apply` also prevents remediation. `-ScanFiles` adds an optional file inventory; it does not delete findings. `-QuickScan` requests a Defender scan, **whose existing antivirus policy can quarantine detections**. Review protected lab components and forensic evidence before requesting a scan. This flag is off by default. Enabling real-time Defender protection can also trigger normal antivirus remediation independently of a requested scan.

## Scenario profile

| Setting | Value |
| --- | --- |
| Administrators | pparker, tstark, ppotts, hhogan, nfury |
| Standard users | bbanner, cbarton, swilson, bbarnes, sstrange, wmaximoff, jrhodes, slang, hvandyne, cdanvers, shuri, okoye, tchalla |
| New account | tchalla |
| Required applications | Google Chrome, Notepad++, 7-Zip, Wireshark; preserve Npcap |
| Required business services | None |
| Password policy | Minimum 14 characters; complexity; history 24; minimum age 1 day; maximum age 60 days |
| Lockout | Five failures; 30-minute lockout and reset window |
| Session lock | 600 seconds of inactivity |

The supplied checklists conflict on password values. This profile selects one consistent machine-wide local policy. A standalone local password policy cannot assign different length/age requirements to administrators and standard users through `secpol.msc` alone. It uses 14 characters for both. Password expiration follows the lab requirement; it is not offered here as a universal recommendation.

`RequiredServiceNames` and `RequiredFeatureNames` exempt exact names from their respective disable lists only. They do **not** automatically open firewall rules, configure authentication, or reverse registry settings. If a future scenario requires RDP, WinRM, IIS or sharing, review those modules together before applying this profile.

## What is automated

| Area | Apply behavior |
| --- | --- |
| Accounts | Create tchalla; enable authorized users; disable unauthorized human accounts and built-in Guest/Administrator; preserve system accounts |
| Groups | Correct Administrators membership; add authorized accounts to Users; clear unneeded Power Users, Backup Operators, Remote Desktop Users and guest memberships |
| Passwords | Require passwords and expiration; reset hhogan by default; `-RotatePasswords` resets other authorized local accounts except protected login accounts |
| User rights | Restrict network/interactive logon and debug/backup/restore/take-ownership rights; deny Guest logons while retaining existing deny entries; retain built-in service identities for global objects |
| UAC and sign-in | Enable UAC and secure desktop, require Ctrl+Alt+Delete, hide last username, enforce inactivity lock |
| Authentication | NTLMv2-only policy, no LM hash storage, no WDigest plaintext credential caching, restrict anonymous/blank-password network access |
| Firewall | Enable all profiles, block unsolicited inbound traffic, allow outbound traffic, log drops; disable named sharing/discovery/remote-management rule families |
| Remote access | Disable RDP and Remote Assistance, and stop/disable explicitly listed unnecessary optional services |
| Optional components | Disable SMB1, PowerShell 2, Telnet/TFTP/Simple TCP/IP, IIS/FTP/NFS components when present |
| SMB | Retain SMB2/3, require signing, reject insecure guest logons |
| Shares | Remove non-system shares not on the profile allowlist; preserve backing files and Windows system shares |
| Monitoring | Enable audit subcategories and script/module logging; start security/event monitoring; retain existing event logs |
| Defender | Enable normal protection features and potentially unwanted application blocking; preserve exclusions for review |
| Browser | Set Chrome Safe Browsing, malicious-download, popup and location policies; retain JavaScript |
| Updates | Enable update notifications; optional exact-ID app upgrades and security/critical/definition Windows updates only |

Windows updates exclude feature/upgrade classifications, feature packs, preview/Insider titles, optional/browse-only updates and updates requiring a new EULA acceptance. Missing applications and unaccepted package/source agreements require manual attention. WinGet does not run an unrestricted `upgrade --all` or install a missing package. Per-user installations belonging to other users may require updating in those accounts.

## Reports, credentials and recovery

Each run creates an access-restricted folder under:

```text
C:\ProgramData\Windows11HardeningLab\Runs\<timestamp-id>
```

It contains inventories, the chosen profile, firewall/audit/local-security exports, registry value snapshots, results and warnings. Passwords generated for successful creation/reset operations are stored as `<username>.credential.xml`. The generated passwords are unique 24-character cryptographic random values, not a shared hard-coded password.

Windows `Export-Clixml` uses DPAPI for credential objects: decrypt them as the **same Windows user on the same VM**. To retrieve tchalla's generated password, replace the folder placeholder with the exact printed run folder:

```powershell
(Import-Clixml 'C:\ProgramData\Windows11HardeningLab\Runs\<timestamp-id>\tchalla.credential.xml').GetNetworkCredential().Password
```

This command intentionally displays that one password. Do not commit reports or credential exports. A `.pending.credential.xml` file means an operation did not reach its successful final save; check its action result and the account's actual state before relying on it.

Configuration exports are **not a complete rollback**. They do not undo password resets, account creation, installed updates, every service dependency, or all policy effects. Use your VM snapshot for a complete rollback. Enabling expiry without changing an old protected password can make it due at the next sign-in. Keep the known primary login and snapshot available.

## Manual work that remains

- Set **Google Chrome as the default** under Settings > Apps > Default apps in each account and verify the latest stable version. The script does not bypass Windows UserChoice protection. Some Chrome enterprise policies may depend on browser/device management state; verify `chrome://policy`.
- Read forensic questions first. Examine suspicious tasks, startup entries, listening processes, event logs, user rights and files before changing or deleting them.
- Review unauthorized software in `applications.json`, including portable apps and installations in other users' profiles. Uninstall confirmed unwanted software through its supported uninstaller. Wireshark and Npcap are required here.
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
git add README.md Invoke-Windows11LabHardening.ps1 lab.config.json tests .github .gitignore .gitattributes
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
- [Microsoft: WinGet upgrade](https://learn.microsoft.com/en-us/windows/package-manager/winget/upgrade)
- [Microsoft: WUA installer properties](https://learn.microsoft.com/en-us/windows/win32/wua_sdk/iupdateinstaller-properties)
- [Google: default browser configuration](https://support.google.com/chrome/a/answer/7009292)
- [Google: download restriction policy](https://support.google.com/chrome/a/answer/7579271)
