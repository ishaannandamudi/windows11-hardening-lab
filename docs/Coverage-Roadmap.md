# Coverage and time-saving priorities

Reviewed October 23, 2026 against the repository, both supplied Windows checklists and Microsoft documentation. No future image's scoring is known. This is a reusable framework with a scenario-specific profile; required apps, accounts, roles and services must be reconsidered with every README.

November 13 update: the current schema 2 profile now supports required RDP through `EnableRemoteDesktop`, with coordinated services, firewall, membership and rights handling. See the root README for the current Round 2 accounts and six required apps. The matrix and priorities below describe the original October review except where that later RDP implementation supersedes them.

November 13 follow-up: [expanded review and exact-target cleanup](Reviewed-Cleanup.md) now cover the observed MP3/backdoor/exclusion gaps. `Audit.ps1` includes the media scan, and `-ExtendedReview` correlates shell commands, listeners and persistence with exclusions, checks sample-submission/notification policies, and highlights duplicate registrations. The separate cleanup helper is explicit-plan only. [Observed results](Round2-Lessons.md) remain 95/100. Windows Update is manual by default. The earlier matrix boundaries below are historical; current behavior is described in those documents.

## Basics: what is covered and what remains

| Area | Implemented behavior | Remaining boundary |
| --- | --- | --- |
| Accounts/groups | Authorized account creation/enabling, unauthorized account disabling, group corrections, built-in account handling | Primary/current/auto-login passwords are protected. Disabling an account is not deletion. Service-account and extra privileged-group requirements must come from the next scenario. |
| Passwords/sign-in | Unique password rotation, complexity/history/expiry/lockout policy, UAC/secure desktop, Ctrl+Alt+Delete, inactivity lock | No password guessing/cracking or automatic changes to protected logins. An old protected password may expire at next sign-in. |
| Firewall/remote access | Firewall profiles, selected inbound rule families, RDP/assistance restrictions | Required RDP, WinRM, sharing or server roles need coordinated changes to accounts, rights, services, registry and firewall. |
| SMB/shares | SMB1 off, SMB signing, reject insecure guest logons, remove unauthorized non-system shares | System shares, exact share/NTFS permissions and required business shares still require review. |
| Defender | Normal protection and PUA blocking, optional signatures/scan, exclusion inventory | Active protection can differ from requested preferences. Exclusion authorization, cloud submission, third-party AV and tamper-protection conflicts are separate decisions. |
| Services/features | Profile-selected disabling; monitoring-service checks | No general service executable/ACL analysis. Required dependencies must be preserved. |
| Updates/apps | Exact required-app updates; selected Windows security updates; installed-app inventory | No automatic uninstall, complete offline/per-user app discovery, portable-app classification or browser-default bypass. A successful command is not a full version/compliance check. |
| Logging | Selected audit subcategories, Security log sizing, PowerShell script/module logging; preserve existing logs | File auditing also needs appropriate SACLs or global object-access auditing. Applying every legacy checklist audit setting is not equivalent to useful evidence. |
| Evidence/manual cleanup | Optional media/executable filename scan, tasks/startup/process/listener exports, accessibility evidence | Archive detection and exact approved cleanup remain gaps. Filename matches, timestamps and unsigned files alone do not prove malware. |
| Verification | Existing backups, action results and inventory; optional registry-target comparison now added | No complete post-Apply compliance engine or automatic proof of remaining score items. |

The checklists contain legacy and scenario-dependent advice. Do not install an alternate browser, remove Wireshark/Npcap, clear browser data, reset a proxy, change built-in account names or clear the pagefile merely because a checklist says so. These decisions depend on current requirements and evidence. The October profile's Wireshark/Npcap requirements do not apply to the new Round 2 README.

[Microsoft: file-system auditing and SACLs](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/audit-file-system).

## Implemented now: optional advanced inspection

The `-AdvancedAudit` switch invokes `modules/Lab.AdvancedAudit.psm1` before account/policy remediation. It writes three files to the existing restricted report directory:

- `advanced-review.txt`: collection status, durations, prioritized mismatches/review items and a reminder to inspect unclassified evidence.
- `advanced-findings.json`: structured review items, including failed checks marked `Unknown`.
- `advanced-evidence.json`: the actual observations and each collector's scope/limitations.

This flag does not enable new security settings or perform cleanup. It runs in Audit or Apply, but its evidence always describes the state **before** remediation. Run Audit afterward for a fresh comparison. Without the switch, the original remediation behavior remains the same.

| Inspection | Why it saves time | Interpretation |
| --- | --- | --- |
| Current registry values versus the existing profile targets | Separates observed mismatches from a plan that re-enforces every setting | Checks value and type. Missing values are `NotExplicitlySet`, not automatically insecure; this is not effective-policy analysis. |
| Additional Installer, printer, anonymous-access and LLMNR settings | Surfaces explicit weakening outside the current registry plan | Machine-side `AlwaysInstallElevated=1` warrants review; the dangerous MSI condition also needs user-side policy 1. No automatic fix is inferred. |
| IFEO Debugger and SilentProcessExit hooks | Checks beyond the five accessibility executables; includes IFEO filter subkeys and both registry paths | Commands are recorded, never run. Debugging/monitoring entries can be legitimate. |
| Permanent WMI subscriptions | Brings filters, command/script consumers and bindings together | Local `root/subscription` only; no automatic removal or script execution. Other namespaces/providers are not covered. |
| Winlogon, AppInit, machine/loaded-user Run and RunOnce | Extends the existing startup inventory with specific registry evidence | Whitelists Winlogon values; does not export `DefaultPassword`. Offline user hives are not loaded. |
| Windows port forwarding | Shows `netsh interface portproxy show all` rules that ordinary process/listener exports do not explain | Output is retained without language-dependent parsing. A forwarding rule can be authorized. |
| Existing BITS jobs | Shows background transfer jobs from all users for one review | Metadata only; update jobs can be legitimate. No resume, cancel, completion or callback execution. |
| Hosts, DNS, WinHTTP and loaded-user proxies | Collects several separate redirection mechanisms together | No DNS replacements, proxy resets, name lookups or hosts edits. |
| Defender active state and cloud preferences | Shows inactive protection even when preference-setting commands succeeded | Inspect running mode/third-party AV and policy. No cloud/sample-submission changes are made. |

`High` is a review priority, not confirmed malware, exploitability or a scored vulnerability. Failed checks are `Unknown`; an empty collection or no findings is not a clean bill of health. WMI queries use individual timeouts, but the full audit has no guaranteed deadline. Avoid repeatedly running optional recursive file scans and long update operations during triage.

Technical references:

- [Microsoft: permanent WMI event components](https://learn.microsoft.com/en-us/windows/win32/wmisdk/receiving-events-at-all-times).
- [Microsoft: Autoruns coverage areas](https://learn.microsoft.com/en-us/sysinternals/downloads/autoruns). The module covers selected areas, not the full Autoruns feature set.
- [Microsoft: silent process exit and monitor commands](https://learn.microsoft.com/en-us/windows-hardware/drivers/debugger/registry-entries-for-silent-process-exit).
- [Microsoft: portproxy inspection](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/netsh-interface).
- [Microsoft: existing BITS jobs and AllUsers](https://learn.microsoft.com/en-us/powershell/module/bitstransfer/get-bitstransfer).
- [Microsoft: WinHTTP proxy](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/netsh-winhttp).
- [Microsoft: Defender current state](https://learn.microsoft.com/en-us/powershell/module/defender/get-mpcomputerstatus).
- [Microsoft: AlwaysInstallElevated requires both policy scopes](https://learn.microsoft.com/en-us/windows/win32/msi/alwaysinstallelevated).
- [Microsoft: LLMNR policy and default](https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-admx-dnsclient#turn_off_multicast).

## Next additions, ordered for a timed lab

| Priority | Proposed addition, not implemented | What is needed first |
| --- | --- | --- |
| 1 | Better archive/portable-app discovery and exact approved cleanup | New README, forensic answers, exact application identities/individual paths and protected dependencies. Add filename-based candidates without unpacking/executing archives. Bound scanning by roots/budget and skip reparse points; preserve explicit unreadable/skipped coverage. |
| 2 | Post-Apply verification across accounts, password policy, firewall, SMB, services/features and Defender | Read actual state; distinguish requested, stored, effective, pending-reboot, unsupported and unknown results. Do not relabel command success as verified compliance. This should become a reusable report, not a score estimator. |
| 3 | Task/service review that explains *why* an entry deserves attention | Resolve executable versus arguments, correlate identities and file/directory permissions, and retain exact evidence. Assess unquoted-path exploitability before recommending a fix. System/user paths and elevated identities alone are not malware proof. |
| 4 | Per-user coverage beyond currently loaded hives | Explicit scope, safe handling of offline hives and read-only browser/profile evidence. Do not force sign-ins or export saved passwords. Report which profiles were actually examined. |
| 5 | Separate, configurable Installer/printer/anonymous-access/LLMNR enforcement | New scenario approval, build/default handling, backup and readback. LLMNR affects local name resolution; do not disable DNS, mDNS, IPv6 or NetBIOS as a side effect of this one policy. |
| 6 | Defender exclusion reasoning and targeted cloud/ASR review | Scope-aware exclusion analysis, visibility limits, active AV mode and app compatibility. Keep approved lab/scoring exceptions. ASR rules should be tested individually before blocking; preserve existing rules instead of replacing the whole set. |
| 7 | LSA protection, memory integrity and application-control evaluation | Build, VM/driver/authentication compatibility and reboot/rollback planning. These are separate protection projects, not universally useful timed-lab switches. |

[Microsoft: service configuration rights](https://learn.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights) and [executable-path interpretation](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createprocessw) explain why a path/ACL analyzer needs more than a string regex.

[Microsoft: ASR deployment](https://learn.microsoft.com/en-us/defender-endpoint/attack-surface-reduction-rules-deployment) recommends testing rules in audit mode. [Application-control known issues](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/windows-defender-application-control/operations/known-issues) also document interactions that can occur even with audit policies. These protections are not enabled by this update.

The highest-value sequence is scenario/evidence review, one audit, baseline remediation, exact approved cleanup, then fresh verification. Start slow downloads early when appropriate, but avoid running multiple remediation tools against the same settings at once. Every future README can change the requirements; previous app removals and user lists are not a universal template.
