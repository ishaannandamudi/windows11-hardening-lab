# Additional Windows 11 coverage

Research date: October 23, 2026. Compared with script/config version `1181ac2` and the supplied Arc Foundry lab README. These are proposals, not implemented controls. This research does not change script behavior or establish that a future image scores any particular setting.

## Highest priority: scenario-approved cleanup

The completed lab report awarded 17 points for removing the Brutus archive (5), Burp Suite (4), Jellyfin (4), and Nmap (4). The current script inventories applications and selected files; it does not uninstall applications or delete archives. Its review application patterns do not yet include Burp Suite, Jellyfin or Nmap, and the optional file scan does not specifically identify tool archives. This is an observed coverage gap rather than a prediction about future scoring.

A future cleanup module should accept exact, explicitly approved application identities and absolute file paths, supplied after reviewing the new README and forensic questions. It should:

- Save forensic answers first and record each approved target and its metadata before removal.
- Match installed applications by exact identity and use a supported uninstaller. An application missing from the required-software list is not sufficient authorization by itself.
- Delete only approved individual files using literal paths, with guards for Windows/system locations, required applications, protected lab components and authorized home directories. Do not use recursive or wildcard deletion.
- Preserve Wireshark and Npcap when removing Nmap. Npcap supplies Wireshark's Windows packet-capture capability; it is a separate required dependency in this scenario.
- Respect Audit/WhatIf, retain an outcome for every target, and verify required applications/dependencies afterward.
- Keep existing deletion safeguards. Implementing cleanup would require narrowly scoped tests and a reviewed change to those safeguards, not simply removing the tests that forbid destructive entrypoint commands.

[Wireshark Windows installation and Npcap documentation](https://www.wireshark.org/docs/wsug_html_chunked/ChBuildInstallWinInstall.html).

## Policy gaps suitable for separate, tested modules

| Proposed addition | What exists today | Implementation and compatibility boundary |
| --- | --- | --- |
| Disable unsafe Windows Installer elevation | UAC and account controls exist; `AlwaysInstallElevated` is not configured | Audit machine and user policy scopes. A machine policy of 0 prevents the unsafe combination that grants elevated privileges to unmanaged MSI installs. Preserve normal administrator-led installation and verify required app updates. |
| Require administrators for Point and Print driver installation | No printer-driver policy is configured | Inspect/enforce `RestrictDriverInstallationToAdministrators=1` when appropriate. This concerns printer-driver installation, not disabling the Print Spooler or removing Npcap. Treat an absent value according to the Windows default, not automatically as a vulnerability. |
| Defender cloud protection and block at first sight | Real-time/behavior/download/script/archive protection and PUA blocking exist; these cloud settings are not configured | Evaluate `MAPSReporting`, `SubmitSamplesConsent` and `DisableBlockAtFirstSeen`. Make changes explicit because cloud analysis/sample submission and detection behavior change. Verify active Defender support, respect tamper protection, and preserve approved lab-component exceptions. |
| Restrict anonymous named-pipe/share access | Anonymous SAM restrictions, SMB signing and insecure-guest rejection exist; `RestrictNullSessAccess` is not configured | Consider `RestrictNullSessAccess=1`. Inspect `NullSessionPipes` and `NullSessionShares`; the restriction retains their exceptions. Do not clear those lists without reviewing exact requirements. |

Primary references:

- [Microsoft: AlwaysInstallElevated](https://learn.microsoft.com/en-us/windows/win32/msi/alwaysinstallelevated).
- [Microsoft: Windows 11 printer policy](https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-printers#restrictdriverinstallationtoadministrators) and [Point and Print behavior](https://support.microsoft.com/en-us/servicing/os/windows/2021/08/kb5005652-manage-new-point-and-print-default-driver-installation-behavior-cve-2021-34481).
- [Microsoft: block at first sight and its required settings](https://learn.microsoft.com/en-us/defender-endpoint/configure-block-at-first-sight-microsoft-defender-antivirus).
- [Microsoft: anonymous named-pipe/share access](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/network-access-restrict-anonymous-access-to-named-pipes-and-shares).

## Additional analysis that can start as reporting only

| New analysis | Existing coverage and actual gap | Proposed behavior |
| --- | --- | --- |
| Broader persistence inspection | Startup commands and scheduled tasks are exported; accessibility IFEO checks cover five executables | Enumerate permanent WMI event filters/consumers/bindings and additional IFEO, AppInit and Winlogon locations. Report entries for review; their presence alone is not proof of malware. |
| Hosts, DNS and proxy review | These are mentioned as manual work but are not collected into a dedicated network report | Record hosts entries, DNS servers by interface, and WinHTTP/user proxy settings. Preserve them for forensic review; do not replace DNS servers or reset proxies automatically. |
| Defender exclusion analysis | Exclusions are already exported, so another raw export is unnecessary | Highlight exclusions covering whole drives or broad executable categories. Preserve approved CCS exceptions. If policy hides exclusions, report that visibility limitation rather than claiming no exclusions exist. |
| Service configuration and file-permission analysis | Service executable paths/account identities are exported; service DACLs and executable/directory write permissions are not assessed | Identify unexpected non-admin service-change rights and review executable/directory ACLs. For unquoted paths, separate the executable from its arguments and assess possible writable alternatives. Do not label every unquoted command line as exploitable or automatically rewrite service paths/ACLs. |
| Actual compliance readback | Audit lists intended changes and exports settings; most controls do not have a unified actual-versus-desired result | Compare supported policy values and security exports with the scenario-approved targets. Report Compliant, NeedsChange, NeedsReview, Unsupported or Unknown separately. A missing registry value may have a secure default. |

Primary references:

- [Microsoft: permanent WMI event consumers](https://learn.microsoft.com/en-us/windows/win32/wmisdk/receiving-events-at-all-times) and [additional autostart locations](https://learn.microsoft.com/en-us/sysinternals/downloads/autoruns). These document coverage areas; installing Autoruns is not required by this proposal.
- [Microsoft: Get-DnsClientServerAddress](https://learn.microsoft.com/en-us/powershell/module/dnsclient/get-dnsclientserveraddress) and [WinHTTP proxy inspection](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/netsh-winhttp).
- [Microsoft: Defender exclusions, scope and visibility limits](https://learn.microsoft.com/en-us/defender-endpoint/microsoft-defender-antivirus-exclusions-configure).
- [Microsoft: service security rights](https://learn.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights) and [Windows executable-path interpretation](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createprocessw).
- [Microsoft: Security Compliance Toolkit and baseline comparison](https://learn.microsoft.com/en-us/windows/security/operating-system-security/device-management/windows-security-configuration-framework/security-compliance-toolkit-10). Compare with an appropriate baseline; do not import it wholesale over the scenario profile.

## Deferred protections and duplicate coverage

LSA protection is a further candidate, initially as a status/compatibility report. Applying it requires checking Windows build and authentication plug-ins, planning a restart, and selecting an appropriate configuration without casually introducing a firmware lock. [Microsoft's LSA protection guidance](https://learn.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/configuring-additional-lsa-protection) documents those considerations.

Memory integrity, Controlled Folder Access and exploit-mitigation compatibility are already documented as manual considerations. They should not be presented as newly discovered gaps or enabled universally. BitLocker, Secure Boot/firmware changes and broad attack-surface-reduction blocking also need separate scenario and compatibility decisions.

Do not duplicate implemented account/group controls, password/lockout settings, UAC, firewall, SMB1 removal, SMB signing, insecure-guest rejection, selected service/feature disabling, logging, application/Windows update options, or baseline Defender protection.

## Integration order and preservation rules

1. Improve application/archive detection, add the review-only analyses, and produce compliance findings.
2. Add cleanup only after exact authorized targets are available and forensic evidence has been addressed.
3. Add installer and printer policies with backup/readback checks, OS/default handling and Windows PowerShell 5.1 regression tests.
4. Introduce cloud protection and anonymous-access changes only with explicit scenario configuration and verification.

Keep all troubleshooting fixes, required software, protected passwords, authorized home directories, Windows release, UTC/time settings, JavaScript and CCS components intact. Continue prohibiting automatic reboots and feature/Insider upgrades. New configuration options must be implemented in validation and tests; adding arbitrary keys to the current strict schema is insufficient. A passing mocked test suite is not a full Apply test on a Windows 11 lab snapshot.
