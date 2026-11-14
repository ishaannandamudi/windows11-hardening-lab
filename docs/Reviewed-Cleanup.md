# Expanded inspection and exact cleanup

Adapt lab.config.json to the next README, save sign-in credentials, and read the
desktop forensic questions. Run this short command from the extracted repository
in elevated 64-bit Windows PowerShell 5.1 at the VM console:

~~~powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\Audit.ps1
~~~

The launcher requests Audit mode with ExtendedReview. This includes the advanced
inspection and file inventory, so the media scan is no longer easy to forget.
It does not start Windows Update or app installers.

## Reports

- extended-review.txt: shell-execution commands, correlated exclusions, Defender
  sample/cloud policy, hidden security notifications and duplicate app registrations.
- extended-evidence.json: process command lines linked to TCP ports, task actions,
  service/startup commands, exclusions, policy and tamper/protection state.
- review-files.json: media, archives, tool filenames and hidden executable/script
  candidates under Users, ProgramData, Windows Temp and system-drive Temp.
- file-scan-status.json: scanned roots/counts, unreadable directories and skipped
  junctions/symlinks. Partial or Unknown does not mean clean.
- advanced-review.txt: existing IFEO, WMI, BITS, proxy, port-forwarding and selected
  policy inspection. Only already-loaded user hives are inspected.

Collected commands are never executed. Archives are listed but not opened. Hidden
attributes, filenames, unsigned signatures and unfamiliar ports require review;
none proves maliciousness by itself. File scanning skips reparse points and the
tool's own reports. Other drives, arbitrary Tools directories, offline hives and
archive contents remain outside this selected scope. No ownership/ACL changes
are used to overcome file access errors. This is not a full malware/scoring engine.

Evidence describes the state before baseline remediation. Run a fresh Audit
after changes. Local reports can contain sensitive command arguments; keep them
out of Git.

## A fresh cleanup plan for each VM

The separate helper handles reviewed findings without rerunning password rotation.
Start with the empty example:

~~~powershell
Copy-Item .\cleanup-plan.example.json .\cleanup-plan.local.json
hostname
~~~

Edit the local plan: use the actual computer name. After completing and saving
forensic answers, set ForensicsComplete to JSON true before Apply. Empty arrays
do nothing. Local plan files ending in .local.json are ignored by Git. Never reuse
another scenario's approval list.

Obtain the current SHA-256 for each independently reviewed file:

~~~powershell
Get-FileHash -LiteralPath 'C:\Users\REPLACE_USER\Music\REPLACE_FILE.mp3' -Algorithm SHA256
~~~

Example entry inside Files, after replacing every placeholder:

~~~json
{
  "Path": "C:\\Users\\REPLACE_USER\\Music\\REPLACE_FILE.mp3",
  "SHA256": "REPLACE_WITH_THE_64_CHARACTER_HASH",
  "AllowSystemPath": false,
  "StopMatchingProcesses": false
}
~~~

Files are permanently deleted only after matching the reviewed hash. Directories,
glob patterns, alternate streams and reparse-point ancestors are refused. Missing
files are reported as already absent. Save needed evidence before Apply.

Ordinary files must be within the scan roots. For an independently confirmed
malicious executable directly in System32, AllowSystemPath true permits only a
non-core .exe whose signature is not valid. Other Windows/Program Files locations,
validly signed executable/script files, protected core filenames, and lab/scoring/
VM/forensic/report components are refused. These checks supplement human review.
StopMatchingProcesses true is only for reviewed .exe files: the image path and
file hash must match before a process object is stopped.

Optional Tasks entries:

~~~json
{
  "TaskName": "REPLACE_EXACT_TASK_NAME",
  "TaskPath": "\\",
  "ExpectedExecute": "C:\\REPLACE_WITH_APPROVED_FILE_PATH.exe",
  "ExpectedArguments": "REPLACE_WITH_EXACT_REVIEWED_ARGUMENTS"
}
~~~

The task must have exactly one matching action and point directly to a file in
Files. Microsoft task paths and protected lab/VM identities are refused. Cleanup
exports the definition, disables/stops the exact task and verifies disabled state.
It does not delete task definitions. Wrapped/scripted tasks, malicious services
and other persistence need separate review.

Optional DefenderExclusions entries:

~~~json
{
  "Kind": "Path",
  "Value": "C:\\REPLACE_WITH_EXACT_UNAUTHORIZED_EXCLUSION.exe"
}
~~~

Kind is Path, Process or Extension. Only the exact entry is removed; other
exceptions remain. Required CCS/VM exceptions are protected. NotListed means a value was not visible in preferences; hidden/policy exclusions may still exist. An absent excluded
file does not automatically authorize removing its exception.

EnableSafeSampleSubmission true explicitly permits safe samples to be submitted
automatically to Microsoft for malware analysis. It requests value 1 and verifies
readback. A policy/tamper override is a failure with a manual MAPS-policy hint.
The helper does not disable tamper protection, edit Defender protected registry
keys or rewrite Group Policy. Notification policy and browser defaults stay manual.

Inspect the reviewed plan:

~~~powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\Invoke-ReviewedCleanup.ps1 -PlanPath .\cleanup-plan.local.json
~~~

Apply only those reviewed targets:

~~~powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\Invoke-ReviewedCleanup.ps1 -PlanPath .\cleanup-plan.local.json -Mode Apply
~~~

Apply with WhatIf previews operations while saving reports. The complete plan
is validated before its first cleanup operation; hashes and task actions are
rechecked. Cleanup stops on failure, without rolling back earlier successful
actions. The restricted report directory contains the plan, task backups and
cleanup-results.json. Blocked Defender changes remain Failed. No account,
password, firewall, clock, service configuration or app-installation changes run.

## Manual updates remain preferred

Use Settings for current-version security/quality updates, respecting the README's
feature/Insider restrictions. The optional InstallSecurityUpdates flag still exists,
with search/download/install messages, download results, overall HRESULT and
per-update installation results. It never reboots and is absent from recommended
commands. Do not rerun baseline Apply/password rotation to retry an update failure.

## Primary references

- [Get-ChildItem and hidden-file/access behavior](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.management/get-childitem?view=powershell-5.1)
- [Remove-Item and LiteralPath](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.management/remove-item?view=powershell-5.1)
- [Disable-ScheduledTask](https://learn.microsoft.com/en-us/powershell/module/scheduledtasks/disable-scheduledtask)
- [Remove-MpPreference](https://learn.microsoft.com/en-us/powershell/module/defender/remove-mppreference)
- [Cloud protection/sample submission policy](https://learn.microsoft.com/en-us/defender-endpoint/cloud-protection-configure)
- [Tamper protection and ignored changes](https://learn.microsoft.com/en-us/defender-endpoint/tamper-protection-troubleshoot)
- [Security notification policies](https://learn.microsoft.com/en-us/windows/security/operating-system-security/system-security/windows-defender-security-center/wdsc-hide-notifications)

Firewall checks use ActiveStore in addition to stored preferences, report explicit disabled policies and adapter exemptions, and fail baseline readback when any effective profile remains disabled. A later policy refresh or restart still requires a fresh check.
