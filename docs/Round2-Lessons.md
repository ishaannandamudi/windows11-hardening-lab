# November 13, 2026 lab observations

The final supplied screenshot was generated November 14 at 00:10:53 UTC
(November 13 locally). It shows **95/100, 18/19 scored checks, zero penalties**.
The remaining five-point check is unidentified. This is distinct from the October
lab that reached 100/100.

The screenshot credits both forensic questions; unauthorized-user/admin cleanup;
the weak administrator password; password complexity; secure Ctrl+Alt+Delete;
firewall enabled; Remote Assistance disabled; RDP NLA enabled; LibreOffice and
OpenRocket updated; prohibited MP3s removed; Angry IP Scanner and AnyDesk removed;
and the netcat backdoor removed.

## Confirmed operational lessons

Three MP3s were in an authorized user's Music subdirectory. The original run omitted
the optional file scan. Explorer produced access denied for another user's folder;
elevated PowerShell could remove the reviewed files. The new short audit launcher
includes media review, and denied locations remain visible in the coverage report.

The confirmed backdoor used the misleading System32 filename nvhostsvc.exe and
arguments "-L -p 49733 -e cmd.exe". A scheduled task repeated that command, and an
antivirus exclusion also named the file. The specific task was disabled, the
matching process stopped, the confirmed executable removed and its exact exclusion
removed. These names/port were evidence from this image, not future cleanup defaults.

ExtendedReview now correlates command lines, listener ports, tasks, services,
startup and exclusions. It detects netcat-style shell-execution options regardless
of filename/port. Matches still require authorization review; an unfamiliar
listener, unsigned file or command option alone is not a malware verdict.

Defender reported active protection, but SubmitSamplesConsent was 2 (Never send).
A PowerShell request for value 1 did not take effect. The policy registry value
also showed 2 while tamper protection was enabled. Changing the supported MAPS
policy to Enabled / Send safe samples and refreshing computer policy produced
effective value 1. The report does not credit this as a separate scored fix.
New inspection shows preference/policy/tamper evidence together; cleanup requires
readback rather than trusting a silent command.

The only reported failed baseline action was Windows Update installation with
overall result code 4. That is a generic failure, not its cause. Manual Windows
Update remained pending during troubleshooting. Future commands prefer manual
updates; the optional installer now prints its stage and saves per-update results.

The observed Windows Security and VMware Tools startup entries were preserved.
No hidden executable matches were returned within the accessible selected roots;
that did not establish the whole machine was malware-free. The archive search
only found the repository ZIP. Duplicate 7-Zip entries were never established
as the missing scored check.

## Next README

Retain the tested baseline/review machinery, then reconsider users, administrator
roles, protected passwords, required RDP/services, authorized software and file
authorization for each image. Do not turn today's account names, media paths,
task name, executable name or TCP port into universal deletion defaults.
The checked-in cleanup example is empty and requires a fresh reviewed VM plan.

A later user report said the firewall credit disappeared while Windows Update was running. All three effective profiles then read enabled, the firewall console showed them on, and both BFE/MpsSvc were Running/Automatic. The cause and scoring restoration remain unconfirmed. The new baseline verifies ActiveStore after enabling, and expanded review includes explicit firewall policies and adapter exemptions. No firewall reset or scoring-system modification is used.
