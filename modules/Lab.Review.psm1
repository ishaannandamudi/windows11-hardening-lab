#Requires -Version 5.1
# Inspection only. Discovered commands are data, never executable input.
Set-StrictMode -Version Latest

function Get-LabReviewFileInventory {
    [CmdletBinding()]
    param([string[]]$Roots,[string[]]$MediaExtensions,[string[]]$ToolNames,[string]$ExcludeRoot='')
    $rows=New-Object 'System.Collections.Generic.List[object]'
    $issues=New-Object 'System.Collections.Generic.List[object]'
    $pending=New-Object 'System.Collections.Generic.Stack[string]'
    $seen=New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    $examined=0; $directories=0; $links=0
    $skip=if ($ExcludeRoot) {[IO.Path]::GetFullPath($ExcludeRoot).TrimEnd('\')+'\'} else {''}
    foreach ($root in $Roots) {
        Write-Host "[Inspecting files] $root"
        if (-not (Test-Path -LiteralPath $root)) { continue }
        $pending.Push($root)
        while ($pending.Count) {
            $directory=$pending.Pop()
            if (-not $seen.Add($directory)) { continue }
            if ($skip -and ($directory.TrimEnd('\')+'\' ).StartsWith($skip,[StringComparison]::OrdinalIgnoreCase)) { continue }
            try {
                $item=Get-Item -LiteralPath $directory -Force -ErrorAction Stop
                if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) { $links++; continue }
                $children=@(Get-ChildItem -LiteralPath $directory -Force -ErrorAction Stop)
                $directories++
            } catch {
                $issues.Add([pscustomobject]@{Path=$directory;Status='Unreadable';Detail=$_.Exception.Message})
                continue
            }
            foreach ($file in $children) {
                if ($file.Attributes -band [IO.FileAttributes]::ReparsePoint) { $links++; continue }
                if ($file.PSIsContainer) { $pending.Push($file.FullName); continue }
                $examined++
                $reasons=@()
                $extension=$file.Extension.ToLowerInvariant()
                if ($extension -in $MediaExtensions) { $reasons+='Media' }
                if ($extension -in @('.zip','.7z','.rar','.tar','.gz','.iso')) { $reasons+='Archive' }
                if ($file.Name -in $ToolNames) { $reasons+='ToolFilename' }
                $hidden=[bool]($file.Attributes -band [IO.FileAttributes]::Hidden)
                if ($hidden -and $extension -in @('.exe','.dll','.scr','.ps1','.cmd','.bat','.vbs','.js')) { $reasons+='HiddenExecutableOrScript' }
                if ($reasons.Count) {
                    $rows.Add([pscustomobject]@{FullName=$file.FullName;Length=$file.Length;LastWriteTimeUtc=$file.LastWriteTimeUtc;Hidden=$hidden;Reason=($reasons -join ', ')})
                }
            }
        }
    }
    [pscustomobject]@{
        Status=$(if ($issues.Count) {'Partial'} else {'CompleteWithinScope'})
        Roots=$Roots;FilesExamined=$examined;DirectoriesExamined=$directories
        SkippedReparsePoints=$links;UnreadableLocations=$issues.ToArray();Files=$rows.ToArray()
        Scope='Accessible ordinary files in these roots only; reparse points are skipped. Filename/attribute matches are review candidates, not malware verdicts. Archives are not opened.'
    }
}

function Get-LabCommandImage {
    param([string]$Command)
    $value=[Environment]::ExpandEnvironmentVariables($Command).Trim()
    if ($value -match '^"([^"]+)"') { return $Matches[1] }
    if ($value -match '^(.+?\.exe)(?=\s|$)') { return $Matches[1] }
    return ''
}

function Test-LabRemoteShellCommand {
    param([string]$Command)
    # Detect renamed netcat/ncat-style shell execution regardless of filename/port.
    # A match requests authorization review; diagnostic tools can use these options.
    return $Command -match '(?i)(?:^|\s)--?(?:e|c|exec|sh-exec)\s+["'']?(?:[^\s"'']*\\)?(?:cmd|powershell|pwsh)(?:\.exe)?(?=["''\s]|$)'
}

function Get-LabReviewRegistryValue {
    param([string]$Path,[string]$Name)
    try {
        $key=Get-Item -LiteralPath $Path -ErrorAction Stop
        if ($Name -in $key.GetValueNames()) {
            return [pscustomobject]@{Path=$Path;Name=$Name;Status='Present';Value=$key.GetValue($Name)}
        }
        [pscustomobject]@{Path=$Path;Name=$Name;Status='NotExplicitlySet';Value=$null}
    } catch {
        $missing=$_.CategoryInfo.Category -eq 'ObjectNotFound'
        [pscustomobject]@{Path=$Path;Name=$Name;Status=$(if ($missing) {'NotExplicitlySet'} else {'Unknown'});Value=$null}
    }
}

function Invoke-LabExtendedReview {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$OutputDirectory)
    $findings=New-Object 'System.Collections.Generic.List[object]'
    $sections=[ordered]@{}
    function Add-Review {
        param([string]$Area,[string]$Target,[string]$Detail,[string]$Priority='Review')
        $findings.Add([pscustomobject]@{Priority=$Priority;Area=$Area;Target=$Target;Detail=$Detail})
    }
    foreach ($name in @('processes','listeners','tasks','services','startup','exclusions','defender')) {
        try {
            $path=Join-Path $OutputDirectory ("before-$name.json")
            $rows=ConvertFrom-Json -InputObject (Get-Content -LiteralPath $path -Raw -ErrorAction Stop) -ErrorAction Stop
            $sections[$name]=[pscustomobject]@{Status='Complete';Rows=@($rows)}
        } catch {
            $sections[$name]=[pscustomobject]@{Status='Unknown';Rows=@()}
            Add-Review 'Collection' $name $_.Exception.Message
        }
    }
    $commands=New-Object 'System.Collections.Generic.List[object]'
    foreach ($p in $sections.processes.Rows) {
        if (-not $p.PSObject.Properties['CommandLine']) { continue }
        $ports=@($sections.listeners.Rows | Where-Object OwningProcess -eq $p.ProcessId | ForEach-Object LocalPort | Sort-Object -Unique)
        $commands.Add([pscustomobject]@{Source='Process';Target=[string]$p.ProcessId;Image=[string]$p.ExecutablePath;Command=[string]$p.CommandLine;ListeningPorts=$ports})
    }
    foreach ($task in $sections.tasks.Rows) {
        foreach ($action in $task.Actions) {
            $command=([string]$action.Execute+' '+[string]$action.Arguments).Trim()
            $image=[Environment]::ExpandEnvironmentVariables([string]$action.Execute).Trim('"')
            $commands.Add([pscustomobject]@{Source='Task';Target=($task.TaskPath+$task.TaskName);Image=$image;Command=$command;ListeningPorts=@()})
        }
    }
    foreach ($service in $sections.services.Rows) {
        $commands.Add([pscustomobject]@{Source='Service';Target=$service.Name;Image=(Get-LabCommandImage $service.PathName);Command=$service.PathName;ListeningPorts=@()})
    }
    foreach ($startup in $sections.startup.Rows) {
        $commands.Add([pscustomobject]@{Source='Startup';Target=$startup.Name;Image=(Get-LabCommandImage $startup.Command);Command=$startup.Command;ListeningPorts=@()})
    }
    $shells=@($commands.ToArray() | Where-Object {Test-LabRemoteShellCommand $_.Command})
    foreach ($command in $shells) {
        Add-Review 'ShellExecution' ($command.Source+': '+$command.Target) ("Command: $($command.Command); TCP listeners: $($command.ListeningPorts -join ', '). Inspect file, task/service/startup persistence and exclusions together. No command was executed.") 'High'
    }
    $exclusionRows=New-Object 'System.Collections.Generic.List[object]'
    foreach ($preferences in $sections.exclusions.Rows) {
        foreach ($kind in @('ExclusionPath','ExclusionProcess','ExclusionExtension')) {
            foreach ($value in @($preferences.$kind)) {
                if ([string]::IsNullOrWhiteSpace([string]$value)) { continue }
                $expanded=[Environment]::ExpandEnvironmentVariables([string]$value).Trim('"').TrimEnd('\')
                $related=@($shells | Where-Object {
                    ($_.Image -and $_.Image.TrimEnd('\') -ieq $expanded) -or
                    ($kind -eq 'ExclusionProcess' -and [IO.Path]::GetFileName($_.Image) -ieq $expanded)
                })
                $broad=($kind -eq 'ExclusionPath' -and ($expanded -match '^[A-Za-z]:$|[*?]' -or $expanded -iin @("$env:SystemDrive\Users",$env:ProgramData,$env:SystemRoot))) -or
                    ($kind -eq 'ExclusionExtension' -and $expanded.TrimStart('.') -in @('exe','dll','ps1','cmd','bat','vbs','js','*'))
                $exclusionRows.Add([pscustomobject]@{Kind=$kind;Value=[string]$value;Broad=[bool]$broad;RelatedShellCommands=$related})
                if ($related.Count) { Add-Review 'DefenderExclusion' ([string]$value) 'Exact exclusion is associated with a shell-execution candidate. Confirm authorization before removing only this exception.' 'High' }
                elseif ($broad) { Add-Review 'DefenderExclusion' ([string]$value) 'Broad antivirus exclusion requires review; required CCS exceptions must be preserved.' 'High' }
            }
        }
        if ($preferences.PSObject.Properties['PUAProtection'] -and [int]$preferences.PUAProtection -ne 1) {
            Add-Review 'Defender' 'PUAProtection' "Observed $($preferences.PUAProtection); 1 enables blocking, 2 is audit only." 'High'
        }
        if ($preferences.PSObject.Properties['SubmitSamplesConsent'] -and [int]$preferences.SubmitSamplesConsent -in @(0,2)) {
            Add-Review 'Defender' 'SubmitSamplesConsent' "Observed $($preferences.SubmitSamplesConsent). Automatic safe-sample submission (1) supports block at first sight; consider privacy/scenario requirements. Read policy and tamper state before changing it." 'High'
        }
        if ($preferences.PSObject.Properties['MAPSReporting'] -and [int]$preferences.MAPSReporting -eq 0) { Add-Review 'Defender' 'MAPSReporting' 'Cloud reporting is disabled; review scenario requirements.' }
        if ($preferences.PSObject.Properties['DisableBlockAtFirstSeen'] -and $preferences.DisableBlockAtFirstSeen) { Add-Review 'Defender' 'DisableBlockAtFirstSeen' 'Block-at-first-sight preference is disabled.' }
    }
    $policyRows=@(
        Get-LabReviewRegistryValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet' 'SubmitSamplesConsent'
        Get-LabReviewRegistryValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer' 'DisableNotificationCenter'
        Get-LabReviewRegistryValue 'HKCU:\SOFTWARE\Policies\Microsoft\Windows\Explorer' 'DisableNotificationCenter'
        Get-LabReviewRegistryValue 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' 'HideSCAHealth'
        Get-LabReviewRegistryValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender Security Center\Notifications' 'DisableNotifications'
        Get-LabReviewRegistryValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender Security Center\Notifications' 'DisableEnhancedNotifications'
    )
    foreach ($row in $policyRows) {
        if ($row.Status -eq 'Unknown') { Add-Review 'Policy' ($row.Path+'\'+$row.Name) 'Policy could not be read; do not interpret it as absent.' }
        elseif ($row.Status -eq 'Present' -and $row.Name -ne 'SubmitSamplesConsent' -and [int]$row.Value -eq 1) {
            Add-Review 'SecurityNotifications' ($row.Path+'\'+$row.Name) 'Security notifications/icon are explicitly hidden. Review the README monitoring requirement.' 'High'
        } elseif ($row.Status -eq 'Present' -and $row.Name -eq 'SubmitSamplesConsent' -and [int]$row.Value -eq 2) {
            Add-Review 'DefenderPolicy' ($row.Path+'\'+$row.Name) 'Never-send policy is explicit. A Set-MpPreference call may not change the effective value. Use the documented MAPS policy and verify readback; never disable tamper protection automatically.' 'High'
        }
    }
    try {
        $apps=ConvertFrom-Json -InputObject (Get-Content -LiteralPath (Join-Path $OutputDirectory 'applications.json') -Raw -ErrorAction Stop)
        foreach ($group in @($apps | Group-Object Name | Where-Object Count -gt 1)) {
            Add-Review 'Applications' $group.Name ("Multiple registrations: $((@($group.Group | ForEach-Object Version)) -join ', '). Verify actual versions, architecture and installation paths; do not blindly uninstall an old-looking entry.")
        }
    } catch { Add-Review 'Collection' 'Applications' $_.Exception.Message }
    $evidence=[pscustomobject]@{Snapshots=$sections;Commands=$commands.ToArray();ShellCandidates=$shells;Exclusions=$exclusionRows.ToArray();Policies=$policyRows}
    ConvertTo-Json -InputObject $evidence -Depth 14 | Set-Content -LiteralPath (Join-Path $OutputDirectory 'extended-evidence.json') -Encoding UTF8
    ConvertTo-Json -InputObject ($findings.ToArray()) -Depth 8 | Set-Content -LiteralPath (Join-Path $OutputDirectory 'extended-findings.json') -Encoding UTF8
    $review=@(
        'Extended review: selected evidence before hardening, not a malware/scoring verdict.'
        'Open review-files.json and file-scan-status.json for media, archives, tools, hidden scripts and unreadable locations.'
        'Preserve forensic evidence and required software/services. Review exact targets before using reviewed cleanup.'
        'Only current-user notification policy is checked; other users/offline hives and archives need separate review.'
        ''
    )
    $review+=@($findings.ToArray() | ForEach-Object {"[$($_.Priority)] $($_.Area): $($_.Target) -- $($_.Detail)"})
    $review | Set-Content -LiteralPath (Join-Path $OutputDirectory 'extended-review.txt') -Encoding UTF8
    Write-Host "Extended review: $($findings.Count) items. Open extended-review.txt and review-files.json."
}

Export-ModuleMember -Function Get-LabReviewFileInventory,Invoke-LabExtendedReview
