#Requires -Version 5.1
# Explicit reviewed targets only. Importing this module performs no work.
Set-StrictMode -Version Latest

function Assert-LabCleanupObject {
    param($Value,[string[]]$Names,[string]$Context)
    if ($null -eq $Value -or $Value -isnot [pscustomobject]) { throw "$Context must be a JSON object." }
    foreach ($name in $Names) { if (-not $Value.PSObject.Properties[$name]) { throw "$Context is missing $name." } }
    foreach ($name in $Value.PSObject.Properties.Name) { if ($name -notin $Names) { throw "Unsupported field $Context.$name." } }
}

function Assert-LabCleanupText {
    param($Value,[string]$Context,[switch]$AllowEmpty)
    if ($Value -isnot [string] -or (-not $AllowEmpty -and [string]::IsNullOrWhiteSpace($Value))) { throw "$Context must be text." }
}

function Test-LabCleanupProtectedName {
    param([string]$Value)
    return $Value -match '(?i)ccsclient|cyberpatriot|vmware|virtualbox|vmtools|vbox|forensic|scoring|Windows11HardeningLab'
}

function Get-LabCleanupFile {
    param($Entry)
    Assert-LabCleanupText $Entry.Path 'Files.Path'
    if ($Entry.Path -notmatch '^[A-Za-z]:\\' -or $Entry.Path.Substring(2) -match '[:*?]' -or $Entry.Path.Contains('..')) {
        throw 'File targets require ordinary absolute local paths; no wildcards, streams, traversal or device/UNC paths.'
    }
    $path=[IO.Path]::GetFullPath($Entry.Path)
    if (Test-LabCleanupProtectedName $path) { throw "Protected lab/forensic/VM component: $path" }
    $core=@('cmd.exe','powershell.exe','pwsh.exe','lsass.exe','svchost.exe','services.exe','smss.exe','csrss.exe','winlogon.exe','wininit.exe','explorer.exe','taskmgr.exe','rundll32.exe','conhost.exe','reg.exe','regedit.exe','dllhost.exe','spoolsv.exe','sihost.exe','securityhealthsystray.exe','msmpeng.exe','sethc.exe','utilman.exe','osk.exe','narrator.exe','magnify.exe','schtasks.exe','dism.exe','sfc.exe')
    if ([IO.Path]::GetFileName($path) -in $core) { throw "Protected system executable name: $path" }
    $roots=@("$env:SystemDrive\Users",$env:ProgramData,"$env:SystemRoot\Temp","$env:SystemDrive\Temp")
    $ordinary=@($roots | Where-Object {$_ -and $path.StartsWith($_.TrimEnd('\')+'\',[StringComparison]::OrdinalIgnoreCase)}).Count -gt 0
    $systemFolder=Join-Path $env:SystemRoot 'System32'
    $systemException=$Entry.AllowSystemPath -and [IO.Path]::GetDirectoryName($path) -ieq $systemFolder -and [IO.Path]::GetExtension($path) -ieq '.exe'
    if (-not $ordinary -and -not $systemException) { throw "Path is outside allowed cleanup roots. Only an explicitly allowed non-core System32 .exe exception is supported: $path" }
    $current=$path
    while ($current) {
        if (Test-Path -LiteralPath $current -ErrorAction Stop) {
            $component=Get-Item -LiteralPath $current -Force -ErrorAction Stop
            if ($component.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw "Reparse-point target/ancestor is not allowed: $current" }
        }
        $parent=[IO.Path]::GetDirectoryName($current)
        if ($parent -eq $current) { break }
        $current=$parent
    }
    if (-not (Test-Path -LiteralPath $path -ErrorAction Stop)) { return [pscustomobject]@{Path=$path;Status='AlreadyAbsent';SHA256=$Entry.SHA256} }
    $file=Get-Item -LiteralPath $path -Force -ErrorAction Stop
    if ($file.PSIsContainer) { throw "Directories cannot be deleted: $path" }
    $hash=(Get-FileHash -LiteralPath $path -Algorithm SHA256 -ErrorAction Stop).Hash
    if ($hash -ine $Entry.SHA256) { throw "SHA-256 changed or does not match the reviewed file: $path" }
    if ($file.Extension -in @('.exe','.dll','.sys','.ps1','.psm1')) {
        $signature=Get-AuthenticodeSignature -LiteralPath $path -ErrorAction Stop
        if ($signature.Status -eq 'Valid') { throw "Signed executable/script requires separate manual software review: $path" }
        if ($signature.Status -notin @('NotSigned','HashMismatch','NotTrusted')) { throw "Signature verification is inconclusive: $path ($($signature.Status))" }
    }
    [pscustomobject]@{Path=$path;Status='Verified';SHA256=$hash}
}

function Get-LabCleanupTask {
    param($Entry)
    $matches=@(Get-ScheduledTask -ErrorAction Stop | Where-Object {$_.TaskName -ceq $Entry.TaskName -and $_.TaskPath -ieq $Entry.TaskPath})
    if ($matches.Count -ne 1) { throw "Expected exactly one existing task: $($Entry.TaskPath)$($Entry.TaskName)" }
    $task=$matches[0]; $actions=@($task.Actions)
    if ($actions.Count -ne 1 -or [string]$actions[0].Execute -cne $Entry.ExpectedExecute -or [string]$actions[0].Arguments -cne $Entry.ExpectedArguments) {
        throw "Task actions changed or do not exactly match the reviewed command: $($Entry.TaskName)"
    }
    $task
}

function Test-LabCleanupPlan {
    param($Plan)
    Assert-LabCleanupObject $Plan @('SchemaVersion','ComputerName','ForensicsComplete','Files','Tasks','DefenderExclusions','EnableSafeSampleSubmission') 'CleanupPlan'
    if ($Plan.SchemaVersion -isnot [int] -or $Plan.SchemaVersion -ne 1) { throw 'Cleanup plan requires integer SchemaVersion 1.' }
    Assert-LabCleanupText $Plan.ComputerName 'ComputerName'
    if ($Plan.ComputerName -ine $env:COMPUTERNAME) { throw 'Cleanup plan belongs to another computer; create a fresh reviewed plan for this VM.' }
    foreach ($name in @('ForensicsComplete','EnableSafeSampleSubmission')) { if ($Plan.$name -isnot [bool]) { throw "$name must be JSON true or false." } }
    foreach ($name in @('Files','Tasks','DefenderExclusions')) { if ($Plan.$name -isnot [array]) { throw "$name must be a JSON array." } }
    $seen=New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    foreach ($file in $Plan.Files) {
        Assert-LabCleanupObject $file @('Path','SHA256','AllowSystemPath','StopMatchingProcesses') 'Files[]'
        if ($file.SHA256 -isnot [string] -or $file.SHA256 -notmatch '^[A-Fa-f0-9]{64}$') { throw 'Each file requires its reviewed SHA256, not a filename-only match.' }
        foreach ($name in @('AllowSystemPath','StopMatchingProcesses')) { if ($file.$name -isnot [bool]) { throw "Files.$name must be JSON true or false." } }
        if ($file.StopMatchingProcesses -and [IO.Path]::GetExtension($file.Path) -ine '.exe') { throw 'StopMatchingProcesses requires an exact reviewed .exe file.' }
        $target=Get-LabCleanupFile $file
        if (-not $seen.Add('File:'+ $target.Path)) { throw 'Repeated cleanup file.' }
    }
    foreach ($task in $Plan.Tasks) {
        Assert-LabCleanupObject $task @('TaskName','TaskPath','ExpectedExecute','ExpectedArguments') 'Tasks[]'
        foreach ($name in @('TaskName','TaskPath','ExpectedExecute')) { Assert-LabCleanupText $task.$name "Tasks.$name" }
        Assert-LabCleanupText $task.ExpectedArguments 'Tasks.ExpectedArguments' -AllowEmpty
        if ($task.TaskName -match '[\\/*?\[\]]' -or $task.TaskPath -notmatch '^\\([^\\*?\[\]]+\\)*$' -or $task.TaskPath -like '\Microsoft\*' -or (Test-LabCleanupProtectedName ($task.TaskPath+$task.TaskName+$task.ExpectedExecute))) { throw 'Protected or nonliteral task identity.' }
        if (-not $seen.Add('Task:'+ $task.TaskPath+$task.TaskName)) { throw 'Repeated cleanup task.' }
        $image=[Environment]::ExpandEnvironmentVariables($task.ExpectedExecute).Trim('"')
        if ($image -notin @($Plan.Files | ForEach-Object {$_.Path})) { throw 'A task must point directly to a hash-reviewed file in this plan.' }
        Get-LabCleanupTask $task | Out-Null
    }
    foreach ($exclusion in $Plan.DefenderExclusions) {
        Assert-LabCleanupObject $exclusion @('Kind','Value') 'DefenderExclusions[]'
        if ($exclusion.Kind -notin @('Path','Process','Extension')) { throw 'Exclusion Kind must be Path, Process or Extension.' }
        Assert-LabCleanupText $exclusion.Value 'DefenderExclusions.Value'
        if (Test-LabCleanupProtectedName $exclusion.Value) { throw 'Required lab/VM/scoring exclusions cannot be removed by this helper.' }
        if (-not $seen.Add('Exclusion:'+ $exclusion.Kind+':'+$exclusion.Value)) { throw 'Repeated exclusion.' }
    }
}

function Invoke-LabReviewedCleanup {
    [CmdletBinding(SupportsShouldProcess=$true,ConfirmImpact='Medium')]
    param([Parameter(Mandatory)]$Plan,[Parameter(Mandatory)][string]$OutputDirectory,[ValidateSet('Audit','Apply')][string]$Mode='Audit')
    # Full preflight before any cleanup. File hashes/actions are rechecked before mutation.
    if (-not (Test-Path -LiteralPath $OutputDirectory -PathType Container)) { throw 'Cleanup requires an existing restricted report directory.' }
    Test-LabCleanupPlan $Plan
    if ($Mode -eq 'Apply' -and -not $Plan.ForensicsComplete) { throw 'Complete and save forensic answers, then set ForensicsComplete true in the reviewed plan before Apply.' }
    $results=New-Object 'System.Collections.Generic.List[object]'
    $stage='Preflight'; $target='Plan'
    try {
        foreach ($entry in $Plan.Tasks) {
            $stage='DisableTask'; $target=$entry.TaskPath+$entry.TaskName
            $task=Get-LabCleanupTask $entry
            $status='Planned'
            if ($Mode -eq 'Apply' -and $PSCmdlet.ShouldProcess($target,'Export, disable and stop this exact reviewed task')) {
                Export-ScheduledTask -TaskName $entry.TaskName -TaskPath $entry.TaskPath -ErrorAction Stop |
                    Set-Content -LiteralPath (Join-Path $OutputDirectory ("task-"+[guid]::NewGuid().ToString('N')+'.xml')) -Encoding UTF8
                $running=$task.State -eq 'Running'
                Disable-ScheduledTask -InputObject $task -ErrorAction Stop | Out-Null
                if ($running) { Stop-ScheduledTask -InputObject $task -ErrorAction Stop }
                if ((Get-LabCleanupTask $entry).State -ne 'Disabled') { throw 'Task disabling did not pass readback.' }
                $status='Applied'
            }
            $results.Add([pscustomobject]@{Action=$stage;Target=$target;Status=$status;Detail='Task definition retained; exact command verified.'})
        }
        foreach ($entry in $Plan.Files) {
            $stage='DeleteReviewedFile'; $target=$entry.Path
            $verified=Get-LabCleanupFile $entry
            $status='Planned'
            if ($verified.Status -eq 'AlreadyAbsent') { $status='AlreadyAbsent' }
            elseif ($Mode -eq 'Apply' -and $PSCmdlet.ShouldProcess($target,'Delete only this hash-verified file')) {
                if ($entry.StopMatchingProcesses) {
                    if ([IO.Path]::GetExtension($target) -ine '.exe') { throw 'Stopping matching processes is supported only for reviewed .exe files.' }
                    foreach ($process in @(Get-Process -ErrorAction Stop)) {
                        try { $image=$process.Path } catch { continue }
                        if ($image -and $image -ieq $verified.Path) {
                            Get-LabCleanupFile $entry | Out-Null
                            Stop-Process -InputObject $process -ErrorAction Stop
                            $process.WaitForExit(5000) | Out-Null
                            if (-not $process.HasExited) { throw 'Reviewed process has not exited; file deletion stopped.' }
                        }
                    }
                }
                Get-LabCleanupFile $entry | Out-Null
                Remove-Item -LiteralPath $verified.Path -Force -ErrorAction Stop
                if (Test-Path -LiteralPath $verified.Path) { throw 'File removal did not pass readback.' }
                $status='Applied'
            }
            $results.Add([pscustomobject]@{Action=$stage;Target=$target;Status=$status;Detail=("SHA256="+$entry.SHA256)})
        }
        foreach ($entry in $Plan.DefenderExclusions) {
            $stage='RemoveExactExclusion'; $target=$entry.Kind+': '+$entry.Value
            $property='Exclusion'+$entry.Kind
            $current=Get-MpPreference -ErrorAction Stop
            $status='Planned'
            if ($entry.Value -notin @($current.$property)) { $status='NotListed' }
            elseif ($Mode -eq 'Apply' -and $PSCmdlet.ShouldProcess($target,'Remove this single reviewed antivirus exclusion')) {
                $arguments=@{ErrorAction='Stop'}; $arguments[$property]=$entry.Value
                Remove-MpPreference @arguments
                $current=Get-MpPreference -ErrorAction Stop
                if ($entry.Value -in @($current.$property)) { throw 'Exclusion removal was blocked or overridden; no success claimed.' }
                $status='Applied'
            }
            $results.Add([pscustomobject]@{Action=$stage;Target=$target;Status=$status;Detail='Other exclusions preserved. NotListed means not visible in preferences; hidden/policy exclusions require separate verification.'})
        }
        if ($Plan.EnableSafeSampleSubmission) {
            $stage='SafeSampleSubmission'; $target='SubmitSamplesConsent'
            $status='Planned'
            if ($Mode -eq 'Apply' -and $PSCmdlet.ShouldProcess($target,'Allow safe samples to be submitted automatically to Microsoft')) {
                Set-MpPreference -SubmitSamplesConsent 1 -ErrorAction Stop
                if ([int](Get-MpPreference -ErrorAction Stop).SubmitSamplesConsent -ne 1) {
                    throw 'Sample submission is still overridden/blocked. Check MAPS > Send file samples when further analysis is required; set Enabled / Send safe samples, then verify. Tamper protection and policy are not bypassed.'
                }
                $status='Applied'
            }
            $results.Add([pscustomobject]@{Action=$stage;Target=$target;Status=$status;Detail='Desired value 1; automatic submission to Microsoft is an explicit plan choice.'})
        }
    } catch {
        $results.Add([pscustomobject]@{Action=$stage;Target=$target;Status='Failed';Detail=$_.Exception.Message})
        Write-Warning "Cleanup stopped at $stage ($target): $($_.Exception.Message)"
    } finally {
        ConvertTo-Json -InputObject ($results.ToArray()) -Depth 8 | Set-Content -LiteralPath (Join-Path $OutputDirectory 'cleanup-results.json') -Encoding UTF8 -WhatIf:$false
    }
    $results.ToArray()
}

Export-ModuleMember -Function Invoke-LabReviewedCleanup
