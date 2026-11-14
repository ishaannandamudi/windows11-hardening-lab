#Requires -Version 5.1
# Only temporary fixture files may be deleted; all Windows actions are harmless stubs.
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
$root=Split-Path -Parent $PSScriptRoot
function Assert-True { param([bool]$Condition,[string]$Message) if (-not $Condition) { throw $Message } }
function Assert-Throws { param([scriptblock]$Read,[string]$Message) $failed=$false; try { & $Read | Out-Null } catch { $failed=$true }; Assert-True $failed $Message }
$tokens=$null; $errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile((Join-Path $root 'modules\Lab.Cleanup.psm1'),[ref]$tokens,[ref]$errors)
Assert-True ($errors.Count -eq 0) 'Cleanup module must parse in Windows PowerShell 5.1.'
foreach ($node in $ast.EndBlock.Statements) {
    if ($node -is [Management.Automation.Language.FunctionDefinitionAst]) { . ([scriptblock]::Create($node.Extent.Text)) }
}
$temp=Join-Path ([Environment]::GetFolderPath('UserProfile')) ('lab-cleanup-fixture-'+[guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $temp | Out-Null
$file=Join-Path $temp 'song[1].mp3'
'reviewed fixture' | Set-Content -LiteralPath $file
$hash=(Get-FileHash -LiteralPath $file -Algorithm SHA256).Hash
function New-Plan {
    [pscustomobject]@{
        SchemaVersion=1;ComputerName=$env:COMPUTERNAME;ForensicsComplete=$true
        Files=@([pscustomobject]@{Path=$file;SHA256=$hash;AllowSystemPath=$false;StopMatchingProcesses=$false})
        Tasks=@();DefenderExclusions=@();EnableSafeSampleSubmission=$false
    }
}
$script:Preference=[pscustomobject]@{ExclusionPath=@('C:\Temp\reviewed.exe','C:\Program Files\CCS\ccsclient.exe');ExclusionProcess=@();ExclusionExtension=@();SubmitSamplesConsent=2}
$script:Removes=0; $script:Sets=0; $script:BlockWrites=$false
function Get-MpPreference { [CmdletBinding()]param() $script:Preference }
function Remove-MpPreference {
    [CmdletBinding()]param([string]$ExclusionPath,[string]$ExclusionProcess,[string]$ExclusionExtension)
    $script:Removes++
    if (-not $script:BlockWrites) { $script:Preference.ExclusionPath=@($script:Preference.ExclusionPath | Where-Object {$_ -ine $ExclusionPath}) }
}
function Set-MpPreference { [CmdletBinding()]param([int]$SubmitSamplesConsent) $script:Sets++; if (-not $script:BlockWrites) { $script:Preference.SubmitSamplesConsent=$SubmitSamplesConsent } }
$script:Task=[pscustomobject]@{TaskName='FixtureTask';TaskPath='\';State='Ready';Actions=@([pscustomobject]@{Execute=$file;Arguments='fixture'})}
function Get-ScheduledTask { [CmdletBinding()]param() $script:Task }
function Export-ScheduledTask { [CmdletBinding()]param($TaskName,$TaskPath) '<fixture />' }
function Disable-ScheduledTask { [CmdletBinding()]param($InputObject) $script:Task.State='Disabled' }
function Stop-ScheduledTask { [CmdletBinding()]param($InputObject) throw 'Unexpected task stop in a nonrunning fixture' }
try {
    $plan=New-Plan
    Test-LabCleanupPlan $plan
    $result=@(Invoke-LabReviewedCleanup -Plan $plan -OutputDirectory $temp)
    Assert-True ((Test-Path -LiteralPath $file) -and $result[0].Status -eq 'Planned') 'Audit must never delete reviewed files.'
    $plan.ForensicsComplete=$false
    Assert-Throws {Invoke-LabReviewedCleanup -Plan $plan -OutputDirectory $temp -Mode Apply} 'Incomplete forensics must block Apply.'
    $plan=New-Plan; $plan.ComputerName='another-computer'
    Assert-Throws {Test-LabCleanupPlan $plan} 'A different computer must be rejected.'
    $plan=New-Plan; $plan.Files[0].SHA256=('0'*64)
    Assert-Throws {Invoke-LabReviewedCleanup -Plan $plan -OutputDirectory $temp -Mode Apply} 'Wrong hashes must prevent any cleanup.'
    Assert-True (Test-Path -LiteralPath $file) 'Hash refusal must preserve the file.'
    $plan=New-Plan; $plan.Files[0].Path=$temp
    Assert-Throws {Test-LabCleanupPlan $plan} 'Directories must never enter file cleanup.'
    $plan=New-Plan; $plan.Files[0].Path=Join-Path $temp '*.mp3'
    Assert-Throws {Test-LabCleanupPlan $plan} 'Wildcard targets must be rejected.'
    $plan=New-Plan; $plan.Files[0].Path=Join-Path $temp 'file.mp3:stream'
    Assert-Throws {Test-LabCleanupPlan $plan} 'Alternate data streams must be rejected.'
    $plan=New-Plan; $plan.Files[0].Path=Join-Path $temp 'ccsclient.exe'
    Assert-Throws {Test-LabCleanupPlan $plan} 'Scoring components must be protected even when absent.'
    $plan=New-Plan; $plan.Files[0].StopMatchingProcesses=$true
    Assert-Throws {Test-LabCleanupPlan $plan} 'Non-executable process-stop requests must be rejected before mutation.'
    $plan=New-Plan; $plan.DefenderExclusions=@([pscustomobject]@{Kind='Path';Value='C:\Program Files\CCS\ccsclient.exe'})
    Assert-Throws {Test-LabCleanupPlan $plan} 'CCS exclusions must not be removed by this helper.'
    $plan=New-Plan
    $plan.Tasks=@([pscustomobject]@{TaskName='FixtureTask';TaskPath='\';ExpectedExecute=$file;ExpectedArguments='changed'})
    Assert-Throws {Test-LabCleanupPlan $plan} 'Changed task actions must block all cleanup.'
    $plan.Tasks[0].ExpectedArguments='fixture'
    $plan.DefenderExclusions=@([pscustomobject]@{Kind='Path';Value='C:\Temp\reviewed.exe'})
    $plan.EnableSafeSampleSubmission=$true
    $result=@(Invoke-LabReviewedCleanup -Plan $plan -OutputDirectory $temp -Mode Apply -WhatIf)
    Assert-True ((Test-Path -LiteralPath $file) -and $script:Task.State -eq 'Ready' -and $script:Removes -eq 0 -and $script:Sets -eq 0) 'WhatIf must prevent file, task, exclusion and sample-submission mutations.'
    $result=@(Invoke-LabReviewedCleanup -Plan $plan -OutputDirectory $temp -Mode Apply)
    Assert-True (-not (Test-Path -LiteralPath $file)) 'Only the exact hash-reviewed temporary media file should be deleted.'
    Assert-True ($script:Task.State -eq 'Disabled' -and $script:Removes -eq 1 -and $script:Preference.ExclusionPath.Count -eq 1) 'Exact task disabling and single exclusion removal must preserve the approved CCS exception.'
    Assert-True ($script:Preference.SubmitSamplesConsent -eq 1 -and @($result | Where-Object Status -eq 'Failed').Count -eq 0) 'A successful explicit sample-submission change must pass readback.'
    $plan.Tasks=@(); $plan.EnableSafeSampleSubmission=$false
    $again=@(Invoke-LabReviewedCleanup -Plan $plan -OutputDirectory $temp -Mode Apply)
    Assert-True (@($again | Where-Object Status -eq 'AlreadyAbsent').Count -eq 1 -and @($again | Where-Object Status -eq 'NotListed').Count -eq 1) 'Missing files and unlisted/possibly hidden exclusions must remain distinct without mutating other targets.'
    $plan.Files=@(); $plan.DefenderExclusions=@(); $plan.EnableSafeSampleSubmission=$true; $script:BlockWrites=$true; $script:Preference.SubmitSamplesConsent=2
    $blocked=@(Invoke-LabReviewedCleanup -Plan $plan -OutputDirectory $temp -Mode Apply)
    Assert-True ($blocked[0].Status -eq 'Failed' -and $blocked[0].Detail -like '*overridden/blocked*') 'Silent Defender policy/tamper overrides must be reported as failed readback.'
    $plan.EnableSafeSampleSubmission=$false; $plan.DefenderExclusions=@([pscustomobject]@{Kind='Path';Value='C:\Program Files\Other\other.exe'})
    $script:Preference.ExclusionPath+= 'C:\Program Files\Other\other.exe'
    $blocked=@(Invoke-LabReviewedCleanup -Plan $plan -OutputDirectory $temp -Mode Apply)
    Assert-True ($blocked[0].Status -eq 'Failed') 'Blocked exclusion removal must not claim success.'
    # Process cleanup must use the reviewed image, never just a matching name/PID.
    $exe=Join-Path $temp 'renamed.exe'
    'synthetic executable, never run' | Set-Content -LiteralPath $exe
    function Get-AuthenticodeSignature { [CmdletBinding()]param($LiteralPath) [pscustomobject]@{Status=$script:FixtureSignature} }
    $script:FixtureSignature='Valid'
    $plan=New-Plan
    $plan.Files=@([pscustomobject]@{Path=$exe;SHA256=(Get-FileHash -LiteralPath $exe -Algorithm SHA256).Hash;AllowSystemPath=$false;StopMatchingProcesses=$true})
    Assert-Throws {Test-LabCleanupPlan $plan} 'Validly signed executable files must require manual software review.'
    $script:FixtureSignature='NotSigned'
    $script:GoodProcess=[pscustomobject]@{Path=$exe;HasExited=$false}
    $script:GoodProcess | Add-Member -MemberType ScriptMethod -Name WaitForExit -Value {param($Timeout) return $this.HasExited}
    $script:OtherProcess=[pscustomobject]@{Path=(Join-Path $temp 'elsewhere\renamed.exe');HasExited=$false}
    $script:ProcessStops=0
    function Get-Process { [CmdletBinding()]param() $script:GoodProcess; $script:OtherProcess }
    function Stop-Process { [CmdletBinding()]param($InputObject) $script:ProcessStops++; $InputObject.HasExited=$true }
    $result=@(Invoke-LabReviewedCleanup -Plan $plan -OutputDirectory $temp -Mode Apply)
    Assert-True ($script:ProcessStops -eq 1 -and $script:GoodProcess.HasExited -and -not $script:OtherProcess.HasExited -and -not (Test-Path -LiteralPath $exe)) 'Only the matching reviewed image may be stopped/deleted.'
    Remove-Item Function:\Get-Process,Function:\Stop-Process,Function:\Get-AuthenticodeSignature
} finally { Remove-Item -LiteralPath $temp -Recurse -Force }
Write-Host 'PASS: hash/path/computer/forensic guards, exact task actions, Audit/WhatIf isolation, literal temporary-file removal, preserved exclusions and Defender readback. Windows actions stubbed.'
