#Requires -Version 5.1
# Real temporary-file traversal; synthetic Windows inventories. No remediation.
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
$root=Split-Path -Parent $PSScriptRoot
function Assert-True { param([bool]$Condition,[string]$Message) if (-not $Condition) { throw $Message } }
$tokens=$null; $errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile((Join-Path $root 'modules\Lab.Review.psm1'),[ref]$tokens,[ref]$errors)
Assert-True ($errors.Count -eq 0) 'Review module must parse in Windows PowerShell 5.1.'
foreach ($node in $ast.EndBlock.Statements) {
    if ($node -is [Management.Automation.Language.FunctionDefinitionAst]) { . ([scriptblock]::Create($node.Extent.Text)) }
}
foreach ($entry in @('Audit.ps1','Invoke-ReviewedCleanup.ps1','modules\Lab.Cleanup.psm1')) {
    [void][Management.Automation.Language.Parser]::ParseFile((Join-Path $root $entry),[ref]$tokens,[ref]$errors)
    Assert-True ($errors.Count -eq 0) "Parse failure: $entry"
}
Assert-True (Test-LabRemoteShellCommand '"C:\Windows\System32\renamed.exe" -L -p 41111 -e cmd.exe') 'Renamed shell listener must be detected without hard-coded filename/port.'
Assert-True (Test-LabRemoteShellCommand 'ncat.exe --listen 1234 --exec powershell.exe') 'Long command-execution option must be detected.'
Assert-True (-not (Test-LabRemoteShellCommand 'C:\Windows\System32\svchost.exe -k NetworkService -p')) 'Ordinary Windows services must not be identified as remote shells.'
Assert-True (-not (Test-LabRemoteShellCommand 'C:\Program Files\VMware\vmtoolsd.exe -n vmusr')) 'VM guest integration must not be classified as shell execution.'
Assert-True ((Get-LabCommandImage '"C:\Program Files\Vendor\app.exe" -n x') -eq 'C:\Program Files\Vendor\app.exe') 'Quoted paths must retain spaces.'
$temp=Join-Path ([IO.Path]::GetTempPath()) ([guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $temp | Out-Null
try {
    $scan=Join-Path $temp 'scan'
    $skip=Join-Path $scan 'reports'
    New-Item -ItemType Directory -Path $skip -Force | Out-Null
    foreach ($name in @('song[1].mp3','download.zip','readme.txt','hidden.ps1','renamed.exe')) { 'fixture' | Set-Content -LiteralPath (Join-Path $scan $name) }
    'skip fixture' | Set-Content -LiteralPath (Join-Path $skip 'skip.mp3')
    $hidden=Get-Item -LiteralPath (Join-Path $scan 'hidden.ps1')
    $hidden.Attributes=$hidden.Attributes -bor [IO.FileAttributes]::Hidden
    $inventory=Get-LabReviewFileInventory -Roots @($scan,$scan) -MediaExtensions @('.mp3') -ToolNames @('renamed.exe') -ExcludeRoot $skip
    Assert-True ($inventory.Status -eq 'CompleteWithinScope' -and $inventory.Files.Count -eq 4) 'Media, archives, hidden scripts and tool names must be found once, with internal report roots skipped.'
    Assert-True (@($inventory.Files | Where-Object Reason -eq 'HiddenExecutableOrScript').Count -eq 1) 'Hidden script attributes must be inspected.'
    Assert-True (Test-Path -LiteralPath (Join-Path $scan 'song[1].mp3')) 'Review must not delete files.'
    function Get-ChildItem { [CmdletBinding()]param([string]$LiteralPath,[switch]$Force) throw 'Synthetic access denied' }
    $denied=Get-LabReviewFileInventory -Roots @($scan) -MediaExtensions @('.mp3') -ToolNames @()
    Assert-True ($denied.Status -eq 'Partial' -and $denied.UnreadableLocations.Count -eq 1) 'Access-denied scanning must not produce a clean/complete claim.'
    Remove-Item Function:\Get-ChildItem
    $snapshots=@{
        processes=@([pscustomobject]@{ProcessId=42;ExecutablePath='C:\Windows\System32\renamed.exe';CommandLine='"C:\Windows\System32\renamed.exe" -L -p 41111 -e cmd.exe'})
        listeners=@([pscustomobject]@{OwningProcess=42;LocalPort=41111})
        tasks=@([pscustomobject]@{TaskPath='\';TaskName='FixtureTask';Actions=@([pscustomobject]@{Execute='C:\Windows\System32\renamed.exe';Arguments='-L -p 41111 -e cmd.exe'})})
        services=@()
        startup=@([pscustomobject]@{Name='SecurityHealth';Command='%windir%\System32\SecurityHealthSystray.exe'})
        exclusions=@([pscustomobject]@{ExclusionPath=@('C:\Windows\System32\renamed.exe');ExclusionProcess=@();ExclusionExtension=@('exe');PUAProtection=1;MAPSReporting=2;SubmitSamplesConsent=2;DisableBlockAtFirstSeen=$false})
        defender=@([pscustomobject]@{IsTamperProtected=$true})
        effectivefirewall=@([pscustomobject]@{Name='Public';Enabled='False'})
    }
    foreach ($name in $snapshots.Keys) { ConvertTo-Json -InputObject $snapshots[$name] -Depth 8 | Set-Content -LiteralPath (Join-Path $temp ("before-$name.json")) }
    ConvertTo-Json -InputObject @([pscustomobject]@{Name='Fixture';Version='1'},[pscustomobject]@{Name='Fixture';Version='2'}) | Set-Content (Join-Path $temp 'applications.json')
    function Get-LabReviewRegistryValue {
        param([string]$Path,[string]$Name)
        [pscustomobject]@{Path=$Path;Name=$Name;Status='Present';Value=$(if ($Name -eq 'SubmitSamplesConsent') {2} else {1})}
    }
    Invoke-LabExtendedReview -OutputDirectory $temp
    $evidence=Get-Content (Join-Path $temp 'extended-evidence.json') -Raw | ConvertFrom-Json
    $findings=Get-Content (Join-Path $temp 'extended-findings.json') -Raw | ConvertFrom-Json
    Assert-True ($evidence.ShellCandidates.Count -eq 2 -and $evidence.ShellCandidates[0].ListeningPorts[0] -eq 41111) 'Process-to-port correlation and matching task must survive serialization.'
    Assert-True ($evidence.Exclusions[0].RelatedShellCommands.Count -eq 2) 'Exact exclusion must be connected to both process and persistence evidence.'
    Assert-True (@($findings | Where-Object Area -eq 'FirewallPolicy').Count -eq 1) 'Disabled effective firewall must be surfaced even when persistent preference writes were successful.'
    Assert-True (@($findings | Where-Object Area -eq 'DefenderPolicy').Count -eq 1) 'Never-send policy must produce an actionable review item.'
    Assert-True (@($findings | Where-Object Area -eq 'Applications').Count -eq 1) 'Duplicate registrations need review, not automatic uninstall.'
    Remove-Item -LiteralPath (Join-Path $temp 'before-processes.json')
    Invoke-LabExtendedReview -OutputDirectory $temp
    $evidence=Get-Content (Join-Path $temp 'extended-evidence.json') -Raw | ConvertFrom-Json
    Assert-True ($evidence.Snapshots.processes.Status -eq 'Unknown' -and $evidence.ShellCandidates.Count -eq 1) 'Missing inventory must remain Unknown while other collectors continue.'
} finally {
    Remove-Item Function:\Get-ChildItem -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath $temp -Recurse -Force
}
Write-Host 'PASS: selected file coverage, hidden scripts, denied scope, renamed shell correlation, exclusion/policy findings and empty/missing inventories. No Windows remediation.'
