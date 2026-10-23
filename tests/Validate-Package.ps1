#Requires -Version 5.1
# Parses the main script and tests helpers/action blocks with harmless stubs.
# It never executes the hardening entrypoint or changes accounts/services.
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$source = Join-Path $root 'Invoke-Windows11LabHardening.ps1'
$tokens = $null; $parseErrors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile($source,[ref]$tokens,[ref]$parseErrors)
if ($parseErrors.Count) { $parseErrors | Format-List; throw 'PowerShell parser errors.' }
function Assert-True { param([bool]$Condition,[string]$Message) if (-not $Condition) { throw $Message } }
function Assert-Throws { param([scriptblock]$Code) $threw=$false; try { & $Code | Out-Null } catch {$threw=$true}; Assert-True $threw 'Expected configuration rejection.' }
foreach ($name in @('Resolve-LabConfigPath','Assert-ProfileProperties','Assert-ProfileInteger','Test-LabProfile','Assert-LabCapabilities','Get-AccountDisposition','Get-CryptoIndex','New-LabPassword','New-RegistryPlan','Set-AccountPolicy','Save-Json','Write-LabWarning','Invoke-LabChange','Invoke-Native')) {
    $definition = $ast.Find({param($node) $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq $name},$true)
    Assert-True ($null -ne $definition) "Missing helper $name"
    . ([scriptblock]::Create($definition.Extent.Text))
}
# Resolve the default beside the saved script, independently of the current directory.
$configFixture = Join-Path ([IO.Path]::GetTempPath()) ([guid]::NewGuid().ToString('N'))
$otherDirectory = Join-Path $configFixture 'elsewhere'
New-Item -ItemType Directory -Path $otherDirectory -Force | Out-Null
$defaultConfig = Join-Path $configFixture 'lab.config.json'
$literalConfig = Join-Path $configFixture 'profile[custom].json'
'{}' | Set-Content -LiteralPath $defaultConfig
'{}' | Set-Content -LiteralPath $literalConfig
try {
    Push-Location $otherDirectory
    try {
        Assert-True ((Resolve-LabConfigPath -ScriptDirectory $configFixture) -eq $defaultConfig) 'Default config must resolve beside the script, not in the current directory.'
        Assert-True ((Resolve-LabConfigPath -Path $literalConfig) -eq $literalConfig) 'Explicit config paths must be treated literally.'
        Assert-True ((Resolve-LabConfigPath -Path ..\lab.config.json) -eq $defaultConfig) 'Explicit relative config paths must resolve from the current directory.'
        Assert-Throws { Resolve-LabConfigPath -ScriptDirectory $otherDirectory }
        Assert-Throws { Resolve-LabConfigPath -Path $configFixture }
        Assert-Throws { Resolve-LabConfigPath }
    } finally { Pop-Location }
} finally { Remove-Item -LiteralPath $configFixture -Recurse -Force }
$profile = Get-Content (Join-Path $root 'lab.config.json') -Raw | ConvertFrom-Json
Test-LabProfile $profile
$script:Profile = $profile
$plan = @(New-RegistryPlan)
Assert-True ($plan.Count -ge 30) 'Registry plan unexpectedly empty.'
foreach ($item in $plan) { Assert-True ($item.Path -like 'HKLM:\*' -and $item.Name -and $item.Type -in @('DWord','String')) 'Invalid registry plan item.' }
Assert-True (@($plan | Where-Object {$_.Name -eq 'EnableLUA' -and $_.Value -eq 1}).Count -eq 1) 'UAC must be enabled.'
Assert-True (@($plan | Where-Object {$_.Name -match 'Javascript|JavaScript'}).Count -eq 0) 'JavaScript must remain unchanged.'
# Use synthetic account names so a new README/profile does not break the suite.
function New-TestProfile {
    $fixture = Get-Content (Join-Path $root 'lab.config.json') -Raw | ConvertFrom-Json
    $fixture.PrimaryAccount='labprimary'
    $fixture.Administrators=@('labprimary','labadmin')
    $fixture.Users=@('labuser','newemployee')
    $fixture.CreateUsers=@('newemployee')
    $fixture.ResetPasswordAccounts=@('labadmin')
    $fixture.RequiredServiceNames=@()
    $fixture.DisableServiceNames=@('RemoteRegistry')
    $fixture.RequiredFeatureNames=@()
    $fixture.DisableFeatureNames=@('IIS-WebServerRole','IIS-FTPServer')
    return $fixture
}
$fixture = New-TestProfile
Test-LabProfile $fixture
$sidPrefix='S-1-5-21-100-200-300'
Assert-True ((Get-AccountDisposition 'labprimary' "$sidPrefix-1000" $fixture @('labprimary')) -eq 'Protected') 'Primary must be protected.'
Assert-True ((Get-AccountDisposition 'session-admin' "$sidPrefix-1099" $fixture @('session-admin')) -eq 'Protected') 'Executing account must be protected.'
Assert-True ((Get-AccountDisposition 'attacker' "$sidPrefix-1099" $fixture @('labprimary')) -eq 'DisableUnauthorized') 'Unknown human account must be disabled.'
Assert-True ((Get-AccountDisposition 'labuser' "$sidPrefix-1001" $fixture @('labprimary')) -eq 'StandardUser') 'Standard user misclassified.'
Assert-True ((Get-AccountDisposition 'labadmin' "$sidPrefix-1002" $fixture @('labprimary')) -eq 'Administrator') 'Administrator misclassified.'
Assert-True ((Get-AccountDisposition 'renamed-guest' "$sidPrefix-501" $fixture @('labprimary')) -eq 'DisableGuest') 'Guest must be recognized by SID even when renamed.'
Assert-True ((Get-AccountDisposition 'DefaultAccount' "$sidPrefix-503" $fixture @('labprimary')) -eq 'PreserveBuiltin') 'System account must not be treated as an employee.'
foreach ($invalidRoot in @($null,42,'text',@())) { Assert-Throws {Test-LabProfile $invalidRoot} }
foreach ($mutate in @(
    {param($p) $p.PSObject.Properties.Remove('Users')},
    {param($p) $p | Add-Member -NotePropertyName MisspelledField -NotePropertyValue 1},
    {param($p) $p.Users='labuser'},
    {param($p) $p.Users=@($null)},
    {param($p) $p.Users=@(' labuser')},
    {param($p) $p.Users=@('labuser','LABUSER')},
    {param($p) $p.Users += 'labprimary'},
    {param($p) $p.Administrators=@('labadmin')},
    {param($p) $p.RemoveNonSystemShares='false'},
    {param($p) $p.SchemaVersion='1'},
    {param($p) $p.LockAfterSeconds=0},
    {param($p) $p.LockAfterSeconds=599941},
    {param($p) $p.LockAfterSeconds=600.5},
    {param($p) $p.PasswordPolicy.History='24'},
    {param($p) $p.PasswordPolicy.PSObject.Properties.Remove('MaximumAgeDays')},
    {param($p) $p.PasswordPolicy.LockoutMinutes=$p.PasswordPolicy.ResetCounterMinutes-1},
    {param($p) $p.PasswordPolicy.LockoutMinutes=100000},
    {param($p) $p.DisableServiceNames += 'EventLog'},
    {param($p) $p.DisableServiceNames += 'CCSClient'},
    {param($p) $p.DisableServiceNames += 'Remote*'},
    {param($p) $p.DisableFeatureNames += 'IIS-*'},
    {param($p) $p.ApplicationPackageIds=@('--help')},
    {param($p) $p.MediaExtensions=@('mp3')},
    {param($p) $p.ReviewExecutableNames=@('C:\Temp\tool.exe')},
    {param($p) $p.RequiredServiceNames=@('TermService')},
    {param($p) $p.RequiredServiceNames=@('WinRM')},
    {param($p) $p.RequiredServiceNames=@('W3SVC')}
)) {
    $bad = New-TestProfile
    & $mutate $bad
    Assert-Throws {Test-LabProfile $bad}
}
$valid = New-TestProfile
$valid.RequiredServiceNames=@('Spooler')
Test-LabProfile $valid
$valid = New-TestProfile
$valid.RequiredServiceNames=@('W3SVC'); $valid.RequiredFeatureNames=@('IIS-WebServerRole')
Test-LabProfile $valid
$valid = New-TestProfile
$valid.Users=@(); $valid.CreateUsers=@()
Test-LabProfile $valid
# Exercise real, harmless native processes: stderr alone is not a failed exit.
$nativeLog = [IO.Path]::GetTempFileName()
try {
    $nativeOutput = @(Invoke-Native 'cmd.exe' @('/d','/c','echo diagnostic-message 1>&2 & exit /b 0') -OutputPath $nativeLog)
    Assert-True (($nativeOutput -join ' ') -like '*diagnostic-message*') 'Native stderr must be preserved.'
    Assert-True ((Get-Content -LiteralPath $nativeLog -Raw) -like '*diagnostic-message*') 'Successful native commands must save requested output logs.'
    Assert-True ($ErrorActionPreference -eq 'Stop') 'Native handling must restore the caller error preference.'
    $nativeFailure=$null
    try { Invoke-Native 'cmd.exe' @('/d','/c','echo native-failure 1>&2 & exit /b 7') -OutputPath $nativeLog | Out-Null }
    catch { $nativeFailure=$_.Exception.Message }
    Assert-True ($nativeFailure -like '*failed (7)*native-failure*') 'Native nonzero exits must remain failures with useful output.'
    Assert-True ((Get-Content -LiteralPath $nativeLog -Raw) -like '*native-failure*') 'Failed native commands must also save their requested output logs.'
    Assert-True ($ErrorActionPreference -eq 'Stop') 'Error preference must also be restored after failure.'
    Assert-Throws { Invoke-Native 'windows11-lab-nonexistent-command.exe' @() }
    & {
        $LASTEXITCODE=123
        Invoke-Native 'cmd.exe' @('/d','/c','exit /b 0') | Out-Null
        Assert-True ($LASTEXITCODE -eq 123 -and $global:LASTEXITCODE -eq 0) 'Native handling must read the global exit code even when a caller has a local variable with that name.'
    }
} finally { Remove-Item -LiteralPath $nativeLog -Force }
# Missing commands are collected before remediation; no installation is attempted.
$script:AvailableTestCommands=@('Present-A','Present-B')
$script:RequestedTestCommands=New-Object 'System.Collections.Generic.List[string]'
function Get-Command {
    [CmdletBinding()]param([string]$Name)
    $script:RequestedTestCommands.Add($Name)
    if ($Name -in $script:AvailableTestCommands) { [pscustomobject]@{Name=$Name} }
}
try {
    Assert-LabCapabilities @('Present-A','Present-B','Present-A')
    Assert-True ($script:RequestedTestCommands.Count -eq 2) 'Capability checks must avoid duplicate lookups.'
    $capabilityFailure=$null
    try { Assert-LabCapabilities @('Present-A','Missing-A','Missing-B') }
    catch { $capabilityFailure=$_.Exception.Message }
    Assert-True ($capabilityFailure -like '*Missing-A*Missing-B*') 'All missing commands must be reported together.'
} finally { Remove-Item Function:\Get-Command }
$seen = @{}
for ($i=0; $i -lt 32; $i++) {
    $secure=New-LabPassword -Length 24
    $pointer=[Runtime.InteropServices.Marshal]::SecureStringToBSTR($secure)
    try {
        $plain=[Runtime.InteropServices.Marshal]::PtrToStringBSTR($pointer)
        Assert-True ($plain.Length -eq 24) 'Incorrect password length.'
        Assert-True ($plain -cmatch '[A-Z]' -and $plain -cmatch '[a-z]' -and $plain -match '[0-9]' -and $plain -match '[!@#%+_=\-]') 'Password lacks required categories.'
        Assert-True (-not $seen.ContainsKey($plain)) 'Duplicate generated password.'
        $seen[$plain]=$true
    } finally { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($pointer); $secure.Dispose(); $plain=$null }
}
Assert-Throws {New-LabPassword -Length 8}
# Exercise the actual group-removal action blocks with the native parameter type.
# Reading one existing principal is harmless; all removals below are stubbed.
Import-Module Microsoft.PowerShell.LocalAccounts
$adminGroup = Get-LocalGroup -SID S-1-5-32-544
$member = Get-LocalGroupMember -Group $adminGroup.Name | Select-Object -First 1
Assert-True ($null -ne $member) 'Need an existing administrator principal for the binding regression test.'
$group = [pscustomobject]@{Name='LabTestGroup'}
function Remove-LocalGroupMember {
    param([string]$Group,[Microsoft.PowerShell.Commands.LocalPrincipal[]]$Member)
    $script:LastRemoval = [pscustomobject]@{Group=$Group;Members=$Member}
}
try {
    foreach ($id in @('RemoveAdmin','RemovePrivilege')) {
        $script:LastRemoval = $null
        $call = $ast.Find({param($n) $n -is [System.Management.Automation.Language.CommandAst] -and $n.GetCommandName() -eq 'Invoke-LabChange' -and $n.CommandElements[1].Value -eq $id},$true)
        Assert-True ($null -ne $call) "Missing action $id"
        & ($call.CommandElements[-1].ScriptBlock.GetScriptBlock())
        $expectedGroup = if ($id -eq 'RemoveAdmin') {$adminGroup.Name} else {$group.Name}
        Assert-True ($script:LastRemoval.Group -eq $expectedGroup -and $script:LastRemoval.Members.Count -eq 1 -and [string]$script:LastRemoval.Members[0].SID -eq [string]$member.SID) "Incorrect principal binding for $id"
    }
} finally { Remove-Item Function:\Remove-LocalGroupMember }
# Protected services that already comply must not receive configuration writes.
$monitoringCall = $ast.Find({param($n) $n -is [System.Management.Automation.Language.CommandAst] -and $n.GetCommandName() -eq 'Invoke-LabChange' -and $n.CommandElements[1].Value -eq 'MonitoringService'},$true)
Assert-True ($null -ne $monitoringCall) 'Missing monitoring action.'
$monitoringAction = $monitoringCall.CommandElements[-1].ScriptBlock.GetScriptBlock()
$name = 'wscsvc'
function Get-Service { param($Name) $script:ServiceReadCalls++; $script:TestService }
function Set-Service {
    param($Name,$StartupType)
    if ($script:RejectServiceConfig) { throw 'Access is denied' }
    Assert-True ($Name -eq 'wscsvc' -and $StartupType -eq 'Automatic') 'Unexpected service configuration.'
    $script:ServiceConfigCalls++
    $script:TestService.StartType = $StartupType
}
function Start-Service {
    param($Name)
    Assert-True ($Name -eq 'wscsvc') 'Unexpected service start.'
    $script:ServiceStartCalls++
    if (-not $script:SimulateStalledService) { $script:TestService.Status = 'Running' }
}
try {
    $script:SimulateStalledService = $false
    foreach ($case in @(
        @{StartType='Automatic';Status='Running';Config=0;Start=0},
        @{StartType='Automatic';Status='Stopped';Config=0;Start=1},
        @{StartType='Manual';Status='Running';Config=1;Start=0},
        @{StartType='Disabled';Status='Stopped';Config=1;Start=1}
    )) {
        $script:TestService = [pscustomobject]$case
        $script:ServiceConfigCalls=0; $script:ServiceStartCalls=0; $script:ServiceReadCalls=0
        $script:RejectServiceConfig = $case.StartType -eq 'Automatic'
        & $monitoringAction
        Assert-True ($script:ServiceConfigCalls -eq $case.Config -and $script:ServiceStartCalls -eq $case.Start) 'Incorrect monitoring service actions.'
        Assert-True ($script:ServiceReadCalls -eq 2) 'Monitoring must verify the final service state.'
    }
    $script:TestService = [pscustomobject]@{StartType='Disabled';Status='Stopped'}
    $script:RejectServiceConfig=$true
    $script:ServiceStartCalls=0
    Assert-Throws { & $monitoringAction }
    Assert-True ($script:ServiceStartCalls -eq 0) 'Configuration denial must remain a failure.'
    $script:TestService = [pscustomobject]@{StartType='Automatic';Status='Stopped'}
    $script:SimulateStalledService = $true
    Assert-Throws { & $monitoringAction }
} finally { Remove-Item Function:\Get-Service,Function:\Set-Service,Function:\Start-Service }
# The action wrapper records failures while allowing later actions to continue.
$script:Runner = [pscustomobject]@{}
$script:Runner | Add-Member -MemberType ScriptMethod -Name ShouldProcess -Value { $script:ApproveTestChange }
$script:ApproveTestChange=$true
$script:Changes = New-Object 'System.Collections.Generic.List[object]'
$script:Warnings = New-Object 'System.Collections.Generic.List[string]'
$script:TestActionCount=0
$Mode='Apply'
Invoke-LabChange 'TestFailure' 'Stub' 'Simulate a failed action' { throw 'Simulated action failure' }
Invoke-LabChange 'TestApply' 'Stub' 'Simulate a successful action' { $script:TestActionCount++ }
$Mode='Audit'
Invoke-LabChange 'TestAudit' 'Stub' 'Plan without running an action' { $script:TestActionCount++ }
$Mode='Apply'; $script:ApproveTestChange=$false
Invoke-LabChange 'TestWhatIf' 'Stub' 'Respect a declined ShouldProcess' { $script:TestActionCount++ }
Assert-True ($script:TestActionCount -eq 1) 'Only an approved Apply action may run.'
Assert-True ($script:Changes[0].Status -eq 'Failed' -and $script:Changes[0].Detail -eq 'Simulated action failure') 'Failure details must be recorded.'
Assert-True ($script:Changes[1].Status -eq 'Applied' -and $script:Changes[2].Status -eq 'Planned' -and $script:Changes[3].Status -eq 'Planned') 'Action statuses are incorrect.'
Assert-True ($script:Warnings.Count -eq 1) 'Failed actions must produce a warning.'
# Test generated policy with harmless stubs; never invoke secedit or account cmdlets.
$script:RunPath = Join-Path ([IO.Path]::GetTempPath()) ([guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $script:RunPath | Out-Null
function Get-LocalUser { [pscustomobject]@{SID=[Security.Principal.SecurityIdentifier]::new('S-1-5-21-100-200-300-501')} }
function Invoke-Native { param($Program,$Arguments) $script:LastNative=[pscustomobject]@{Program=$Program;Arguments=$Arguments} }
try {
    'SeDenyNetworkLogonRight = *S-1-5-21-100-200-300-1234' | Set-Content (Join-Path $script:RunPath 'security-before.inf')
    Set-AccountPolicy
    $inf=Get-Content (Join-Path $script:RunPath 'security-target.inf') -Raw
    Assert-True ($inf -match 'MinimumPasswordLength = 14' -and $inf -match 'PasswordComplexity = 1') 'Password template incomplete.'
    Assert-True ($inf -match 'SeDenyNetworkLogonRight = .*\*S-1-5-21-100-200-300-1234') 'Existing deny must survive.'
    Assert-True ($inf -match 'SeCreateGlobalPrivilege = .*\*S-1-5-19,\*S-1-5-20') 'Service identities must retain global-object rights.'
    Assert-True ($script:LastNative.Program -eq 'secedit.exe' -and 'USER_RIGHTS' -in $script:LastNative.Arguments) 'User rights not included in policy application.'
} finally { Remove-Item -LiteralPath $script:RunPath -Recurse -Force }
# Exercise the actual reporting finally-block with empty and populated generic lists.
# This catches List[object] array conversion errors that parser-only checks miss.
$entrypointTry = $ast.EndBlock.Statements | Where-Object {$_ -is [System.Management.Automation.Language.TryStatementAst]} | Select-Object -Last 1
Assert-True ($null -ne $entrypointTry.Finally) 'Missing reporting finally-block.'
$body = $entrypointTry.Finally.Extent.Text
$reportBody = [scriptblock]::Create($body.Substring(1,$body.Length - 2))
$script:RunPath = Join-Path ([IO.Path]::GetTempPath()) ([guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $script:RunPath | Out-Null
$script:Changes = New-Object 'System.Collections.Generic.List[object]'
$script:Warnings = New-Object 'System.Collections.Generic.List[string]'
$script:RebootNeeded = $false
$script:ProtectedNames = @('labprimary')
$Mode = 'Audit'
try {
    & $reportBody
    $summary = Get-Content (Join-Path $script:RunPath 'summary.json') -Raw | ConvertFrom-Json
    Assert-True ($summary.Planned -eq 0 -and $summary.Failed -eq 0) 'Empty reports should serialize successfully.'
    $script:Changes.Add([pscustomobject]@{Id='Test';Target='Test';Description='Test';Status='Planned';Detail=''})
    $script:Changes.Add([pscustomobject]@{Id='TestFailure';Target='Stub';Description='Test';Status='Failed';Detail='Simulated failure'})
    $script:Changes.Add([pscustomobject]@{Id='TestApplied';Target='Stub';Description='Test';Status='Applied';Detail=''})
    $script:Warnings.Add('Test warning')
    & $reportBody
    # Windows PowerShell 5.1 emits a JSON array as one pipeline object.
    # Assign it directly instead of nesting it inside another array expression.
    $rows = ConvertFrom-Json -InputObject (Get-Content (Join-Path $script:RunPath 'changes.json') -Raw)
    $summary = Get-Content (Join-Path $script:RunPath 'summary.json') -Raw | ConvertFrom-Json
    Assert-True ($rows.Count -eq 3 -and $rows[0].Id -eq 'Test' -and $rows[1].Detail -eq 'Simulated failure') 'Populated reports must retain rows and failure details.'
    Assert-True ($summary.Planned -eq 1 -and $summary.Applied -eq 1 -and $summary.Failed -eq 1) 'Summary must count each action status accurately.'
} finally { Remove-Item -LiteralPath $script:RunPath -Recurse -Force }
# Do not permit destructive cleanup commands to creep into the entrypoint.
$commands = @($ast.FindAll({param($n) $n -is [System.Management.Automation.Language.CommandAst]},$true) | ForEach-Object {$_.GetCommandName()})
foreach ($forbidden in @('Remove-LocalUser','Remove-Item','Unregister-ScheduledTask','Restart-Computer','Stop-Computer','Clear-EventLog')) {
    Assert-True ($forbidden -notin $commands) "Unexpected destructive command $forbidden"
}
Write-Host 'PASS: script parses; config paths, profile validation, capabilities, native exits, account protections, passwords, reports and stubbed actions pass. Windows remediation was not executed.'
