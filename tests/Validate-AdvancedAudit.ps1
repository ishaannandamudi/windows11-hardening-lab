#Requires -Version 5.1
# Harmless test fixtures only. The hardening entrypoint is never run.
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$modulePath = Join-Path $root 'modules\Lab.AdvancedAudit.psm1'
function Assert-True { param([bool]$Condition,[string]$Message) if (-not $Condition) { throw $Message } }
$tokens=$null; $errors=$null
$ast = [System.Management.Automation.Language.Parser]::ParseFile($modulePath,[ref]$tokens,[ref]$errors)
Assert-True ($errors.Count -eq 0) 'Advanced audit module must parse in Windows PowerShell 5.1.'
# Load only function definitions so internal helpers can be exercised in this scope.
foreach ($definition in $ast.FindAll({param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst]},$true)) {
    . ([scriptblock]::Create($definition.Extent.Text))
}
$commandNames = @($ast.FindAll({param($n) $n -is [System.Management.Automation.Language.CommandAst]},$true) | ForEach-Object {$_.GetCommandName()})
foreach ($forbidden in @('Set-ItemProperty','New-ItemProperty','Remove-Item','New-Item','Set-MpPreference','Start-BitsTransfer','Resume-BitsTransfer','Complete-BitsTransfer','Remove-BitsTransfer','Invoke-CimMethod','Invoke-Expression','Start-Process','Set-Service','Stop-Service','Restart-Computer')) {
    Assert-True ($forbidden -notin $commandNames) "Advanced inspection must not contain $forbidden."
}
# Exercise actual RegistryKey methods against one disposable, non-policy HKCU key.
$fixture = 'HKCU:\Software\Windows11LabAuditTest-' + [guid]::NewGuid().ToString('N')
New-Item -Path $fixture | Out-Null
try {
    New-ItemProperty -LiteralPath $fixture -Name 'Enabled' -PropertyType DWord -Value 1 | Out-Null
    New-ItemProperty -LiteralPath $fixture -Name 'Literal[Value]' -PropertyType ExpandString -Value '%SystemRoot%\example.exe' | Out-Null
    New-ItemProperty -LiteralPath $fixture -Name 'DefaultPassword' -PropertyType String -Value 'fixture-secret-not-for-reports' | Out-Null
    $actual = Get-LabAuditValue $fixture Enabled
    $target = [pscustomobject]@{Type='DWord';Value=1}
    Assert-True ($actual.Status -eq 'Present' -and $actual.Value -eq 1 -and $actual.Type -eq 'DWord') 'Registry values and types must be read accurately.'
    Assert-True ((Compare-LabAuditRegistryTarget $actual $target) -eq 'MatchesExplicitTarget') 'Matching values must be distinguished from planned changes.'
    $target.Value=0
    Assert-True ((Compare-LabAuditRegistryTarget $actual $target) -eq 'DiffersFromTarget') 'A mismatched value must be reported.'
    $target.Value=1; $target.Type='String'
    Assert-True ((Compare-LabAuditRegistryTarget $actual $target) -eq 'DiffersFromTarget') 'Wrong registry types must not appear to match.'
    $missing = Get-LabAuditValue $fixture MissingValue
    Assert-True ((Compare-LabAuditRegistryTarget $missing $target) -eq 'NotExplicitlySet') 'Absent values must not be automatically classified as insecure.'
    Assert-True ((Get-LabAuditValue "$fixture\MissingKey" Enabled).Status -eq 'Missing') 'Missing keys must be handled without a false collection failure.'
    $literal = Get-LabAuditValue $fixture 'Literal[Value]'
    Assert-True ($literal.Value -ceq '%SystemRoot%\example.exe') 'Registry strings must be read literally without environment expansion.'
    $rows = @(Get-LabAuditRegistryRows $fixture -Names @('Enabled','Literal[Value]'))
    Assert-True ($rows.Count -eq 2 -and 'DefaultPassword' -notin $rows.Name) 'Whitelist reads must not export unrelated values.'
    New-Item -Path "$fixture\tool.exe\filter" -Force | Out-Null
    New-ItemProperty -LiteralPath "$fixture\tool.exe" -Name Debugger -Value 'DO-NOT-EXECUTE.exe' -PropertyType String | Out-Null
    New-ItemProperty -LiteralPath "$fixture\tool.exe\filter" -Name FilterFullPath -Value 'C:\example.exe' -PropertyType String | Out-Null
    $rows = @(Get-LabAuditRegistryRows $fixture -Children -Grandchildren -Names @('Debugger','FilterFullPath'))
    Assert-True ($rows.Count -eq 2) 'IFEO filter subkeys must be included without recursive filesystem scanning.'
} finally { Remove-Item -LiteralPath $fixture -Recurse -Force }

$state = @{Evidence=[ordered]@{};Findings=(New-Object 'System.Collections.Generic.List[object]')}
Invoke-LabAuditSection $state Empty { } 'Known empty scope'
Invoke-LabAuditSection $state Denied { throw 'Simulated access denied' }
Invoke-LabAuditSection $state Later { [pscustomobject]@{Value=42} }
Assert-True ($state.Evidence.Empty.Status -eq 'Complete' -and $state.Evidence.Empty.Rows.Count -eq 0) 'A successfully empty check must remain distinct from a failed check.'
Assert-True ($state.Evidence.Denied.Status -eq 'Unknown' -and $state.Findings[0].Status -eq 'Unknown') 'Denied checks must be Unknown and visible in the review.'
Assert-True ($state.Evidence.Later.Rows[0].Value -eq 42) 'A failed optional collector must not prevent later checks.'

# End-to-end report generation with synthetic reads. Never read WMI/BITS/network state.
function Get-LabAuditValue {
    param([string]$Path,[string]$Name)
    if ($Name -eq 'AlwaysInstallElevated') { return [pscustomobject]@{Path=$Path;Name=$Name;Status='Present';Value=1;Type='DWord'} }
    [pscustomobject]@{Path=$Path;Name=$Name;Status='Missing';Value=$null;Type=$null}
}
function Get-LabAuditRegistryRows {
    param([string]$Path,[string[]]$Names=@(),[switch]$Children,[switch]$Grandchildren)
    if ($Path -like '*Image File Execution Options' -and $Children) {
        [pscustomobject]@{Path="$Path\fixture.exe";Name='Debugger';Status='Present';Value='DO-NOT-EXECUTE.exe';Type='String'}
    }
}
function Get-ChildItem {
    [CmdletBinding()]param([string]$LiteralPath)
    if ($script:FailUserEnumeration) { throw 'Simulated user-hive access denied' }
    [pscustomobject]@{PSPath='Registry::HKEY_USERS\S-1-5-21-100-200-300-1001';PSChildName='S-1-5-21-100-200-300-1001'}
}
$script:WmiCalls = New-Object 'System.Collections.Generic.List[string]'
function Get-CimInstance {
    [CmdletBinding()]param([string]$Namespace,[string]$ClassName,[int]$OperationTimeoutSec)
    Assert-True ($Namespace -eq 'root/subscription' -and $OperationTimeoutSec -eq 10) 'Only local subscription queries with an explicit timeout are allowed.'
    $script:WmiCalls.Add($ClassName)
    if ($ClassName -eq 'CommandLineEventConsumer') { [pscustomobject]@{Name='SyntheticConsumer';ExecutablePath='DO-NOT-EXECUTE.exe';CommandLineTemplate='synthetic';WorkingDirectory='C:\Temp'} }
    elseif ($ClassName -eq 'ActiveScriptEventConsumer') { throw 'Simulated WMI class unavailable' }
}
function Get-BitsTransfer { [CmdletBinding()]param([switch]$AllUsers) Assert-True ([bool]$AllUsers) 'BITS inspection must include existing jobs for all users.' }
function Get-DnsClientServerAddress { [CmdletBinding()]param() [pscustomobject]@{InterfaceAlias='Synthetic';InterfaceIndex=1;AddressFamily=2;ServerAddresses=@('192.0.2.1')} }
function Get-MpComputerStatus { [CmdletBinding()]param() [pscustomobject]@{AntivirusEnabled=$false;RealTimeProtectionEnabled=$false;AMRunningMode='Passive'} }
function Get-MpPreference { [CmdletBinding()]param() [pscustomobject]@{MAPSReporting=0;SubmitSamplesConsent=2;DisableBlockAtFirstSeen=$true} }
function Invoke-LabAuditNativeRead { param([string]$Query) [pscustomobject]@{Query=$Query;Output='Synthetic read-only output'} }
$temp = Join-Path ([IO.Path]::GetTempPath()) ([guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $temp | Out-Null
# Redirect only the hosts read; leave process environment and real system files alone.
function Get-Content {
    [CmdletBinding()]param([string]$LiteralPath,[switch]$Raw)
    if ($LiteralPath -eq (Join-Path $env:SystemRoot 'System32\drivers\etc\hosts')) { return '127.0.0.1 localhost # fixture comment' }
    Microsoft.PowerShell.Management\Get-Content @PSBoundParameters
}
try {
    $script:FailUserEnumeration=$false
    Invoke-LabAdvancedAudit -OutputDirectory $temp -RegistryPlan @([pscustomobject]@{Path='HKLM:\Synthetic';Name='Missing';Type='DWord';Value=1})
    $evidence = ConvertFrom-Json -InputObject (Get-Content -LiteralPath (Join-Path $temp 'advanced-evidence.json') -Raw)
    $findings = ConvertFrom-Json -InputObject (Get-Content -LiteralPath (Join-Path $temp 'advanced-findings.json') -Raw)
    Assert-True ($evidence.RegistryTargets.Rows[0].Status -eq 'NotExplicitlySet') 'Missing default-aware comparisons must survive JSON serialization.'
    Assert-True ($evidence.WmiScriptConsumers.Status -eq 'Unknown' -and $evidence.DnsServers.Status -eq 'Complete') 'Reports must preserve failures and subsequent successful evidence.'
    Assert-True ($script:WmiCalls.Count -eq 4) 'All four WMI component collections must run.'
    Assert-True (@($findings | Where-Object {$_.Area -eq 'ImageExecutionHooks' -and $_.Status -eq 'NeedsReview'}).Count -eq 2) 'Both registry views must produce evidence without running hook commands.'
    Assert-True (@($findings | Where-Object Area -eq 'DefenderStatus').Count -eq 1) 'Inactive protection must be highlighted instead of trusting preference writes.'
    Assert-True ($evidence.HostsEntries.Rows[0] -eq '127.0.0.1 localhost') 'Hosts comments must be stripped without changing the hosts file.'
    Assert-True ((Get-Content -LiteralPath (Join-Path $temp 'advanced-review.txt') -Raw) -like '*not confirmed malware*') 'Human-readable review must explain uncertainty.'
    $script:FailUserEnumeration=$true
    Invoke-LabAdvancedAudit -OutputDirectory $temp
    $evidence = ConvertFrom-Json -InputObject (Get-Content -LiteralPath (Join-Path $temp 'advanced-evidence.json') -Raw)
    Assert-True ($evidence.LoadedUserScopes.Status -eq 'Unknown' -and $evidence.UserPoliciesAndProxy.Status -eq 'Unknown' -and $evidence.LogonAndDllHooks.Status -eq 'Unknown') 'Failed user enumeration must not make dependent checks look complete.'
} finally {
    Remove-Item Function:\Get-ChildItem,Function:\Get-Content
    Remove-Item -LiteralPath $temp -Recurse -Force
}
# Also verify the real module boundary: import defines functions only, no collections.
$module = Import-Module $modulePath -Force -PassThru
Assert-True ($module.ExportedFunctions.Keys.Count -eq 1 -and 'Invoke-LabAdvancedAudit' -in $module.ExportedFunctions.Keys) 'Only the public audit entrypoint should be exported.'
Remove-Module $module.Name
Write-Host 'PASS: read-only audit parsing, registry reads, comparison semantics, failure isolation, synthetic collection/reporting and module exports. No Windows remediation executed.'
