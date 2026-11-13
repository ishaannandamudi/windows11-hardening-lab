#Requires -Version 5.1
# Tests the required-RDP scenario with synthetic identities and harmless stubs.
# Never executes the hardening entrypoint or changes real services/groups/firewall.
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
$root=Split-Path -Parent $PSScriptRoot
$tokens=$null; $errors=$null
$ast=[System.Management.Automation.Language.Parser]::ParseFile((Join-Path $root 'Invoke-Windows11LabHardening.ps1'),[ref]$tokens,[ref]$errors)
if ($errors.Count) { $errors | Format-List; throw 'Script parser errors.' }
function Assert-True { param([bool]$Condition,[string]$Message) if (-not $Condition) { throw $Message } }
function Assert-Throws { param([scriptblock]$Read,[string]$Message) $failed=$false; try { & $Read | Out-Null } catch { $failed=$true }; Assert-True $failed $Message }
foreach ($name in @('Assert-ProfileProperties','Assert-ProfileInteger','Test-LabProfile','New-RegistryPlan','Get-LabRdpSidClosure','Get-LabDenyPrincipals','Get-LabRestrictedGroups','Get-LabDisabledFirewallPatterns','Set-LabRdpMembership','Set-LabRdpServices','Set-LabRdpFirewall','Save-LabRdpState','Set-AccountPolicy','Save-Json','Write-LabWarning')) {
    $definition=$ast.Find({param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq $name},$true)
    Assert-True ($null -ne $definition) "Missing helper $name"
    . ([scriptblock]::Create($definition.Extent.Text))
}
$profile=Get-Content (Join-Path $root 'lab.config.json') -Raw | ConvertFrom-Json
Test-LabProfile $profile
function New-Fixture {
    $p=Get-Content (Join-Path $root 'lab.config.json') -Raw | ConvertFrom-Json
    $p.PrimaryAccount='labadmin'; $p.Administrators=@('labadmin'); $p.Users=@('labuser')
    $p.CreateUsers=@(); $p.ResetPasswordAccounts=@(); $p.EnableRemoteDesktop=$true
    $p.RequiredServiceNames=@('TermService','SessionEnv','UmRdpService')
    $p.DisableServiceNames=@('RemoteRegistry','WinRM')
    return $p
}
$script:Profile=New-Fixture
Test-LabProfile $script:Profile
foreach ($mutate in @(
    {param($p) $p.RequiredServiceNames=@()},
    {param($p) $p.DisableServiceNames+= 'TermService'},
    {param($p) $p.DisableServiceNames+= 'SessionEnv'},
    {param($p) $p.DisableServiceNames+= 'UmRdpService'},
    {param($p) $p.RequiredServiceNames+= 'WinRM'},
    {param($p) $p.EnableRemoteDesktop=$false}
)) { $bad=New-Fixture; & $mutate $bad; Assert-Throws {Test-LabProfile $bad} 'RDP/service conflicts must be rejected.' }
$plan=@(New-RegistryPlan)
Assert-True (@($plan | Where-Object {$_.Name -eq 'fDenyTSConnections' -and $_.Value -eq 0}).Count -eq 2) 'Both RDP configuration and policy must allow connections.'
foreach ($pair in @(@('UserAuthentication',1),@('SecurityLayer',2),@('MinEncryptionLevel',3))) {
    Assert-True (@($plan | Where-Object {$_.Name -eq $pair[0] -and $_.Value -eq $pair[1]}).Count -eq 2) 'NLA, TLS and encryption must be set in both scopes.'
}
Assert-True ('S-1-5-32-555' -notin @(Get-LabRestrictedGroups)) 'Required RDP group must not be emptied by privilege cleanup.'
Assert-True ('RemoteDesktop*' -notin @(Get-LabDisabledFirewallPatterns)) 'Required RDP rules must not enter the disable pass.'
$script:Profile.EnableRemoteDesktop=$false
Assert-True ('S-1-5-32-555' -in @(Get-LabRestrictedGroups) -and 'RemoteDesktop*' -in @(Get-LabDisabledFirewallPatterns)) 'Non-RDP scenarios must retain their original restrictions.'
Assert-True (@(New-RegistryPlan | Where-Object {$_.Name -eq 'fDenyTSConnections' -and $_.Value -eq 1}).Count -eq 2) 'Non-RDP scenarios must deny RDP in both scopes.'
$script:Profile=New-Fixture
$adminSid='S-1-5-21-100-200-300-1000'; $userSid='S-1-5-21-100-200-300-1001'; $outsiderSid='S-1-5-21-100-200-300-1099'
$guest=@('*S-1-5-32-546','*S-1-5-21-100-200-300-501')
$closure=@(Get-LabRdpSidClosure @($adminSid,$userSid) @(
    [pscustomobject]@{GroupSid='S-1-5-32-777';MemberSid='S-1-5-32-778'},
    [pscustomobject]@{GroupSid='S-1-5-32-778';MemberSid=$userSid}
))
Assert-True ('S-1-5-32-777' -in $closure -and 'S-1-5-32-778' -in $closure) 'Nested group denials must be detected regardless of enumeration order.'
$denied=@(Get-LabDenyPrincipals @("*$userSid",'*S-1-5-113','*S-1-5-114','*S-1-5-32-777',"*$outsiderSid") $guest $closure)
Assert-True ($denied.Count -eq 3 -and "*$outsiderSid" -in $denied -and $guest[0] -in $denied -and $guest[1] -in $denied) 'Remove only conflicting RDP denials; retain Guests and unrelated denied accounts.'
$unchanged=@(Get-LabDenyPrincipals @("*$userSid") $guest)
Assert-True ("*$userSid" -in $unchanged) 'Without required RDP, existing denials must survive.'

$script:Members=New-Object 'System.Collections.Generic.List[object]'
$script:Members.Add([pscustomobject]@{Name='LAB\labuser';SID=$userSid})
$script:Members.Add([pscustomobject]@{Name='LAB\outsider';SID=$outsiderSid})
$script:Removed=New-Object 'System.Collections.Generic.List[object]'
function Get-LocalGroup { [CmdletBinding()]param([string]$SID) [pscustomobject]@{Name='Localized RDP group';SID='S-1-5-32-555'} }
function Get-LocalUser {
    [CmdletBinding()]param([string]$Name)
    if (-not $Name) { return [pscustomobject]@{Name='Guest';SID=[Security.Principal.SecurityIdentifier]::new('S-1-5-21-100-200-300-501')} }
    $sid=if ($Name -eq 'labadmin') {$adminSid} else {$userSid}
    [pscustomobject]@{Name=$Name;SID=$sid}
}
function Get-LocalGroupMember { [CmdletBinding()]param([string]$Group) $script:Members.ToArray() }
function Remove-LocalGroupMember {
    param([string]$Group,$Member)
    Assert-True ($Member -is [System.Management.Automation.PSCustomObject]) 'Member must be the principal object, not a raw SID.'
    $script:Removed.Add($Member)
    [void]$script:Members.Remove($Member)
}
function Add-LocalGroupMember { param([string]$Group,$Member) $script:Members.Add($Member) }
Set-LabRdpMembership
Assert-True ($script:Removed.Count -eq 1 -and $script:Removed[0].SID -eq $outsiderSid) 'RDP membership cleanup must remove only unauthorized principals.'
Assert-True ($script:Members.Count -eq 1 -and $script:Members[0].SID -eq $userSid) 'Existing employee RDP membership must be retained without duplicates.'
$script:Members.Clear()
Set-LabRdpMembership
Assert-True ($script:Members.Count -eq 1 -and $script:Members[0].SID -eq $userSid) 'Standard employees must gain RDP membership; administrators use their own group.'

$script:ServiceChanges=New-Object 'System.Collections.Generic.List[string]'
$script:ServiceStarts=New-Object 'System.Collections.Generic.List[string]'
$script:Services=@{
    TermService=[pscustomobject]@{StartType='Automatic';Status='Running'}
    SessionEnv=[pscustomobject]@{StartType='Manual';Status='Stopped'}
    UmRdpService=[pscustomobject]@{StartType='Disabled';Status='Stopped'}
}
function Get-Service { param([string]$Name) $script:Services[$Name] }
function Set-Service { param([string]$Name,[string]$StartupType) $script:ServiceChanges.Add("${Name}:$StartupType"); $script:Services[$Name].StartType=$StartupType }
function Start-Service { param([string]$Name) $script:ServiceStarts.Add($Name); $script:Services[$Name].Status='Running' }
Set-LabRdpServices
Assert-True ($script:ServiceChanges.Count -eq 1 -and $script:ServiceChanges[0] -eq 'UmRdpService:Manual' -and $script:ServiceStarts.Count -eq 0) 'Do not restart an already-running RDP service or force-start manual support services.'
$script:Services.TermService.StartType='Disabled'; $script:Services.TermService.Status='Stopped'
Set-LabRdpServices
Assert-True ($script:Services.TermService.StartType -eq 'Automatic' -and $script:ServiceStarts.Count -eq 1) 'Disabled RDP must be restored to Running/Automatic.'

$script:FirewallWrites=New-Object 'System.Collections.Generic.List[object]'
$script:RejectFirewall=$false
function Get-ItemProperty { [CmdletBinding()]param([string]$LiteralPath,[string]$Name) [pscustomobject]@{PortNumber=3391} }
function Get-NetFirewallRule {
    [CmdletBinding()]param([string]$Name,[string]$PolicyStore)
    [pscustomobject]@{Name=$Name;Enabled=$(if ($script:RejectFirewall) {'False'} else {'True'});Action='Allow';Direction='Inbound';Profile='Domain, Private'}
}
function Set-NetFirewallRule {
    param([string]$Name,[string]$Enabled,[string]$Action,[string]$Direction,[string]$Protocol,[int]$LocalPort)
    $script:FirewallWrites.Add([pscustomobject]@{Name=$Name;Port=$LocalPort;Protocol=$Protocol})
}
Set-LabRdpFirewall
Assert-True ($script:FirewallWrites.Count -eq 2 -and @($script:FirewallWrites | Where-Object Port -eq 3391).Count -eq 2) 'Only exact TCP/UDP built-in rules should be updated using the existing custom port.'
Assert-True ($script:FirewallWrites[0].Name -eq 'RemoteDesktop-UserMode-In-TCP' -and $script:FirewallWrites[1].Name -eq 'RemoteDesktop-UserMode-In-UDP') 'Do not open unrelated remote management rules.'
$script:RejectFirewall=$true
Assert-Throws {Set-LabRdpFirewall} 'Ineffective RDP firewall writes must fail readback.'

$script:RunPath=Join-Path ([IO.Path]::GetTempPath()) ([guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $script:RunPath | Out-Null
function Invoke-Native { param($Program,$Arguments) $script:NativeArguments=$Arguments }
try {
    @(
        "SeDenyRemoteInteractiveLogonRight = *$userSid,*S-1-5-113,*$outsiderSid",
        "SeDenyNetworkLogonRight = *S-1-5-32-545,*$outsiderSid",
        "SeDenyInteractiveLogonRight = *$outsiderSid"
    ) | Set-Content (Join-Path $script:RunPath 'security-before.inf')
    Set-AccountPolicy
    $inf=Get-Content (Join-Path $script:RunPath 'security-target.inf') -Raw
    $remoteLine=($inf -split '\r?\n' | Where-Object {$_ -match '^SeDenyRemoteInteractiveLogonRight ='})
    Assert-True ($inf -match 'SeRemoteInteractiveLogonRight = \*S-1-5-32-544,\*S-1-5-32-555') 'RDP allow rights must include Administrators and Remote Desktop Users.'
    Assert-True ($remoteLine -notlike "*$userSid*" -and $remoteLine -notlike '*S-1-5-113*' -and $remoteLine -like "*$outsiderSid*") 'Generated policy must remove conflicting denies without dropping unrelated denies.'
    $adjustments=Get-Content (Join-Path $script:RunPath 'rdp-deny-adjustments.json') -Raw | ConvertFrom-Json
    Assert-True ($adjustments.Count -eq 3) 'Each conflicting deny removed from the policy must have an audit record.'
} finally { Remove-Item -LiteralPath $script:RunPath -Recurse -Force }

# Installer flags must respect the new README and remain exact-ID upgrade only.
$updateCommand=$ast.Find({param($n) $n -is [System.Management.Automation.Language.CommandAst] -and $n.GetCommandName() -eq 'Invoke-Native' -and $n.Extent.Text -like "*'winget.exe'*"},$true)
Assert-True ($null -ne $updateCommand) 'Missing WinGet upgrade command.'
$text=$updateCommand.Extent.Text
Assert-True ($text.Contains("'upgrade'") -and $text.Contains("'--interactive'") -and $text.Contains("'--architecture','x64'")) 'Updates must use interactive x64 exact-package upgrades.'
foreach ($forbidden in @("'--silent'","'--allow-reboot'","'--all'","'--force'")) { Assert-True (-not $text.Contains($forbidden)) "Unexpected updater flag $forbidden" }
Write-Host 'PASS: RDP and non-RDP validation, NLA/TLS plans, memberships, deny-right conflicts, service preservation, firewall readback and interactive update flags. No Windows remediation executed.'
