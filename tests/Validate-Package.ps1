#Requires -Version 5.1
# Parses the main script and tests pure helpers. It never executes the hardening entrypoint.
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$source = Join-Path $root 'Invoke-Windows11LabHardening.ps1'
$tokens = $null; $parseErrors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile($source,[ref]$tokens,[ref]$parseErrors)
if ($parseErrors.Count) { $parseErrors | Format-List; throw 'PowerShell parser errors.' }
function Assert-True { param([bool]$Condition,[string]$Message) if (-not $Condition) { throw $Message } }
function Assert-Throws { param([scriptblock]$Code) $threw=$false; try { & $Code | Out-Null } catch {$threw=$true}; Assert-True $threw 'Expected configuration rejection.' }
foreach ($name in @('Test-LabProfile','Get-AccountDisposition','Get-CryptoIndex','New-LabPassword','New-RegistryPlan','Set-AccountPolicy')) {
    $definition = $ast.Find({param($node) $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq $name},$true)
    Assert-True ($null -ne $definition) "Missing helper $name"
    . ([scriptblock]::Create($definition.Extent.Text))
}
$profile = Get-Content (Join-Path $root 'lab.config.json') -Raw | ConvertFrom-Json
Test-LabProfile $profile
$script:Profile = $profile
$plan = @(New-RegistryPlan)
Assert-True ($plan.Count -ge 30) 'Registry plan unexpectedly empty.'
foreach ($item in $plan) { Assert-True ($item.Path -like 'HKLM:\*' -and $item.Name -and $item.Type -in @('DWord','String')) 'Invalid registry plan item.' }
Assert-True (@($plan | Where-Object {$_.Name -eq 'EnableLUA' -and $_.Value -eq 1}).Count -eq 1) 'UAC must be enabled.'
Assert-True (@($plan | Where-Object {$_.Name -match 'Javascript|JavaScript'}).Count -eq 0) 'JavaScript must remain unchanged.'
Assert-True ($profile.Administrators.Count -eq 5) 'Expected five authorized administrators.'
Assert-True ($profile.Users.Count -eq 13) 'Expected 12 original users plus tchalla.'
Assert-True ('tchalla' -in $profile.Users -and 'tchalla' -in $profile.CreateUsers) 'New employee missing.'
Assert-True ($profile.PrimaryAccount -eq 'pparker') 'Primary account changed.'
Assert-True ('Wireshark*' -in $profile.ProtectedApplicationPatterns -and 'Npcap*' -in $profile.ProtectedApplicationPatterns) 'Required software must be protected.'
$sidPrefix='S-1-5-21-100-200-300'
Assert-True ((Get-AccountDisposition 'pparker' "$sidPrefix-1000" $profile @('pparker')) -eq 'Protected') 'Primary must be protected.'
Assert-True ((Get-AccountDisposition 'session-admin' "$sidPrefix-1099" $profile @('session-admin')) -eq 'Protected') 'Executing account must be protected.'
Assert-True ((Get-AccountDisposition 'attacker' "$sidPrefix-1099" $profile @('pparker')) -eq 'DisableUnauthorized') 'Unknown human account must be disabled.'
Assert-True ((Get-AccountDisposition 'bbanner' "$sidPrefix-1001" $profile @('pparker')) -eq 'StandardUser') 'Standard user misclassified.'
Assert-True ((Get-AccountDisposition 'nfury' "$sidPrefix-1002" $profile @('pparker')) -eq 'Administrator') 'Administrator misclassified.'
Assert-True ((Get-AccountDisposition 'Guest' "$sidPrefix-501" $profile @('pparker')) -eq 'DisableGuest') 'Guest should be disabled.'
Assert-True ((Get-AccountDisposition 'DefaultAccount' "$sidPrefix-503" $profile @('pparker')) -eq 'PreserveBuiltin') 'System account must not be treated as an employee.'
$bad = Get-Content (Join-Path $root 'lab.config.json') -Raw | ConvertFrom-Json
$bad.Administrators=@('nfury'); Assert-Throws {Test-LabProfile $bad}
$bad = Get-Content (Join-Path $root 'lab.config.json') -Raw | ConvertFrom-Json
$bad.Users += 'pparker'; Assert-Throws {Test-LabProfile $bad}
$bad = Get-Content (Join-Path $root 'lab.config.json') -Raw | ConvertFrom-Json
$bad.DisableServiceNames += 'EventLog'; Assert-Throws {Test-LabProfile $bad}
$bad = Get-Content (Join-Path $root 'lab.config.json') -Raw | ConvertFrom-Json
$bad.DisableServiceNames += 'CCSClient'; Assert-Throws {Test-LabProfile $bad}
$bad = Get-Content (Join-Path $root 'lab.config.json') -Raw | ConvertFrom-Json
$bad.PasswordPolicy.LockoutMinutes=10; Assert-Throws {Test-LabProfile $bad}
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
# Do not permit destructive cleanup commands to creep into the entrypoint.
$commands = @($ast.FindAll({param($n) $n -is [System.Management.Automation.Language.CommandAst]},$true) | ForEach-Object {$_.GetCommandName()})
foreach ($forbidden in @('Remove-LocalUser','Remove-Item','Unregister-ScheduledTask','Restart-Computer','Stop-Computer','Clear-EventLog')) {
    Assert-True ($forbidden -notin $commands) "Unexpected destructive command $forbidden"
}
Write-Host 'PASS: script parses; profile, account protections and password helpers pass. Windows remediation was not executed.'
