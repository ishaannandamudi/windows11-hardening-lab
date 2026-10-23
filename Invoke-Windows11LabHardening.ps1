#Requires -Version 5.1
#Requires -RunAsAdministrator
<#
.SYNOPSIS
Audits or hardens a standalone Windows 11 personal lab using an explicit profile.
.DESCRIPTION
Default mode is Audit. Apply requires -Mode Apply. No automatic reboot, file
deletion, application uninstall, task deletion, feature upgrade, or scoring changes.
Use 64-bit Windows PowerShell 5.1 at the VM console. Take a VM snapshot first.
#>
[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
param(
    [ValidateSet('Audit', 'Apply')][string]$Mode = 'Audit',
    [string]$ConfigPath = (Join-Path $PSScriptRoot 'lab.config.json'),
    [switch]$RotatePasswords,
    [switch]$ScanFiles,
    [switch]$UpdateApps,
    [switch]$InstallSecurityUpdates,
    [switch]$UpdateDefender,
    [switch]$QuickScan
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$script:Runner = $PSCmdlet
$script:Changes = New-Object 'System.Collections.Generic.List[object]'
$script:Warnings = New-Object 'System.Collections.Generic.List[string]'
$script:RebootNeeded = $false
$script:CreatedNow = New-Object 'System.Collections.Generic.List[string]'

function Test-LabProfile {
    param($Profile)
    if ($Profile.SchemaVersion -ne 1) { throw 'Unsupported profile schema.' }
    $all = @($Profile.Administrators) + @($Profile.Users)
    if (@($Profile.Administrators).Count -eq 0 -or $Profile.PrimaryAccount -notin $Profile.Administrators) {
        throw 'PrimaryAccount must be an authorized administrator.'
    }
    if (@($all | Sort-Object -Unique).Count -ne $all.Count) { throw 'Account names overlap or repeat.' }
    foreach ($name in $all) {
        if ($name -notmatch '^[A-Za-z0-9][A-Za-z0-9_.-]{0,19}$') { throw "Invalid local account name: $name" }
    }
    foreach ($name in @($Profile.CreateUsers) + @($Profile.ResetPasswordAccounts)) {
        if ($name -notin $all) { throw "Account is not authorized: $name" }
    }
    $p = $Profile.PasswordPolicy
    if ($p.MinimumLength -ne 14 -or $p.GeneratedLength -lt $p.MinimumLength -or $p.GeneratedLength -gt 128) {
        throw 'This portable local-policy profile requires MinimumLength 14 and generated passwords of 14-128 characters.'
    }
    if ($p.History -lt 1 -or $p.History -gt 24 -or $p.MinimumAgeDays -lt 0 -or $p.MaximumAgeDays -gt 999 -or $p.MaximumAgeDays -le $p.MinimumAgeDays) {
        throw 'Invalid password history or expiration interval.'
    }
    if ($p.LockoutThreshold -lt 1 -or $p.LockoutThreshold -gt 999 -or $p.ResetCounterMinutes -lt 1 -or $p.LockoutMinutes -lt $p.ResetCounterMinutes) {
        throw 'Invalid account lockout policy.'
    }
    $essential = @('RpcSs','DcomLaunch','SamSs','LSM','EventLog','WinDefend','WdNisSvc','mpssvc','BFE','wuauserv','BITS','CryptSvc','Dhcp','Dnscache','Winmgmt','wscsvc','SecurityHealthService')
    foreach ($name in $Profile.DisableServiceNames) {
        if ($name -in $essential -or $name -match '(?i)ccs|cyberpatriot|vmtools|vbox') { throw "Protected service in disable list: $name" }
        if ($name -notmatch '^[A-Za-z0-9_.-]+$') { throw 'Service disable entries must be simple exact names, not patterns.' }
    }
}

function Get-AccountDisposition {
    param([string]$Name, [string]$Sid, $Profile, [string[]]$ProtectedNames)
    if ($Name -in $ProtectedNames) { return 'Protected' }
    $rid = [int64]($Sid.Split('-')[-1])
    if ($rid -eq 501) { return 'DisableGuest' }
    if ($rid -eq 500) { return 'DisableBuiltinAdministrator' }
    if ($rid -lt 1000) { return 'PreserveBuiltin' }
    if ($Name -in $Profile.Administrators) { return 'Administrator' }
    if ($Name -in $Profile.Users) { return 'StandardUser' }
    return 'DisableUnauthorized'
}

function Get-CryptoIndex {
    param([Security.Cryptography.RandomNumberGenerator]$Rng, [int]$Limit)
    $bytes = New-Object byte[] 4
    $range = [uint64][uint32]::MaxValue + 1
    $ceiling = $range - ($range % [uint64]$Limit)
    do { $Rng.GetBytes($bytes); $n = [uint64][BitConverter]::ToUInt32($bytes, 0) } while ($n -ge $ceiling)
    return [int]($n % [uint64]$Limit)
}

function New-LabPassword {
    param([int]$Length = 24)
    if ($Length -lt 14 -or $Length -gt 128) { throw 'Password length must be 14-128.' }
    $sets = @('ABCDEFGHJKLMNPQRSTUVWXYZ','abcdefghijkmnopqrstuvwxyz','23456789','!@#%+-_=')
    $alphabet = $sets -join ''
    $chars = New-Object char[] $Length
    $rng = [Security.Cryptography.RandomNumberGenerator]::Create()
    try {
        for ($i = 0; $i -lt $sets.Count; $i++) { $chars[$i] = $sets[$i][(Get-CryptoIndex $rng $sets[$i].Length)] }
        for ($i = $sets.Count; $i -lt $Length; $i++) { $chars[$i] = $alphabet[(Get-CryptoIndex $rng $alphabet.Length)] }
        for ($i = $Length - 1; $i -gt 0; $i--) {
            $j = Get-CryptoIndex $rng ($i + 1)
            $tmp = $chars[$i]; $chars[$i] = $chars[$j]; $chars[$j] = $tmp
        }
        $secure = New-Object Security.SecureString
        foreach ($char in $chars) { $secure.AppendChar($char) }
        $secure.MakeReadOnly()
        return $secure
    } finally { [Array]::Clear($chars, 0, $chars.Length); $rng.Dispose() }
}

function Write-LabWarning {
    param([string]$Message)
    $script:Warnings.Add($Message)
    Write-Warning $Message
}

function Save-Json {
    param([string]$Name, $Value)
    ConvertTo-Json -InputObject $Value -Depth 12 | Set-Content -LiteralPath (Join-Path $script:RunPath $Name) -Encoding UTF8
}

function Invoke-Native {
    param([string]$Program, [string[]]$Arguments)
    $output = & $Program @Arguments 2>&1
    $exitCode = $LASTEXITCODE
    if ($exitCode -ne 0) { throw "$Program failed ($exitCode): $($output -join ' ')" }
    return $output
}

function Invoke-LabChange {
    param([string]$Id, [string]$Target, [string]$Description, [scriptblock]$Action)
    $status = 'Planned'; $detail = ''
    if ($Mode -eq 'Apply' -and $script:Runner.ShouldProcess($Target, $Description)) {
        try { & $Action | Out-Null; $status = 'Applied' }
        catch { $status = 'Failed'; $detail = $_.Exception.Message; Write-LabWarning "$Id failed: $detail" }
    }
    $script:Changes.Add([pscustomobject]@{Id=$Id; Target=$Target; Description=$Description; Status=$status; Detail=$detail})
    Write-Host "[$status] $Description : $Target"
}

function Save-Inventory {
    param([string]$Prefix)
    $collectors = [ordered]@{
        users = { Get-LocalUser | Select-Object Name,Enabled,SID,PrincipalSource,PasswordRequired,PasswordExpires,PasswordLastSet,UserMayChangePassword,LastLogon }
        groups = { foreach ($g in Get-LocalGroup) { try { foreach ($m in Get-LocalGroupMember -Group $g.Name) { [pscustomobject]@{Group=$g.Name; Member=$m.Name; SID=[string]$m.SID; ObjectClass=$m.ObjectClass} } } catch { Write-LabWarning "Cannot read group $($g.Name): $($_.Exception.Message)" } } }
        services = { Get-CimInstance Win32_Service | Select-Object Name,DisplayName,State,StartMode,StartName,PathName }
        tasks = { Get-ScheduledTask | Select-Object TaskName,TaskPath,State,Author,@{n='User';e={$_.Principal.UserId}},@{n='Actions';e={@($_.Actions | Select-Object Execute,Arguments,WorkingDirectory)}} }
        startup = { Get-CimInstance Win32_StartupCommand | Select-Object Name,Command,Location,User }
        listeners = { Get-NetTCPConnection -State Listen | Select-Object LocalAddress,LocalPort,OwningProcess }
        udp = { Get-NetUDPEndpoint | Select-Object LocalAddress,LocalPort,OwningProcess }
        processes = { Get-CimInstance Win32_Process | Select-Object Name,ProcessId,ParentProcessId,ExecutablePath }
        shares = { Get-SmbShare | Select-Object Name,Path,Description,Special,@{n='Access';e={@(Get-SmbShareAccess -Name $_.Name | Select-Object AccountName,AccessControlType,AccessRight)}} }
        firewall = { Get-NetFirewallProfile | Select-Object Name,Enabled,DefaultInboundAction,DefaultOutboundAction,AllowInboundRules,LogBlocked,LogFileName }
        defender = { Get-MpComputerStatus | Select-Object AMServiceEnabled,AntivirusEnabled,RealTimeProtectionEnabled,BehaviorMonitorEnabled,IoavProtectionEnabled,AntivirusSignatureLastUpdated,IsTamperProtected }
        eventlog = { Get-WinEvent -ListLog Security | Select-Object LogName,IsEnabled,MaximumSizeInBytes,LogMode }
        exclusions = { Get-MpPreference | Select-Object ExclusionPath,ExclusionExtension,ExclusionProcess,DisableRealtimeMonitoring,PUAProtection }
        features = { Get-WindowsOptionalFeature -Online | Select-Object FeatureName,State }
        logons = { Get-WinEvent -FilterHashtable @{LogName='Security';Id=4625,4720;StartTime=(Get-Date).AddDays(-7)} -MaxEvents 200 -ErrorAction SilentlyContinue | Select-Object TimeCreated,Id,Message }
    }
    foreach ($entry in $collectors.GetEnumerator()) {
        try { Save-Json "$Prefix-$($entry.Key).json" @(& $entry.Value) }
        catch { Write-LabWarning "Inventory $($entry.Key): $($_.Exception.Message)" }
    }
    Invoke-Native 'auditpol.exe' @('/get','/category:*','/r') | Set-Content (Join-Path $script:RunPath "$Prefix-audit.csv")
    Invoke-Native 'net.exe' @('accounts') | Set-Content (Join-Path $script:RunPath "$Prefix-password-policy.txt")
}

function Get-ApplicationInventory {
    $paths = @('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*','HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*','HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*')
    foreach ($path in $paths) {
        foreach ($app in Get-ItemProperty -Path $path -ErrorAction SilentlyContinue) {
            if (-not $app.PSObject.Properties['DisplayName'] -or -not $app.DisplayName) { continue }
            $protected = $false; $review = $false
            foreach ($pattern in $script:Profile.ProtectedApplicationPatterns) { if ($app.DisplayName -like $pattern) { $protected = $true } }
            foreach ($pattern in $script:Profile.ReviewApplicationPatterns) { if ($app.DisplayName -like $pattern) { $review = $true } }
            [pscustomobject]@{
                Name=$app.DisplayName
                Version=$(if ($app.PSObject.Properties['DisplayVersion']) {$app.DisplayVersion} else {''})
                RegistryPath=$app.PSPath
                Protected=$protected
                Review=($review -and -not $protected)
            }
        }
    }
}

function Set-RegistrySetting {
    param($Setting)
    if (-not (Test-Path -LiteralPath $Setting.Path)) { New-Item -Path $Setting.Path -Force | Out-Null }
    New-ItemProperty -LiteralPath $Setting.Path -Name $Setting.Name -Value $Setting.Value -PropertyType $Setting.Type -Force | Out-Null
}

function New-RegistryPlan {
    $system = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
    $lsa = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
    $settings = @(
        @($system,'EnableLUA',1), @($system,'ConsentPromptBehaviorAdmin',2),
        @($system,'PromptOnSecureDesktop',1), @($system,'FilterAdministratorToken',1),
        @($system,'DisableCAD',0), @($system,'DontDisplayLastUserName',1),
        @($system,'InactivityTimeoutSecs',[int]$script:Profile.LockAfterSeconds),
        @($lsa,'RestrictAnonymous',1), @($lsa,'RestrictAnonymousSAM',1),
        @($lsa,'EveryoneIncludesAnonymous',0), @($lsa,'LimitBlankPasswordUse',1),
        @($lsa,'NoLMHash',1), @($lsa,'LmCompatibilityLevel',5), @($lsa,'DisableDomainCreds',1),
        @($lsa,'SCENoApplyLegacyAuditPolicy',1),
        @('HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest','UseLogonCredential',0),
        @('HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server','fDenyTSConnections',1),
        @('HKLM:\SYSTEM\CurrentControlSet\Control\Remote Assistance','fAllowToGetHelp',0),
        @('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer','NoDriveTypeAutoRun',255),
        @('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer','NoAutorun',1),
        @('HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer','NoAutoplayfornonVolume',1),
        @('HKLM:\SOFTWARE\Policies\Microsoft\Windows\System','EnableSmartScreen',1),
        @('HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging','EnableScriptBlockLogging',1),
        @('HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging','EnableModuleLogging',1),
        @('HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU','NoAutoUpdate',0),
        @('HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU','AUOptions',2),
        @('HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU','NoAutoRebootWithLoggedOnUsers',1),
        @('HKLM:\SOFTWARE\Policies\Google\Chrome','SafeBrowsingProtectionLevel',1),
        @('HKLM:\SOFTWARE\Policies\Google\Chrome','DefaultPopupsSetting',2),
        @('HKLM:\SOFTWARE\Policies\Google\Chrome','DefaultGeolocationSetting',2),
        @('HKLM:\SOFTWARE\Policies\Google\Chrome','DownloadRestrictions',4)
    )
    foreach ($s in $settings) { [pscustomobject]@{Path=$s[0];Name=$s[1];Value=$s[2];Type='DWord'} }
    [pscustomobject]@{Path='HKLM:\SOFTWARE\Policies\Microsoft\Windows\System';Name='ShellSmartScreenLevel';Value='Warn';Type='String'}
    [pscustomobject]@{Path='HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging\ModuleNames';Name='*';Value='*';Type='String'}
}

function Save-RegistryBefore {
    param([object[]]$Settings)
    $before = foreach ($s in $Settings) {
        $key = Get-Item -LiteralPath $s.Path -ErrorAction SilentlyContinue
        $exists = $null -ne $key -and $s.Name -in $key.GetValueNames()
        [pscustomobject]@{
            Path=$s.Path; Name=$s.Name; Exists=$exists
            Type=$(if ($exists) {[string]$key.GetValueKind($s.Name)} else {$null})
            Value=$(if ($exists) {$key.GetValue($s.Name)} else {$null})
        }
    }
    Save-Json 'registry-before.json' @($before)
}

function Save-LabBackups {
    Invoke-Native 'secedit.exe' @('/export','/cfg',(Join-Path $script:RunPath 'security-before.inf'),'/areas','SECURITYPOLICY','USER_RIGHTS','/log',(Join-Path $script:RunPath 'security-export.log'),'/quiet') | Out-Null
    Invoke-Native 'auditpol.exe' @('/backup',("/file:{0}" -f (Join-Path $script:RunPath 'audit-before.csv'))) | Out-Null
    Invoke-Native 'netsh.exe' @('advfirewall','export',(Join-Path $script:RunPath 'firewall-before.wfw')) | Out-Null
    foreach ($file in @('security-before.inf','audit-before.csv','firewall-before.wfw')) {
        if (-not (Test-Path (Join-Path $script:RunPath $file))) { throw "Required backup missing: $file" }
    }
}

function Set-LabPassword {
    param([string]$Name, [switch]$Create)
    if ($Name -in $script:ProtectedNames) { throw "Refusing to reset protected account $Name" }
    $password = New-LabPassword -Length $script:Profile.PasswordPolicy.GeneratedLength
    try {
        $credential = [System.Management.Automation.PSCredential]::new($Name, $password)
        # Windows DPAPI binds this encrypted file to this user on this VM.
        $pending = Join-Path $script:RunPath "$Name.pending.credential.xml"
        $credential | Export-Clixml -LiteralPath $pending -Force
        if ($Create) {
            New-LocalUser -Name $Name -Password $password -Description 'Authorized lab employee' -AccountNeverExpires | Out-Null
            $script:CreatedNow.Add($Name)
        }
        else {
            $u = Get-LocalUser -Name $Name
            if ([string]$u.PrincipalSource -ne 'Local') { throw 'Password rotation supports local SAM accounts only.' }
            Set-LocalUser -Name $Name -Password $password
        }
        Move-Item -LiteralPath $pending -Destination (Join-Path $script:RunPath "$Name.credential.xml") -Force
    } finally { $password.Dispose() }
}

function Set-AccountPolicy {
    $p = $script:Profile.PasswordPolicy
    $guest = Get-LocalUser | Where-Object {$_.SID.Value -match '-501$'} | Select-Object -First 1
    $guestSid = if ($guest) { [string]$guest.SID } else { '' }
    $denyGuest = @('*S-1-5-32-546')
    if ($guestSid) { $denyGuest += "*$guestSid" }
    $denyLines = foreach ($right in @('SeDenyInteractiveLogonRight','SeDenyNetworkLogonRight','SeDenyRemoteInteractiveLogonRight')) {
        # Preserve pre-existing deny assignments rather than silently widening access.
        $existing = Select-String -LiteralPath (Join-Path $script:RunPath 'security-before.inf') -Pattern "^$right\s*=" | Select-Object -First 1
        $principals = @($denyGuest)
        if ($existing) { $principals += @((($existing.Line -split '=',2)[1] -split ',') | ForEach-Object {$_.Trim()} | Where-Object {$_}) }
        "$right = $((@($principals | Sort-Object -Unique)) -join ',')"
    }
    $inf = @"
[Unicode]
Unicode=yes
[Version]
signature="`$CHICAGO`$"
Revision=1
[System Access]
MinimumPasswordAge = $($p.MinimumAgeDays)
MaximumPasswordAge = $($p.MaximumAgeDays)
MinimumPasswordLength = $($p.MinimumLength)
PasswordComplexity = 1
PasswordHistorySize = $($p.History)
ClearTextPassword = 0
LockoutBadCount = $($p.LockoutThreshold)
ResetLockoutCount = $($p.ResetCounterMinutes)
LockoutDuration = $($p.LockoutMinutes)
[Privilege Rights]
SeNetworkLogonRight = *S-1-5-32-544,*S-1-5-32-545
SeInteractiveLogonRight = *S-1-5-32-544,*S-1-5-32-545
SeCreateGlobalPrivilege = *S-1-5-32-544,*S-1-5-6,*S-1-5-19,*S-1-5-20
SeDebugPrivilege = *S-1-5-32-544
SeBackupPrivilege = *S-1-5-32-544
SeRestorePrivilege = *S-1-5-32-544
SeTakeOwnershipPrivilege = *S-1-5-32-544
$($denyLines -join "`r`n")
"@
    $path = Join-Path $script:RunPath 'security-target.inf'
    $inf | Set-Content -LiteralPath $path -Encoding Unicode
    Invoke-Native 'secedit.exe' @('/configure','/db',(Join-Path $script:RunPath 'security-target.sdb'),'/cfg',$path,'/overwrite','/areas','SECURITYPOLICY','USER_RIGHTS','/log',(Join-Path $script:RunPath 'security-apply.log'),'/quiet') | Out-Null
}

function Find-ReviewFiles {
    $roots = @("$env:SystemDrive\Users", "$env:ProgramData", "$env:SystemRoot\Temp", "$env:SystemDrive\Temp")
    $scanErrors = @()
    $findings = foreach ($root in $roots) {
        if (-not (Test-Path -LiteralPath $root)) { continue }
        Get-ChildItem -LiteralPath $root -File -Recurse -Force -ErrorAction SilentlyContinue -ErrorVariable +scanErrors |
            Where-Object { $_.FullName -notlike "$script:BasePath\*" -and ($_.Extension.ToLowerInvariant() -in $script:Profile.MediaExtensions -or $_.Name -in $script:Profile.ReviewExecutableNames) } |
            Select-Object FullName,Length,LastWriteTime,@{n='Reason';e={if ($_.Name -in $script:Profile.ReviewExecutableNames) {'Review executable'} else {'Review media'}}}
    }
    Save-Json 'review-files.json' @($findings)
    Write-LabWarning "File scan is a filename/extension inventory, not a malware verdict. Unreadable locations: $($scanErrors.Count). Nothing was deleted."
}

function Install-LabSecurityUpdates {
    $session = New-Object -ComObject Microsoft.Update.Session
    $session.ClientApplicationID = 'Windows11HardeningLab'
    $searcher = $session.CreateUpdateSearcher()
    $found = $searcher.Search("IsInstalled=0 and IsHidden=0 and Type='Software'")
    $allow = @('0fa1201d-4330-4fa8-8ae9-b877473b6441','e6cf1350-c01b-414d-a61f-263d14d133b4','e0789628-ce08-4437-be74-2495b842f43b')
    $block = @('3689bdc8-b205-4af4-8d4a-a63924c5e9d5','b54e7d24-7add-428f-8b75-90a396fa584f')
    $updates = New-Object -ComObject Microsoft.Update.UpdateColl
    $review = foreach ($u in $found.Updates) {
        $cats = @($u.Categories | ForEach-Object { $_.CategoryID.ToLowerInvariant() })
        $safe = @($cats | Where-Object { $_ -in $allow }).Count -gt 0 -and @($cats | Where-Object { $_ -in $block }).Count -eq 0
        $safe = $safe -and $u.Title -notmatch '(?i)\bpreview\b|\binsider\b|\bfeature update\b' -and -not $u.BrowseOnly -and [bool]$u.AutoSelectOnWebSites
        if ($safe -and $u.EulaAccepted) { $updates.Add($u) | Out-Null }
        [pscustomobject]@{Title=$u.Title;Selected=($safe -and $u.EulaAccepted);EulaAccepted=$u.EulaAccepted;Categories=$cats}
    }
    Save-Json 'windows-update-selection.json' @($review)
    if ($updates.Count -eq 0) { Write-LabWarning 'No already-approved security/critical/definition updates selected. Review Windows Update manually; feature and preview updates stay excluded.'; return }
    $downloader = $session.CreateUpdateDownloader(); $downloader.Updates = $updates
    $download = $downloader.Download()
    if ([int]$download.ResultCode -ne 2) { throw "Update download incomplete; result code $($download.ResultCode)." }
    $installer = $session.CreateUpdateInstaller(); $installer.Updates = $updates
    $installer.AllowSourcePrompts = $false; $installer.ForceQuiet = $true
    if ($installer.RebootRequiredBeforeInstallation) { throw 'A restart is already required. Restart manually before installing updates.' }
    $result = $installer.Install()
    Save-Json 'windows-update-result.json' ([pscustomobject]@{ResultCode=[int]$result.ResultCode;RebootRequired=$result.RebootRequired;HResult=$result.HResult})
    if ($result.RebootRequired) { $script:RebootNeeded = $true }
    if ([int]$result.ResultCode -ne 2) { throw "Update installation incomplete; result code $($result.ResultCode)." }
}

# Preflight: Windows 11 client, standalone local accounts, VM console.
if ($env:OS -ne 'Windows_NT' -or -not [Environment]::Is64BitProcess -or $PSVersionTable.PSEdition -ne 'Desktop') {
    throw 'Use elevated 64-bit Windows PowerShell 5.1 inside the Windows 11 VM.'
}
$os = Get-CimInstance Win32_OperatingSystem
$computer = Get-CimInstance Win32_ComputerSystem
if ($os.ProductType -ne 1 -or [int]$os.BuildNumber -lt 22000) { throw 'This profile supports Windows 11 client only.' }
$edition = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion').EditionID
if ($edition -like 'Core*') { throw 'Use Windows 11 Pro, Education or Enterprise; this package relies on local security-policy tools.' }
if ($computer.PartOfDomain) { throw 'This local-account lab profile must not run on a domain-joined computer.' }
if ($env:SESSIONNAME -like 'RDP*' -or (Get-Variable PSSenderInfo -ErrorAction SilentlyContinue)) { throw 'Use the VM console; this profile disables remote management.' }
$script:Profile = Get-Content -LiteralPath $ConfigPath -Raw | ConvertFrom-Json
Test-LabProfile $script:Profile
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$current = Get-LocalUser -SID $identity.User
$adminGroup = Get-LocalGroup -SID 'S-1-5-32-544'
$usersGroup = Get-LocalGroup -SID 'S-1-5-32-545'
$initialMembers = @(Get-LocalGroupMember -Group $adminGroup.Name)
$primary = Get-LocalUser -Name $script:Profile.PrimaryAccount
if (-not $primary.Enabled -or [string]$primary.SID -notin @($initialMembers | ForEach-Object {[string]$_.SID})) { throw 'The primary account must already be an enabled local administrator.' }
if ($current.Name -notin $script:Profile.Administrators) { throw 'Run as one of the authorized local administrators.' }
$autoName = ''
$winlogon = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
if ($winlogon.PSObject.Properties['AutoAdminLogon'] -and $winlogon.AutoAdminLogon -eq '1' -and $winlogon.PSObject.Properties['DefaultUserName']) {
    $autoName = ([string]$winlogon.DefaultUserName).Split('\')[-1]
    if ($autoName -and $autoName -notin (@($script:Profile.Administrators) + @($script:Profile.Users))) { throw 'Auto-login names an unauthorized account. Review it manually before applying this profile.' }
}
$script:ProtectedNames = @($current.Name,$script:Profile.PrimaryAccount,$autoName) | Where-Object { $_ } | Sort-Object -Unique
$script:BasePath = Join-Path $env:ProgramData 'Windows11HardeningLab'
$script:RunPath = Join-Path $script:BasePath ("Runs\{0}-{1}" -f (Get-Date -Format 'yyyyMMdd-HHmmss'),([guid]::NewGuid().ToString('N').Substring(0,8)))
New-Item -Path $script:RunPath -ItemType Directory -Force | Out-Null
# Set an explicit ACL before collecting any inventory or encrypted credentials.
$acl = New-Object Security.AccessControl.DirectorySecurity
$acl.SetAccessRuleProtection($true,$false)
foreach ($sid in @($identity.User.Value,'S-1-5-18','S-1-5-32-544') | Select-Object -Unique) {
    $rule = [Security.AccessControl.FileSystemAccessRule]::new([Security.Principal.SecurityIdentifier]::new($sid),[Security.AccessControl.FileSystemRights]::FullControl,[Security.AccessControl.InheritanceFlags]'ContainerInherit,ObjectInherit',[Security.AccessControl.PropagationFlags]::None,[Security.AccessControl.AccessControlType]::Allow)
    $acl.AddAccessRule($rule)
}
Set-Acl -LiteralPath $script:RunPath -AclObject $acl
Copy-Item -LiteralPath $ConfigPath -Destination (Join-Path $script:RunPath 'profile-used.json')
Write-Host "Mode: $Mode. Reports: $script:RunPath"
Write-Host "Passwords preserved for: $($script:ProtectedNames -join ', ')"

try {
    Save-Inventory 'before'
    Save-Json 'applications.json' @(Get-ApplicationInventory)
    $registryPlan = @(New-RegistryPlan)
    Save-Json 'registry-target.json' $registryPlan
    Save-RegistryBefore $registryPlan
    # These commands only export settings. Backups are mandatory before remediation.
    Save-LabBackups
    $allAuthorized = @($script:Profile.Administrators) + @($script:Profile.Users)

    foreach ($name in $script:Profile.CreateUsers) {
        if (-not (Get-LocalUser -Name $name -ErrorAction SilentlyContinue)) {
            Invoke-LabChange 'CreateUser' $name 'Create authorized employee with a unique encrypted-record password' { Set-LabPassword -Name $name -Create }
        }
    }
    foreach ($user in Get-LocalUser) {
        $name = $user.Name
        $disposition = Get-AccountDisposition $name ([string]$user.SID) $script:Profile $script:ProtectedNames
        if ($disposition -like 'Disable*') {
            if ($user.Enabled) { Invoke-LabChange 'DisableUser' $name $disposition { Disable-LocalUser -Name $name } }
            continue
        }
        if ($disposition -eq 'PreserveBuiltin') { continue }
        if ($name -notin $allAuthorized) { continue }
        $passwordReady = $true
        if ($name -notin $script:ProtectedNames -and ($RotatePasswords -or $name -in $script:Profile.ResetPasswordAccounts) -and $name -notin $script:CreatedNow) {
            Invoke-LabChange 'RotatePassword' $name 'Rotate to a unique random password; save a Windows DPAPI credential file' { Set-LabPassword -Name $name }
            if ($Mode -eq 'Apply' -and $script:Changes[$script:Changes.Count - 1].Status -eq 'Failed') { $passwordReady = $false }
        }
        if (-not $user.Enabled -and $passwordReady) { Invoke-LabChange 'EnableAuthorizedUser' $name 'Enable authorized account' { Enable-LocalUser -Name $name } }
        if (-not $passwordReady -and -not $user.Enabled) { Write-LabWarning "Account $name stays disabled because its password reset failed." }
        Invoke-LabChange 'UserFlags' $name 'Require a password, enable expiration and allow password changes' {
            Set-LocalUser -Name $name -PasswordNeverExpires $false -UserMayChangePassword $true
            Invoke-Native 'net.exe' @('user',$name,'/passwordreq:yes') | Out-Null
        }
        Invoke-LabChange 'UsersMembership' $name 'Ensure authorized account belongs to local Users' {
            $sid = [string](Get-LocalUser -Name $name).SID
            if ($sid -notin @(Get-LocalGroupMember $usersGroup.Name | ForEach-Object {[string]$_.SID})) { Add-LocalGroupMember -Group $usersGroup.Name -Member $name }
        }
        if ($name -in $script:Profile.Administrators) {
            Invoke-LabChange 'AdminMembership' $name 'Ensure authorized administrator membership' {
                $sid = [string](Get-LocalUser -Name $name).SID
                if ($sid -notin @(Get-LocalGroupMember $adminGroup.Name | ForEach-Object {[string]$_.SID})) { Add-LocalGroupMember -Group $adminGroup.Name -Member $name }
            }
        }
    }
    foreach ($name in $allAuthorized) {
        if (-not (Get-LocalUser -Name $name -ErrorAction SilentlyContinue) -and $name -notin $script:Profile.CreateUsers) { Write-LabWarning "Authorized account $name is absent; review rather than inventing an account." }
    }
    foreach ($member in Get-LocalGroupMember -Group $adminGroup.Name) {
        # Built-in Administrator is disabled above; Windows can prevent removing its built-in membership.
        if ([string]$member.SID -match '-500$') { continue }
        $shortName = $member.Name.Split('\')[-1]
        if ($shortName -notin $script:Profile.Administrators -and $shortName -notin $script:ProtectedNames) {
            Invoke-LabChange 'RemoveAdmin' $member.Name 'Remove unauthorized administrator membership' { Remove-LocalGroupMember -Group $adminGroup.Name -Member $member.SID }
        }
    }
    # No RDP, Backup Operators, Power Users or guest privileges are authorized in this profile.
    foreach ($groupSid in @('S-1-5-32-547','S-1-5-32-551','S-1-5-32-555','S-1-5-32-546')) {
        $group = Get-LocalGroup -SID $groupSid -ErrorAction SilentlyContinue
        if (-not $group) { continue }
        foreach ($member in Get-LocalGroupMember -Group $group.Name) {
            if ([string]$member.SID -match '-501$' -and $groupSid -eq 'S-1-5-32-546') { continue }
            Invoke-LabChange 'RemovePrivilege' "$($group.Name): $($member.Name)" 'Remove unneeded privileged/guest group membership' { Remove-LocalGroupMember -Group $group.Name -Member $member.SID }
        }
    }

    Invoke-LabChange 'AccountPolicy' 'Local security policy' 'Enforce password/lockout policy and restrict selected user rights while preserving service identities' { Set-AccountPolicy }
    foreach ($setting in $registryPlan) {
        Invoke-LabChange 'Registry' "$($setting.Path)\$($setting.Name)" "Set $($setting.Value)" { Set-RegistrySetting $setting }
    }
    Invoke-LabChange 'Firewall' 'All profiles' 'Enable firewall; block unsolicited inbound, allow outbound, preserve core rules and log dropped traffic' {
        Set-NetFirewallProfile -Profile Domain,Private,Public -Enabled True -DefaultInboundAction Block -DefaultOutboundAction Allow -AllowInboundRules True -NotifyOnListen True -LogBlocked True -LogMaxSizeKilobytes 32767
    }
    $rulePatterns = @('FPS-*','NETDIS-*','RemoteDesktop*','RemoteAssistance*','WINRM-*','WMI-*')
    foreach ($rule in Get-NetFirewallRule -Direction Inbound -Enabled True) {
        $disable = $false
        foreach ($pattern in $rulePatterns) { if ($rule.Name -like $pattern) { $disable = $true } }
        if ($disable -and $rule.DisplayName -notmatch '(?i)ccs|cyberpatriot') { Invoke-LabChange 'FirewallRule' $rule.Name 'Disable unnecessary inbound management/discovery/sharing rule' { Disable-NetFirewallRule -Name $rule.Name } }
    }
    foreach ($subcategory in $script:Profile.AuditSubcategories) {
        Invoke-LabChange 'Audit' $subcategory 'Enable success and failure auditing' { Invoke-Native 'auditpol.exe' @('/set',"/subcategory:$subcategory",'/success:enable','/failure:enable') | Out-Null }
    }
    Invoke-LabChange 'EventLogSize' 'Security log' 'Set a 128 MiB rolling log; do not clear existing events' { Invoke-Native 'wevtutil.exe' @('sl','Security','/ms:134217728','/rt:false') | Out-Null }
    foreach ($name in $script:Profile.DisableServiceNames) {
        if ($name -in $script:Profile.RequiredServiceNames) { continue }
        $service = Get-CimInstance Win32_Service -Filter "Name='$name'" -ErrorAction SilentlyContinue
        if ($service -and $service.PathName -notmatch '(?i)ccsclient|cyberpatriot') {
            Invoke-LabChange 'DisableService' $name 'Stop and disable unnecessary optional service' {
                Set-Service -Name $name -StartupType Disabled
                # Do not force-stop dependent services.
                if ((Get-Service -Name $name).Status -ne 'Stopped') { Stop-Service -Name $name }
            }
        }
    }
    $availableFeatures = @{}
    try { foreach ($f in Get-WindowsOptionalFeature -Online) { $availableFeatures[$f.FeatureName] = $f } }
    catch { Write-LabWarning "Cannot enumerate optional features: $($_.Exception.Message)" }
    foreach ($name in $script:Profile.DisableFeatureNames) {
        if ($name -in $script:Profile.RequiredFeatureNames) { continue }
        $feature = $availableFeatures[$name]
        if ($feature -and [string]$feature.State -eq 'Enabled') {
            Invoke-LabChange 'DisableFeature' $name 'Disable obsolete/unneeded optional component without restarting' {
                $result = Disable-WindowsOptionalFeature -Online -FeatureName $name -NoRestart
                if ($result.RestartNeeded) { $script:RebootNeeded = $true }
            }
        }
    }
    Invoke-LabChange 'SMBServer' 'SMB' 'Disable SMB1 and require signing; retain SMB2/3' { Set-SmbServerConfiguration -EnableSMB1Protocol $false -EnableSecuritySignature $true -RequireSecuritySignature $true -Force }
    Invoke-LabChange 'SMBClient' 'SMB' 'Reject insecure guest logons and require signing' { Set-SmbClientConfiguration -EnableInsecureGuestLogons $false -EnableSecuritySignature $true -RequireSecuritySignature $true -Force }
    if ($script:Profile.RemoveNonSystemShares) {
        foreach ($share in Get-SmbShare | Where-Object {-not $_.Special -and $_.Name -notin $script:Profile.AllowedShareNames}) {
            Invoke-LabChange 'RemoveShare' $share.Name 'Remove unauthorized non-system share; keep files and system shares' { Remove-SmbShare -Name $share.Name -Force }
        }
    }
    foreach ($name in @('EventLog','wscsvc')) {
        Invoke-LabChange 'MonitoringService' $name 'Ensure security/event monitoring service is enabled and running' { Set-Service -Name $name -StartupType Automatic; Start-Service -Name $name }
    }
    Invoke-LabChange 'SecurityHealth' 'SecurityHealthService' 'Start Windows Security health reporting' { Start-Service -Name SecurityHealthService }
    Invoke-LabChange 'Defender' 'Microsoft Defender' 'Enable realtime, behavior, downloaded-file, script and archive protection; block potentially unwanted apps' {
        Set-MpPreference -DisableRealtimeMonitoring $false -DisableBehaviorMonitoring $false -DisableIOAVProtection $false -DisableScriptScanning $false -DisableArchiveScanning $false -PUAProtection Enabled
    }
    if ($UpdateDefender) { Invoke-LabChange 'DefenderUpdate' 'Signatures' 'Update Microsoft Defender definitions' { Update-MpSignature } }
    if ($QuickScan) { Invoke-LabChange 'DefenderScan' 'Quick scan' 'Run Defender quick scan; its configured remediation may quarantine detections' { Start-MpScan -ScanType QuickScan } }
    if ($UpdateApps) {
        foreach ($packageId in $script:Profile.ApplicationPackageIds) {
            Invoke-LabChange 'ApplicationUpdate' $packageId 'Upgrade this required application using its exact WinGet package ID' {
                if (-not (Get-Command winget.exe -ErrorAction SilentlyContinue)) { throw 'WinGet is unavailable; update from the vendor manually.' }
                # Do not install missing apps, accept new agreements, upgrade all, or permit reboot.
                $output = & winget.exe upgrade --id $packageId --exact --source winget --silent --disable-interactivity 2>&1
                $code = $LASTEXITCODE
                $output | Set-Content (Join-Path $script:RunPath "$packageId-upgrade.txt")
                if ($code -ne 0) { throw "WinGet returned $code; see package log. It may be current, missing, or require interactive agreement." }
            }
        }
    }
    if ($InstallSecurityUpdates) { Invoke-LabChange 'WindowsUpdates' 'Windows Update Agent' 'Install only classified security/critical/definition updates; exclude feature/preview builds; never reboot' { Install-LabSecurityUpdates } }
    if ($ScanFiles) { Find-ReviewFiles }
    # Accessibility hijacks are reported as evidence, never overwritten or launched.
    $accessibility = foreach ($exe in @('sethc.exe','utilman.exe','osk.exe','Narrator.exe','Magnify.exe')) {
        $file = Join-Path "$env:SystemRoot\System32" $exe
        $sig = Get-AuthenticodeSignature -LiteralPath $file -ErrorAction SilentlyContinue
        $ifeo = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\$exe"
        $properties = Get-ItemProperty -LiteralPath $ifeo -ErrorAction SilentlyContinue
        [pscustomobject]@{File=$file;Signature=$(if ($sig) {[string]$sig.Status} else {'Unavailable'});SHA256=$(if (Test-Path $file) {(Get-FileHash $file -Algorithm SHA256).Hash} else {''});Debugger=$(if ($properties -and $properties.PSObject.Properties['Debugger']) {$properties.Debugger} else {''})}
    }
    Save-Json 'accessibility-review.json' @($accessibility)
    Write-LabWarning 'Chrome defaults require per-user verification in Settings > Apps > Default apps > Google Chrome. No UserChoice protection or JavaScript settings were changed.'
    Write-LabWarning 'Review applications, per-user installs, Defender exclusions, scheduled tasks, startup entries, shares, user rights and forensic evidence manually. File and malware findings are not automatically deleted.'
    Write-LabWarning 'Primary/current/auto-login passwords stay unchanged. Expiration is enabled for authorized accounts; an old password can become due at the next sign-in.'
    if ($Mode -eq 'Apply' -and -not $WhatIfPreference) { Save-Inventory 'after'; $script:RebootNeeded = $true }
} catch {
    $script:Changes.Add([pscustomobject]@{Id='Fatal';Target='Run';Description='Run stopped by a terminating error';Status='Failed';Detail=$_.Exception.Message})
    throw
} finally {
    Save-Json 'changes.json' @($script:Changes)
    Save-Json 'warnings.json' @($script:Warnings)
    Save-Json 'summary.json' ([pscustomobject]@{Mode=$Mode;WhatIf=[bool]$WhatIfPreference;RebootNeeded=$script:RebootNeeded;Applied=@($script:Changes | Where-Object Status -eq 'Applied').Count;Planned=@($script:Changes | Where-Object Status -eq 'Planned').Count;Failed=@($script:Changes | Where-Object Status -eq 'Failed').Count;ProtectedAccounts=$script:ProtectedNames})
    Write-Host "Reports saved to $script:RunPath"
    if ($script:RebootNeeded) { Write-Warning 'Restart may be needed. No restart was initiated.' }
}
if (@($script:Changes | Where-Object Status -eq 'Failed').Count -gt 0) { exit 2 }
