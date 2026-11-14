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
    [string]$ConfigPath = '',
    [switch]$RotatePasswords,
    [switch]$ScanFiles,
    [switch]$UpdateApps,
    [switch]$InstallSecurityUpdates,
    [switch]$UpdateDefender,
    [switch]$QuickScan,
    [switch]$AdvancedAudit,
    [switch]$ExtendedReview
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
if ($ExtendedReview) { $AdvancedAudit = $true; $ScanFiles = $true }
$script:Runner = $PSCmdlet
$script:Changes = New-Object 'System.Collections.Generic.List[object]'
$script:Warnings = New-Object 'System.Collections.Generic.List[string]'
$script:RebootNeeded = $false
$script:CreatedNow = New-Object 'System.Collections.Generic.List[string]'

function Resolve-LabConfigPath {
    param([string]$Path, [string]$ScriptDirectory)
    if ([string]::IsNullOrWhiteSpace($Path)) {
        if ([string]::IsNullOrWhiteSpace($ScriptDirectory)) {
            throw 'Cannot locate lab.config.json. Save the complete .ps1 file and run it with powershell.exe -File, or provide -ConfigPath explicitly.'
        }
        $Path = Join-Path -Path $ScriptDirectory -ChildPath 'lab.config.json'
    }
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        throw "Lab configuration file not found: $Path. Extract the entire package or provide -ConfigPath with the JSON file location."
    }
    $resolved = Resolve-Path -LiteralPath $Path
    if ($resolved.Provider.Name -ne 'FileSystem') { throw 'ConfigPath must identify a JSON file on the filesystem.' }
    return $resolved.ProviderPath
}

function Assert-ProfileProperties {
    param($Value, [string[]]$Names, [string]$Context)
    if ($null -eq $Value -or $Value -isnot [System.Management.Automation.PSCustomObject]) {
        throw "$Context must be a JSON object."
    }
    $missing = @($Names | Where-Object { -not $Value.PSObject.Properties[$_] })
    if ($missing.Count) { throw "${Context} is missing required fields: $($missing -join ', ')." }
    $unknown = @($Value.PSObject.Properties.Name | Where-Object { $_ -notin $Names })
    if ($unknown.Count) { throw "${Context} has unsupported fields (check spelling): $($unknown -join ', ')." }
}

function Assert-ProfileInteger {
    param($Value, [string]$Name)
    if ($Value -isnot [int] -and $Value -isnot [long]) { throw "$Name must be a JSON integer, not quoted text or a decimal." }
}

function Test-LabProfile {
    param($Profile)
    $lists = @('Administrators','Users','CreateUsers','ResetPasswordAccounts','RequiredServiceNames','DisableServiceNames','RequiredFeatureNames','DisableFeatureNames','AllowedShareNames','ProtectedApplicationPatterns','ReviewApplicationPatterns','ApplicationPackageIds','AuditSubcategories','MediaExtensions','ReviewExecutableNames')
    Assert-ProfileProperties $Profile (@('SchemaVersion','PrimaryAccount','PasswordPolicy','RemoveNonSystemShares','LockAfterSeconds','EnableRemoteDesktop') + $lists) 'Profile'
    Assert-ProfileInteger $Profile.SchemaVersion 'SchemaVersion'
    if ($Profile.SchemaVersion -ne 2) { throw 'Use the schema 2 profile supplied with this script; older scenario profiles must be adapted explicitly.' }
    if ($Profile.EnableRemoteDesktop -isnot [bool]) { throw 'EnableRemoteDesktop must be JSON true or false.' }
    if ($Profile.PrimaryAccount -isnot [string] -or [string]::IsNullOrWhiteSpace($Profile.PrimaryAccount)) { throw 'PrimaryAccount must be a nonempty account name.' }
    if ($Profile.RemoveNonSystemShares -isnot [bool]) { throw 'RemoveNonSystemShares must be JSON true or false, without quotes.' }
    Assert-ProfileInteger $Profile.LockAfterSeconds 'LockAfterSeconds'
    if ($Profile.LockAfterSeconds -lt 1 -or $Profile.LockAfterSeconds -gt 599940) { throw 'LockAfterSeconds must be between 1 and 599940.' }
    foreach ($field in $lists) {
        if ($Profile.$field -isnot [array]) { throw "$field must be a JSON array, including when empty or containing one item." }
        foreach ($value in $Profile.$field) {
            if ($value -isnot [string] -or [string]::IsNullOrWhiteSpace($value) -or $value -ne $value.Trim()) { throw "$field entries must be nonempty strings without surrounding spaces." }
        }
        if (@($Profile.$field | Sort-Object -Unique).Count -ne @($Profile.$field).Count) { throw "$field contains repeated entries." }
    }
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
    $policyFields = @('MinimumLength','GeneratedLength','History','MinimumAgeDays','MaximumAgeDays','LockoutThreshold','LockoutMinutes','ResetCounterMinutes')
    Assert-ProfileProperties $p $policyFields 'PasswordPolicy'
    foreach ($field in $policyFields) { Assert-ProfileInteger $p.$field "PasswordPolicy.$field" }
    if ($p.MinimumLength -ne 14 -or $p.GeneratedLength -lt $p.MinimumLength -or $p.GeneratedLength -gt 128) {
        throw 'This portable local-policy profile requires MinimumLength 14 and generated passwords of 14-128 characters.'
    }
    if ($p.History -lt 1 -or $p.History -gt 24 -or $p.MinimumAgeDays -lt 0 -or $p.MaximumAgeDays -gt 999 -or $p.MaximumAgeDays -le $p.MinimumAgeDays) {
        throw 'Invalid password history or expiration interval.'
    }
    if ($p.LockoutThreshold -lt 1 -or $p.LockoutThreshold -gt 999 -or $p.ResetCounterMinutes -lt 1 -or $p.ResetCounterMinutes -gt 99999 -or $p.LockoutMinutes -lt $p.ResetCounterMinutes -or $p.LockoutMinutes -gt 99999) {
        throw 'Invalid account lockout policy.'
    }
    $essential = @('RpcSs','DcomLaunch','SamSs','LSM','EventLog','WinDefend','WdNisSvc','mpssvc','BFE','wuauserv','BITS','CryptSvc','Dhcp','Dnscache','Winmgmt','wscsvc','SecurityHealthService')
    foreach ($name in @($Profile.DisableServiceNames) + @($Profile.RequiredServiceNames)) {
        if ($name -notmatch '^[A-Za-z0-9_.$-]+$') { throw 'Service entries must be simple exact names, not patterns.' }
    }
    foreach ($name in $Profile.DisableServiceNames) {
        if ($name -in $essential -or $name -match '(?i)ccs|cyberpatriot|vmtools|vbox') { throw "Protected service in disable list: $name" }
    }
    foreach ($name in @($Profile.DisableFeatureNames) + @($Profile.RequiredFeatureNames)) {
        if ($name -notmatch '^[A-Za-z0-9_.-]+$') { throw 'Feature entries must be simple exact names, not patterns.' }
    }
    foreach ($id in $Profile.ApplicationPackageIds) {
        if ($id -notmatch '^[A-Za-z0-9][A-Za-z0-9_.+-]*$') { throw "Invalid exact application package ID: $id" }
    }
    foreach ($extension in $Profile.MediaExtensions) {
        if ($extension -notmatch '^\.[A-Za-z0-9]+$') { throw "Invalid media extension: $extension" }
    }
    foreach ($name in $Profile.ReviewExecutableNames) {
        if ($name -notmatch '^[^\\/:*?"<>|]+\.exe$') { throw "ReviewExecutableNames must contain exact .exe filenames: $name" }
    }
    foreach ($name in $Profile.RequiredServiceNames) {
        if ($name -eq 'WinRM' -or (-not $Profile.EnableRemoteDesktop -and $name -in @('TermService','SessionEnv','UmRdpService'))) {
            throw "Required service $name conflicts with this baseline's remote-access registry/firewall settings. Adapt those modules before Apply; a service exemption alone is insufficient."
        }
        $dependencies = switch ($name) {
            'W3SVC' { 'IIS-WebServerRole' }
            'FTPSVC' { 'IIS-WebServerRole'; 'IIS-FTPServer' }
            'WMSVC' { 'IIS-WebServerRole' }
        }
        foreach ($feature in $dependencies) {
            if ($feature -in $Profile.DisableFeatureNames -and $feature -notin $Profile.RequiredFeatureNames) {
                throw "Required service $name conflicts with disabling feature $feature. Review the service and feature requirements together."
            }
        }
    }
    if ($Profile.EnableRemoteDesktop) {
        if ('TermService' -notin $Profile.RequiredServiceNames) { throw 'Required RDP must include TermService in RequiredServiceNames.' }
        foreach ($name in @('TermService','SessionEnv','UmRdpService')) {
            if ($name -in $Profile.DisableServiceNames) { throw "RDP is required but $name is in DisableServiceNames." }
        }
    }
}

function Assert-LabCapabilities {
    param([string[]]$CommandNames)
    $missing = @(foreach ($name in $CommandNames | Sort-Object -Unique) {
        if (-not (Get-Command -Name $name -ErrorAction SilentlyContinue)) { $name }
    })
    if ($missing.Count) { throw "Required commands are unavailable: $($missing -join ', '). Use elevated 64-bit Windows PowerShell 5.1 and verify the relevant Windows components before Apply." }
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
    param([string]$Program, [string[]]$Arguments, [string]$OutputPath = '')
    $command = Get-Command -Name $Program -CommandType Application -ErrorAction Stop
    $savedPreference = $ErrorActionPreference
    try {
        # Windows PowerShell 5.1 can turn redirected stderr into an error even
        # when a native tool succeeds. Preserve both streams and check its exit.
        $ErrorActionPreference = 'Continue'
        # Native execution updates the global automatic variable, even in a function.
        $global:LASTEXITCODE = $null
        $output = & $command.Source @Arguments 2>&1
        $exitCode = $global:LASTEXITCODE
    } finally { $ErrorActionPreference = $savedPreference }
    if ($OutputPath) { $output | Set-Content -LiteralPath $OutputPath -Encoding UTF8 }
    if ($null -eq $exitCode) { throw "$Program did not return a native exit code." }
    if ($exitCode -ne 0) { throw "$Program failed ($exitCode): $($output -join ' ')" }
    return $output
}

function Invoke-LabChange {
    param([string]$Id, [string]$Target, [string]$Description, [scriptblock]$Action)
    $status = 'Planned'; $detail = ''
    if ($Mode -eq 'Apply' -and $script:Runner.ShouldProcess($Target, $Description)) {
        Write-Host "[Applying] $Description : $Target"
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
        processes = { Get-CimInstance Win32_Process | Select-Object Name,ProcessId,ParentProcessId,ExecutablePath,CommandLine }
        shares = { Get-SmbShare | Select-Object Name,Path,Description,Special,@{n='Access';e={@(Get-SmbShareAccess -Name $_.Name | Select-Object AccountName,AccessControlType,AccessRight)}} }
        firewall = { Get-NetFirewallProfile | Select-Object Name,Enabled,DefaultInboundAction,DefaultOutboundAction,AllowInboundRules,LogBlocked,LogFileName }
        defender = { Get-MpComputerStatus | Select-Object AMRunningMode,AMServiceEnabled,AntivirusEnabled,RealTimeProtectionEnabled,BehaviorMonitorEnabled,IoavProtectionEnabled,AntivirusSignatureLastUpdated,IsTamperProtected }
        eventlog = { Get-WinEvent -ListLog Security | Select-Object LogName,IsEnabled,MaximumSizeInBytes,LogMode }
        exclusions = { Get-MpPreference | Select-Object ExclusionPath,ExclusionExtension,ExclusionProcess,DisableRealtimeMonitoring,PUAProtection,MAPSReporting,SubmitSamplesConsent,DisableBlockAtFirstSeen }
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
        @('HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server','fDenyTSConnections',$(if ($script:Profile.EnableRemoteDesktop) {0} else {1})),
        @('HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services','fDenyTSConnections',$(if ($script:Profile.EnableRemoteDesktop) {0} else {1})),
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
    if ($script:Profile.EnableRemoteDesktop) {
        foreach ($path in @('HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp','HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services')) {
            foreach ($item in @(@('UserAuthentication',1),@('SecurityLayer',2),@('MinEncryptionLevel',3))) {
                [pscustomobject]@{Path=$path;Name=$item[0];Value=$item[1];Type='DWord'}
            }
        }
    }
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

function Get-LabRdpSidClosure {
    param([string[]]$AccountSids,[object[]]$Memberships)
    # Token groups shared by authenticated local/RDP users, including the local-
    # account SIDs that are sometimes used to deny all local RDP sign-ins.
    $sids = @($AccountSids) + @('S-1-1-0','S-1-2-0','S-1-5-2','S-1-5-4','S-1-5-11','S-1-5-14','S-1-5-113','S-1-5-114','S-1-5-32-544','S-1-5-32-545','S-1-5-32-555')
    do {
        $added = $false
        foreach ($membership in $Memberships) {
            if ($membership.MemberSid -in $sids -and $membership.GroupSid -notin $sids) { $sids += $membership.GroupSid; $added=$true }
        }
    } while ($added)
    return @($sids | Sort-Object -Unique)
}

function Get-LabDenyPrincipals {
    param([string[]]$Existing,[string[]]$GuestPrincipals,[string[]]$PermittedSids=@())
    foreach ($principal in @($Existing) + @($GuestPrincipals) | Sort-Object -Unique) {
        $sid = $principal.TrimStart('*')
        if ($sid -notmatch '^S-\d-') {
            # Secedit usually exports SIDs. Resolve named assignments when possible;
            # retain unresolved identities rather than deleting an unknown denial.
            try { $sid = ([Security.Principal.NTAccount]::new($sid)).Translate([Security.Principal.SecurityIdentifier]).Value }
            catch { $sid = '' }
        }
        if ($principal -in $GuestPrincipals -or $sid -notin $PermittedSids) { $principal }
    }
}

function Set-AccountPolicy {
    $p = $script:Profile.PasswordPolicy
    $guest = Get-LocalUser | Where-Object {$_.SID.Value -match '-501$'} | Select-Object -First 1
    $guestSid = if ($guest) { [string]$guest.SID } else { '' }
    $denyGuest = @('*S-1-5-32-546')
    if ($guestSid) { $denyGuest += "*$guestSid" }
    $rdpSids = @()
    if ($script:Profile.EnableRemoteDesktop) {
        $authorizedSids = @(foreach ($name in @($script:Profile.Administrators) + @($script:Profile.Users)) {
            $user = Get-LocalUser -Name $name -ErrorAction SilentlyContinue
            if ($user) { [string]$user.SID }
        })
        $memberships = @(foreach ($group in Get-LocalGroup) {
            foreach ($member in Get-LocalGroupMember -Group $group.Name) { [pscustomobject]@{GroupSid=[string]$group.SID;MemberSid=[string]$member.SID} }
        })
        $rdpSids = @(Get-LabRdpSidClosure $authorizedSids $memberships)
    }
    $denyAdjustments = New-Object 'System.Collections.Generic.List[object]'
    $denyLines = foreach ($right in @('SeDenyInteractiveLogonRight','SeDenyNetworkLogonRight','SeDenyRemoteInteractiveLogonRight')) {
        # Keep unrelated denials. Required RDP must not retain a broad/direct denial
        # of authorized employees; deny rights override allow/group assignments.
        $existing = Select-String -LiteralPath (Join-Path $script:RunPath 'security-before.inf') -Pattern "^$right\s*=" | Select-Object -First 1
        $previous = @()
        if ($existing) { $previous = @((($existing.Line -split '=',2)[1] -split ',') | ForEach-Object {$_.Trim()} | Where-Object {$_}) }
        $permitted = if ($right -ne 'SeDenyInteractiveLogonRight') { $rdpSids } else { @() }
        $principals = @(Get-LabDenyPrincipals $previous $denyGuest $permitted)
        foreach ($removed in $previous | Where-Object {$_ -notin $principals}) {
            $denyAdjustments.Add([pscustomobject]@{Right=$right;Principal=$removed;Reason='Conflicts with scenario-required employee RDP access'})
        }
        "$right = $((@($principals | Sort-Object -Unique)) -join ',')"
    }
    Save-Json 'rdp-deny-adjustments.json' ($denyAdjustments.ToArray())
    $remoteLogonRight = if ($script:Profile.EnableRemoteDesktop) { 'SeRemoteInteractiveLogonRight = *S-1-5-32-544,*S-1-5-32-555' } else { '' }
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
$remoteLogonRight
$($denyLines -join "`r`n")
"@
    $path = Join-Path $script:RunPath 'security-target.inf'
    $inf | Set-Content -LiteralPath $path -Encoding Unicode
    Invoke-Native 'secedit.exe' @('/configure','/db',(Join-Path $script:RunPath 'security-target.sdb'),'/cfg',$path,'/overwrite','/areas','SECURITYPOLICY','USER_RIGHTS','/log',(Join-Path $script:RunPath 'security-apply.log'),'/quiet') | Out-Null
}

function Get-LabRestrictedGroups {
    @('S-1-5-32-547','S-1-5-32-551','S-1-5-32-546')
    if (-not $script:Profile.EnableRemoteDesktop) { 'S-1-5-32-555' }
}

function Get-LabDisabledFirewallPatterns {
    @('FPS-*','NETDIS-*','RemoteAssistance*','WINRM-*','WMI-*')
    if (-not $script:Profile.EnableRemoteDesktop) { 'RemoteDesktop*' }
}

function Set-LabRdpMembership {
    $group = Get-LocalGroup -SID 'S-1-5-32-555'
    $allowed = @($script:Profile.Administrators) + @($script:Profile.Users)
    $users = @(foreach ($name in $allowed) { Get-LocalUser -Name $name -ErrorAction SilentlyContinue })
    $allowedSids = @($users | ForEach-Object {[string]$_.SID})
    foreach ($member in Get-LocalGroupMember -Group $group.Name) {
        if ([string]$member.SID -notin $allowedSids) { Remove-LocalGroupMember -Group $group.Name -Member $member }
    }
    foreach ($user in $users | Where-Object {$_.Name -in $script:Profile.Users}) {
        if ([string]$user.SID -notin @(Get-LocalGroupMember -Group $group.Name | ForEach-Object {[string]$_.SID})) {
            Add-LocalGroupMember -Group $group.Name -Member $user
        }
    }
}

function Set-LabRdpServices {
    foreach ($name in @('TermService','SessionEnv','UmRdpService')) {
        $service = Get-Service -Name $name
        if ($name -eq 'TermService') {
            if ($service.StartType -ne 'Automatic') { Set-Service -Name $name -StartupType Automatic }
            if ($service.Status -ne 'Running') { Start-Service -Name $name }
            $verified = Get-Service -Name $name
            if ($verified.Status -ne 'Running' -or $verified.StartType -ne 'Automatic') { throw 'TermService did not reach Running/Automatic.' }
        } elseif ($service.StartType -eq 'Disabled') {
            # Leave supporting services trigger-start/manual unless explicitly disabled.
            Set-Service -Name $name -StartupType Manual
        }
    }
}

function Set-LabRdpFirewall {
    $port = [int](Get-ItemProperty -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -Name PortNumber).PortNumber
    if ($port -lt 1 -or $port -gt 65535) { throw 'Invalid configured RDP listener port. Review it manually.' }
    foreach ($protocol in @('TCP','UDP')) {
        $name = "RemoteDesktop-UserMode-In-$protocol"
        $rule = Get-NetFirewallRule -Name $name -ErrorAction Stop
        if (-not $rule) { throw "Required built-in RDP rule $name is missing; no broad replacement rule was created." }
        # Keep source-address, program, service and profile restrictions. Match the
        # existing listener port rather than resetting a custom port to 3389.
        Set-NetFirewallRule -Name $name -Enabled True -Action Allow -Direction Inbound -Protocol $protocol -LocalPort $port
        $verified = Get-NetFirewallRule -PolicyStore ActiveStore -Name $name -ErrorAction Stop
        if ([string]$verified.Enabled -ne 'True' -or [string]$verified.Action -ne 'Allow' -or [string]$verified.Direction -ne 'Inbound') { throw "RDP firewall rule $name did not become an active inbound allow rule." }
    }
}

function Save-LabRdpState {
    param([string]$Prefix)
    $path = 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp'
    $listener = Get-ItemProperty -LiteralPath $path
    $port = [int]$listener.PortNumber
    $rules = @(Get-NetFirewallRule -PolicyStore ActiveStore -Name 'RemoteDesktop-UserMode-In-TCP','RemoteDesktop-UserMode-In-UDP' -ErrorAction Stop)
    $state = [pscustomobject]@{
        Note='Stored configuration/local listener evidence; verify an actual employee RDP sign-in from another computer. Existing rule profile/source restrictions and other block rules can still affect access.'
        Port=$port
        Listening=@(Get-NetTCPConnection -State Listen -LocalPort $port -ErrorAction SilentlyContinue).Count -gt 0
        ListenerSettings=$listener | Select-Object UserAuthentication,SecurityLayer,MinEncryptionLevel
        Services=@(Get-Service -Name TermService,SessionEnv,UmRdpService | Select-Object Name,Status,StartType)
        FirewallRules=@($rules | Select-Object Name,Enabled,Action,Direction,Profile)
        FirewallPorts=@($rules | Get-NetFirewallPortFilter | Select-Object Protocol,LocalPort)
        FirewallSources=@($rules | Get-NetFirewallAddressFilter | Select-Object LocalAddress,RemoteAddress)
        Members=@(Get-LocalGroupMember -Group (Get-LocalGroup -SID 'S-1-5-32-555').Name | Select-Object Name,@{n='SID';e={[string]$_.SID}})
    }
    Save-Json "$Prefix-rdp.json" $state
    if ($Prefix -eq 'after' -and -not $state.Listening) { Write-LabWarning 'RDP has no local TCP listener yet. Restart manually if needed, then verify RDP before considering this scenario complete.' }
}

function Find-ReviewFiles {
    Import-Module -Name $reviewModule -Force -ErrorAction Stop
    $roots = @("$env:SystemDrive\Users", "$env:ProgramData", "$env:SystemRoot\Temp", "$env:SystemDrive\Temp")
    $inventory = Get-LabReviewFileInventory -Roots $roots -MediaExtensions $script:Profile.MediaExtensions -ToolNames $script:Profile.ReviewExecutableNames -ExcludeRoot $script:BasePath
    Save-Json 'review-files.json' $inventory.Files
    Save-Json 'file-scan-status.json' ($inventory | Select-Object -Property * -ExcludeProperty Files)
    Write-Host "File review: $($inventory.Files.Count) candidates; $($inventory.FilesExamined) files inspected; $($inventory.UnreadableLocations.Count) unreadable locations. Nothing deleted."
    if ($inventory.Status -eq 'Partial') { Write-LabWarning 'File review is partial. Open file-scan-status.json for unreadable locations; access restrictions were not bypassed.' }
}

function Install-LabSecurityUpdates {
    $session = New-Object -ComObject Microsoft.Update.Session
    $session.ClientApplicationID = 'Windows11HardeningLab'
    $searcher = $session.CreateUpdateSearcher()
    Write-Host '[Windows Update] Searching for approved security/critical/definition updates. This synchronous operation can take several minutes.'
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
    Write-Host "[Windows Update] Downloading $($updates.Count) selected updates. Manual updates are preferred; this runs only with -InstallSecurityUpdates."
    $download = $downloader.Download()
    Save-Json 'windows-update-download.json' ([pscustomobject]@{ResultCode=[int]$download.ResultCode;HResult=$download.HResult})
    if ([int]$download.ResultCode -ne 2) { throw "Update download incomplete; result code $($download.ResultCode)." }
    $installer = $session.CreateUpdateInstaller(); $installer.Updates = $updates
    $installer.AllowSourcePrompts = $false; $installer.ForceQuiet = $true
    if ($installer.RebootRequiredBeforeInstallation) { throw 'A restart is already required. Restart manually before installing updates.' }
    Write-Host '[Windows Update] Installing selected updates; waiting for Windows Update Agent to return. No restart will be initiated.'
    $result = $installer.Install()
    $perUpdate = for ($index=0; $index -lt $updates.Count; $index++) {
        $detail=$result.GetUpdateResult($index)
        [pscustomobject]@{Title=$updates.Item($index).Title;ResultCode=[int]$detail.ResultCode;HResult=$detail.HResult;RebootRequired=$detail.RebootRequired}
    }
    Save-Json 'windows-update-result.json' ([pscustomobject]@{ResultCode=[int]$result.ResultCode;RebootRequired=$result.RebootRequired;HResult=$result.HResult;Updates=@($perUpdate)})
    if ($result.RebootRequired) { $script:RebootNeeded = $true }
    if ([int]$result.ResultCode -ne 2) { throw "Update installation incomplete; result code $($result.ResultCode), HRESULT $($result.HResult). See windows-update-result.json for individual updates. Finish through Windows Update manually; do not rerun baseline Apply to retry updates." }
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
if ($env:SESSIONNAME -like 'RDP*' -or (Get-Variable PSSenderInfo -ErrorAction SilentlyContinue)) { throw 'Use the VM console while changing passwords, sign-in rights and firewall settings, including when this scenario requires RDP.' }
$ConfigPath = Resolve-LabConfigPath -Path $ConfigPath -ScriptDirectory $PSScriptRoot
$script:Profile = Get-Content -LiteralPath $ConfigPath -Raw | ConvertFrom-Json
Test-LabProfile $script:Profile
$requiredCommands = @('Get-LocalUser','New-LocalUser','Set-LocalUser','Enable-LocalUser','Disable-LocalUser','Get-LocalGroup','Get-LocalGroupMember','Add-LocalGroupMember','Remove-LocalGroupMember','Get-NetFirewallProfile','Set-NetFirewallProfile','Get-NetFirewallRule','Disable-NetFirewallRule','Get-WindowsOptionalFeature','Disable-WindowsOptionalFeature','Get-SmbShare','Get-SmbShareAccess','Remove-SmbShare','Set-SmbServerConfiguration','Set-SmbClientConfiguration','Get-MpComputerStatus','Get-MpPreference','Set-MpPreference','auditpol.exe','net.exe','netsh.exe','secedit.exe','wevtutil.exe')
if ($UpdateApps) { $requiredCommands += 'winget.exe' }
if ($UpdateDefender) { $requiredCommands += 'Update-MpSignature' }
if ($QuickScan) { $requiredCommands += 'Start-MpScan' }
if ($script:Profile.EnableRemoteDesktop) { $requiredCommands += @('Set-NetFirewallRule','Get-NetFirewallPortFilter','Get-NetFirewallAddressFilter','Get-NetTCPConnection') }
Assert-LabCapabilities $requiredCommands
$reviewModule = Join-Path $PSScriptRoot 'modules\Lab.Review.psm1'
if (($ScanFiles -or $ExtendedReview) -and -not (Test-Path -LiteralPath $reviewModule -PathType Leaf)) { throw 'File/extended review requires modules\Lab.Review.psm1. Extract the complete repository ZIP.' }
$advancedAuditModule = Join-Path $PSScriptRoot 'modules\Lab.AdvancedAudit.psm1'
if ($AdvancedAudit -and -not (Test-Path -LiteralPath $advancedAuditModule -PathType Leaf)) {
    throw 'AdvancedAudit requires modules\Lab.AdvancedAudit.psm1. Extract the complete repository ZIP.'
}
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
    Save-Json 'run-info.json' ([pscustomobject]@{
        StartedAtUtc=[DateTime]::UtcNow.ToString('o')
        PowerShellVersion=[string]$PSVersionTable.PSVersion
        WindowsBuild=[string]$os.BuildNumber
        Edition=$edition
        ScriptSHA256=(Get-FileHash -LiteralPath $PSCommandPath -Algorithm SHA256).Hash
        ProfileSHA256=(Get-FileHash -LiteralPath $ConfigPath -Algorithm SHA256).Hash
        ReviewModuleSHA256=$(if ($ScanFiles -or $ExtendedReview) {(Get-FileHash -LiteralPath $reviewModule -Algorithm SHA256).Hash} else {$null})
        AdvancedAuditModuleSHA256=$(if ($AdvancedAudit) {(Get-FileHash -LiteralPath $advancedAuditModule -Algorithm SHA256).Hash} else {$null})
        Options=[pscustomobject]@{Mode=$Mode;WhatIf=[bool]$WhatIfPreference;RotatePasswords=[bool]$RotatePasswords;ScanFiles=[bool]$ScanFiles;UpdateApps=[bool]$UpdateApps;InstallSecurityUpdates=[bool]$InstallSecurityUpdates;UpdateDefender=[bool]$UpdateDefender;QuickScan=[bool]$QuickScan;AdvancedAudit=[bool]$AdvancedAudit;ExtendedReview=[bool]$ExtendedReview}
    })
    Save-Inventory 'before'
    Save-Json 'applications.json' @(Get-ApplicationInventory)
    $registryPlan = @(New-RegistryPlan)
    Save-Json 'registry-target.json' $registryPlan
    Save-RegistryBefore $registryPlan
    # These commands only export settings. Backups are mandatory before remediation.
    Save-LabBackups
    if ($script:Profile.EnableRemoteDesktop) {
        try { Save-LabRdpState 'before' } catch { Write-LabWarning "RDP before-state collection: $($_.Exception.Message)" }
    }
    if ($ScanFiles) {
        try { Find-ReviewFiles }
        catch {
            Save-Json 'file-scan-status.json' ([pscustomobject]@{Status='Unknown';Detail=$_.Exception.Message})
            Write-LabWarning "File review incomplete: $($_.Exception.Message)"
        }
    }
    if ($ExtendedReview) {
        try {
            Import-Module -Name $reviewModule -Force -ErrorAction Stop
            Invoke-LabExtendedReview -OutputDirectory $script:RunPath
        } catch { Write-LabWarning "Extended review incomplete: $($_.Exception.Message). No clean verdict can be inferred." }
    }
    if ($AdvancedAudit) {
        try {
            Import-Module -Name $advancedAuditModule -Force -ErrorAction Stop
            Invoke-LabAdvancedAudit -OutputDirectory $script:RunPath -RegistryPlan $registryPlan
        } catch { Write-LabWarning "Advanced audit incomplete: $($_.Exception.Message). Check advanced reports and collected evidence manually." }
    }
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
            Invoke-LabChange 'RemoveAdmin' $member.Name 'Remove unauthorized administrator membership' { Remove-LocalGroupMember -Group $adminGroup.Name -Member $member }
        }
    }
    # Required RDP has its own authorized membership plan; other privilege cleanup remains.
    foreach ($groupSid in Get-LabRestrictedGroups) {
        $group = Get-LocalGroup -SID $groupSid -ErrorAction SilentlyContinue
        if (-not $group) { continue }
        foreach ($member in Get-LocalGroupMember -Group $group.Name) {
            if ([string]$member.SID -match '-501$' -and $groupSid -eq 'S-1-5-32-546') { continue }
            Invoke-LabChange 'RemovePrivilege' "$($group.Name): $($member.Name)" 'Remove unneeded privileged/guest group membership' { Remove-LocalGroupMember -Group $group.Name -Member $member }
        }
    }
    if ($script:Profile.EnableRemoteDesktop) {
        Invoke-LabChange 'RdpMembership' 'Remote Desktop Users' 'Allow authorized employees and remove unauthorized RDP group members' { Set-LabRdpMembership }
    }

    Invoke-LabChange 'AccountPolicy' 'Local security policy' 'Enforce password/lockout policy and restrict selected user rights while preserving service identities' { Set-AccountPolicy }
    foreach ($setting in $registryPlan) {
        Invoke-LabChange 'Registry' "$($setting.Path)\$($setting.Name)" "Set $($setting.Value)" { Set-RegistrySetting $setting }
    }
    Invoke-LabChange 'Firewall' 'All profiles' 'Enable firewall; block unsolicited inbound, allow outbound, preserve core rules and log dropped traffic' {
        Set-NetFirewallProfile -Profile Domain,Private,Public -Enabled True -DefaultInboundAction Block -DefaultOutboundAction Allow -AllowInboundRules True -NotifyOnListen True -LogBlocked True -LogMaxSizeKilobytes 32767
    }
    $rulePatterns = @(Get-LabDisabledFirewallPatterns)
    foreach ($rule in Get-NetFirewallRule -Direction Inbound -Enabled True) {
        $disable = $false
        foreach ($pattern in $rulePatterns) { if ($rule.Name -like $pattern) { $disable = $true } }
        if ($disable -and $rule.DisplayName -notmatch '(?i)ccs|cyberpatriot') { Invoke-LabChange 'FirewallRule' $rule.Name 'Disable unnecessary inbound management/discovery/sharing rule' { Disable-NetFirewallRule -Name $rule.Name } }
    }
    if ($script:Profile.EnableRemoteDesktop) {
        Invoke-LabChange 'RdpFirewall' 'Built-in RDP TCP/UDP rules' 'Enable required RDP rules on the existing listener port; preserve source/profile restrictions' { Set-LabRdpFirewall }
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
    if ($script:Profile.EnableRemoteDesktop) {
        Invoke-LabChange 'RdpServices' 'Remote Desktop services' 'Keep TermService running/automatic and supporting RDP services available' { Set-LabRdpServices }
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
        Invoke-LabChange 'MonitoringService' $name 'Ensure security/event monitoring service is enabled and running' {
            $service = Get-Service -Name $name
            # Avoid unnecessary configuration writes, including to protected services.
            # Automatic also includes delayed automatic startup; preserve that setting.
            if ($service.StartType -ne 'Automatic') { Set-Service -Name $name -StartupType Automatic }
            if ($service.Status -ne 'Running') { Start-Service -Name $name }
            $verified = Get-Service -Name $name
            if ($verified.StartType -ne 'Automatic' -or $verified.Status -ne 'Running') {
                throw "Service $name did not reach Running with Automatic startup (Status=$($verified.Status); StartType=$($verified.StartType))."
            }
        }
    }
    Invoke-LabChange 'SecurityHealth' 'SecurityHealthService' 'Start Windows Security health reporting' { Start-Service -Name SecurityHealthService }
    Invoke-LabChange 'Defender' 'Microsoft Defender' 'Enable realtime, behavior, downloaded-file, script and archive protection; block potentially unwanted apps' {
        Set-MpPreference -DisableRealtimeMonitoring $false -DisableBehaviorMonitoring $false -DisableIOAVProtection $false -DisableScriptScanning $false -DisableArchiveScanning $false -PUAProtection Enabled
    }
    if ($UpdateDefender) { Invoke-LabChange 'DefenderUpdate' 'Signatures' 'Update Microsoft Defender definitions' { Update-MpSignature } }
    if ($QuickScan) { Invoke-LabChange 'DefenderScan' 'Quick scan' 'Run Defender quick scan; its configured remediation may quarantine detections' { Start-MpScan -ScanType QuickScan } }
    if ($UpdateApps) {
        foreach ($packageId in $script:Profile.ApplicationPackageIds) {
            Invoke-LabChange 'ApplicationUpdate' $packageId 'Open the x64 update installer; choose Do not close applications and defer reboot' {
                if (-not (Get-Command winget.exe -ErrorAction SilentlyContinue)) { throw 'WinGet is unavailable; update from the vendor manually.' }
                # Do not install missing apps, accept new agreements, upgrade all, or permit reboot.
                Invoke-Native 'winget.exe' @('upgrade','--id',$packageId,'--exact','--source','winget','--architecture','x64','--interactive') -OutputPath (Join-Path $script:RunPath "$packageId-upgrade.txt") | Out-Null
            }
        }
    }
    if ($InstallSecurityUpdates) { Invoke-LabChange 'WindowsUpdates' 'Windows Update Agent' 'Install only classified security/critical/definition updates; exclude feature/preview builds; never reboot' { Install-LabSecurityUpdates } }
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
    if ($Mode -eq 'Apply' -and -not $WhatIfPreference) {
        Save-Inventory 'after'; $script:RebootNeeded = $true
        if ($script:Profile.EnableRemoteDesktop) {
            try { Save-LabRdpState 'after' } catch { Write-LabWarning "RDP after-state collection: $($_.Exception.Message)" }
        }
    }
} catch {
    $script:Changes.Add([pscustomobject]@{Id='Fatal';Target='Run';Description='Run stopped by a terminating error';Status='Failed';Detail=$_.Exception.Message})
    throw
} finally {
    # Avoid the Windows PowerShell List[object] -> @() conversion bug.
    Save-Json 'changes.json' ($script:Changes.ToArray())
    Save-Json 'warnings.json' ($script:Warnings.ToArray())
    Save-Json 'summary.json' ([pscustomobject]@{Mode=$Mode;WhatIf=[bool]$WhatIfPreference;RebootNeeded=$script:RebootNeeded;Applied=@($script:Changes | Where-Object Status -eq 'Applied').Count;Planned=@($script:Changes | Where-Object Status -eq 'Planned').Count;Failed=@($script:Changes | Where-Object Status -eq 'Failed').Count;ProtectedAccounts=$script:ProtectedNames})
    $failedChanges = @($script:Changes | Where-Object Status -eq 'Failed')
    if ($failedChanges.Count -gt 0) {
        Write-Host 'Failed actions (also saved in changes.json):'
        $failedChanges | Format-List Id,Target,Detail | Out-Host
    }
    Write-Host "Reports saved to $script:RunPath"
    if ($script:RebootNeeded) { Write-Warning 'Restart may be needed. No restart was initiated.' }
}
if (@($script:Changes | Where-Object Status -eq 'Failed').Count -gt 0) { exit 2 }
