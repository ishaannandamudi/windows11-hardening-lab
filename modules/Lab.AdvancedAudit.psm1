#Requires -Version 5.1
# Read-only inspection. Only the three report files in OutputDirectory are written.
Set-StrictMode -Version Latest

function Get-LabAuditKey {
    param([string]$Path)
    try { Get-Item -LiteralPath $Path -ErrorAction Stop }
    catch {
        if ($_.CategoryInfo.Category -ne 'ObjectNotFound') { throw }
    }
}

function Get-LabAuditValue {
    param([string]$Path, [string]$Name)
    $key = Get-LabAuditKey $Path
    if ($null -eq $key -or $Name -notin $key.GetValueNames()) {
        return [pscustomobject]@{Path=$Path;Name=$Name;Status='Missing';Value=$null;Type=$null}
    }
    [pscustomobject]@{
        Path=$Path;Name=$Name;Status='Present'
        Value=$key.GetValue($Name,$null,[Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
        Type=[string]$key.GetValueKind($Name)
    }
}

function Compare-LabAuditRegistryTarget {
    param($Actual, $Target)
    if ($Actual.Status -eq 'Missing') { return 'NotExplicitlySet' }
    if ($Actual.Type -ne $Target.Type -or [string]$Actual.Value -cne [string]$Target.Value) { return 'DiffersFromTarget' }
    return 'MatchesExplicitTarget'
}

function Add-LabAuditFinding {
    param([hashtable]$State,[string]$Priority,[string]$Status,[string]$Area,[string]$Target,[string]$Detail)
    $State.Findings.Add([pscustomobject]@{Priority=$Priority;Status=$Status;Area=$Area;Target=$Target;Detail=$Detail})
}

function Invoke-LabAuditSection {
    param([hashtable]$State,[string]$Name,[scriptblock]$Read,[string]$ScopeNote='')
    $timer = [Diagnostics.Stopwatch]::StartNew()
    try {
        $rows = @(& $Read)
        $State.Evidence[$Name] = [pscustomobject]@{Status='Complete';Rows=$rows;Detail='';ScopeNote=$ScopeNote;ElapsedMilliseconds=$timer.ElapsedMilliseconds}
    } catch {
        $State.Evidence[$Name] = [pscustomobject]@{Status='Unknown';Rows=@();Detail=$_.Exception.Message;ScopeNote=$ScopeNote;ElapsedMilliseconds=$timer.ElapsedMilliseconds}
        Add-LabAuditFinding $State 'Review' 'Unknown' $Name 'Collection failed' $_.Exception.Message
    } finally { $timer.Stop() }
}

function Get-LabAuditRegistryRows {
    param([string]$Path,[string[]]$Names=@(),[switch]$Children,[switch]$Grandchildren)
    $root = Get-LabAuditKey $Path
    if ($null -eq $root) { return }
    $keys = @($root)
    if ($Children) {
        $keys = @(Get-ChildItem -LiteralPath $Path -ErrorAction Stop)
        if ($Grandchildren) {
            $keys += @(foreach ($child in @($keys)) { Get-ChildItem -LiteralPath $child.PSPath -ErrorAction Stop })
        }
    }
    foreach ($key in $keys) {
        foreach ($name in $key.GetValueNames()) {
            if ($Names.Count -and $name -notin $Names) { continue }
            Get-LabAuditValue -Path $key.PSPath -Name $name
        }
    }
}

function Invoke-LabAuditNativeRead {
    param([ValidateSet('PortProxy','WinHttpProxy')][string]$Query)
    # Fixed read-only arguments; never interpret commands found in the evidence.
    $arguments = if ($Query -eq 'PortProxy') { @('interface','portproxy','show','all') } else { @('winhttp','show','proxy') }
    $command = Get-Command netsh.exe -CommandType Application -ErrorAction Stop
    $saved = $ErrorActionPreference
    try {
        $ErrorActionPreference = 'Continue'
        $global:LASTEXITCODE = $null
        $output = & $command.Source @arguments 2>&1
        $code = $global:LASTEXITCODE
    } finally { $ErrorActionPreference = $saved }
    if ($null -eq $code -or $code -ne 0) { throw "netsh $Query failed ($code): $($output -join ' ')" }
    [pscustomobject]@{Query=$Query;Output=($output -join [Environment]::NewLine)}
}

function Invoke-LabAdvancedAudit {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$OutputDirectory,[object[]]$RegistryPlan=@())
    if (-not (Test-Path -LiteralPath $OutputDirectory -PathType Container)) { throw 'Advanced audit requires the existing restricted run-report directory.' }
    $state = @{Evidence=[ordered]@{};Findings=(New-Object 'System.Collections.Generic.List[object]')}
    Write-Host '[Inspecting] Optional advanced audit; no security settings are changed.'
    Invoke-LabAuditSection $state 'RegistryTargets' {
        foreach ($target in $RegistryPlan) {
            try {
                $actual = Get-LabAuditValue $target.Path $target.Name
                $status = Compare-LabAuditRegistryTarget $actual $target
                if ($status -eq 'DiffersFromTarget') {
                    Add-LabAuditFinding $state 'High' $status 'RegistryTargets' "$($target.Path)\$($target.Name)" "Observed $($actual.Type) '$($actual.Value)'; profile requests $($target.Type) '$($target.Value)'. This is a stored-value comparison, not an effective-policy or scoring verdict."
                }
                [pscustomobject]@{Path=$target.Path;Name=$target.Name;Status=$status;Actual=$actual.Value;ActualType=$actual.Type;Target=$target.Value;TargetType=$target.Type}
            } catch {
                Add-LabAuditFinding $state 'Review' 'Unknown' 'RegistryTargets' "$($target.Path)\$($target.Name)" $_.Exception.Message
                [pscustomobject]@{Path=$target.Path;Name=$target.Name;Status='Unknown';Actual=$null;ActualType=$null;Target=$target.Value;TargetType=$target.Type}
            }
        }
    } 'Missing values are NotExplicitlySet, not automatically insecure. Defaults, policy precedence and reboot requirements need separate verification.'

    Invoke-LabAuditSection $state 'AdditionalPolicies' {
        $policies = @(
            @('HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer','AlwaysInstallElevated',1,'Machine-side elevated MSI policy is enabled. Review promptly; the unsafe condition also requires user-side policy 1.'),
            @('HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint','RestrictDriverInstallationToAdministrators',0,'Administrator-only Point and Print driver installation is explicitly disabled.'),
            @('HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient','EnableMulticast',1,'LLMNR is explicitly enabled. Consider disabling it only after checking name-resolution requirements.'),
            @('HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters','RestrictNullSessAccess',0,'Anonymous named-pipe/share restriction is explicitly disabled; review required exceptions before changing it.')
        )
        foreach ($p in $policies) {
            $actual = Get-LabAuditValue $p[0] $p[1]
            if ($actual.Status -eq 'Present' -and [string]$actual.Value -eq [string]$p[2]) {
                Add-LabAuditFinding $state 'High' 'NeedsReview' 'AdditionalPolicies' "$($p[0])\$($p[1])" $p[3]
            }
            $actual
        }
    } 'Only explicit values are flagged. Absence can select a Windows default; no universal remediation is inferred.'

    Invoke-LabAuditSection $state 'LoadedUserScopes' {
        Get-ChildItem -LiteralPath 'Registry::HKEY_USERS' -ErrorAction Stop |
            Where-Object {$_.PSChildName -match '^S-1-5-21-(\d+-){3}\d+$'} | Select-Object PSPath,PSChildName
    } 'Only already-loaded local/domain-style SID hives are inspected. Offline NTUSER.DAT files are not loaded; other user profiles remain unexamined.'
    Invoke-LabAuditSection $state 'UserPoliciesAndProxy' {
        if ($state.Evidence['LoadedUserScopes'].Status -ne 'Complete') { throw 'Loaded user hives could not be enumerated.' }
        foreach ($userHive in $state.Evidence['LoadedUserScopes'].Rows) {
            Get-LabAuditRegistryRows -Path "$($userHive.PSPath)\Software\Policies\Microsoft\Windows\Installer" -Names @('AlwaysInstallElevated')
            Get-LabAuditRegistryRows -Path "$($userHive.PSPath)\Software\Microsoft\Windows\CurrentVersion\Internet Settings" -Names @('ProxyEnable','ProxyServer','ProxyOverride','AutoConfigURL')
        }
    } 'Per-user proxy data is observational. AutoConfigURL and proxy requirements can be legitimate.'

    Invoke-LabAuditSection $state 'ImageExecutionHooks' {
        foreach ($view in @('SOFTWARE','SOFTWARE\WOW6432Node')) {
            Get-LabAuditRegistryRows -Path "HKLM:\$view\Microsoft\Windows NT\CurrentVersion\Image File Execution Options" -Children -Grandchildren -Names @('Debugger','GlobalFlag','UseFilter','FilterFullPath')
            Get-LabAuditRegistryRows -Path "HKLM:\$view\Microsoft\Windows NT\CurrentVersion\SilentProcessExit" -Names @('MonitorProcess','ReportingMode')
            Get-LabAuditRegistryRows -Path "HKLM:\$view\Microsoft\Windows NT\CurrentVersion\SilentProcessExit" -Children -Names @('MonitorProcess','ReportingMode')
        }
    } 'Both registry views and IFEO filter subkeys are inspected. Debugger/monitor entries can be legitimate diagnostics; nothing is launched or removed.'
    foreach ($row in $state.Evidence['ImageExecutionHooks'].Rows) {
        if ($row.Name -in @('Debugger','MonitorProcess') -and -not [string]::IsNullOrWhiteSpace([string]$row.Value)) {
            Add-LabAuditFinding $state 'High' 'NeedsReview' 'ImageExecutionHooks' "$($row.Path)\$($row.Name)" "Configured command: $($row.Value). Verify purpose and authorization; presence does not prove malware."
        }
    }
    Invoke-LabAuditSection $state 'LogonAndDllHooks' {
        foreach ($view in @('SOFTWARE','SOFTWARE\WOW6432Node')) {
            Get-LabAuditRegistryRows -Path "HKLM:\$view\Microsoft\Windows NT\CurrentVersion\Windows" -Names @('AppInit_DLLs','LoadAppInit_DLLs','RequireSignedAppInit_DLLs')
            Get-LabAuditRegistryRows -Path "HKLM:\$view\Microsoft\Windows\CurrentVersion\Run"
            Get-LabAuditRegistryRows -Path "HKLM:\$view\Microsoft\Windows\CurrentVersion\RunOnce"
        }
        # Whitelist values: never export Winlogon DefaultPassword or stored secrets.
        Get-LabAuditRegistryRows -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Names @('Shell','Userinit')
        if ($state.Evidence['LoadedUserScopes'].Status -ne 'Complete') { throw 'Loaded user hives could not be enumerated; logon coverage is incomplete.' }
        foreach ($userHive in $state.Evidence['LoadedUserScopes'].Rows) {
            foreach ($suffix in @('Run','RunOnce')) {
                Get-LabAuditRegistryRows -Path "$($userHive.PSPath)\Software\Microsoft\Windows\CurrentVersion\$suffix"
            }
        }
    } 'Selected locations only; this is not a complete Autoruns replacement or DLL-loadability analysis.'

    $wmiClasses = [ordered]@{
        WmiFilters=@('__EventFilter',@('Name','Query','QueryLanguage','EventNamespace'))
        WmiCommandConsumers=@('CommandLineEventConsumer',@('Name','ExecutablePath','CommandLineTemplate','WorkingDirectory'))
        WmiScriptConsumers=@('ActiveScriptEventConsumer',@('Name','ScriptingEngine','ScriptFilename','ScriptText'))
        WmiBindings=@('__FilterToConsumerBinding',@('Filter','Consumer','DeliverSynchronously','MaintainSecurityContext'))
    }
    foreach ($entry in $wmiClasses.GetEnumerator()) {
        Invoke-LabAuditSection $state $entry.Key {
            Get-CimInstance -Namespace 'root/subscription' -ClassName $entry.Value[0] -OperationTimeoutSec 10 -ErrorAction Stop | Select-Object -Property $entry.Value[1]
        } 'root/subscription only; command/script consumers and bindings are evidence, including potentially legitimate management entries. Queries are read-only with a per-query timeout.'
        foreach ($row in $state.Evidence[$entry.Key].Rows) {
            Add-LabAuditFinding $state 'Review' 'NeedsReview' $entry.Key 'Permanent WMI subscription component' 'Review the filters, consumers and bindings together in advanced-evidence.json. Their presence alone is not proof of a backdoor.'
        }
    }
    Invoke-LabAuditSection $state 'BitsJobs' {
        Get-BitsTransfer -AllUsers -ErrorAction Stop | Select-Object JobId,DisplayName,OwnerAccount,JobState,TransferType,CreationTime,ModificationTime
    } 'Existing job metadata only. URLs, credentials and callbacks are not read; jobs are not resumed, completed or canceled. Windows/app updates legitimately use BITS.'
    Invoke-LabAuditSection $state 'DnsServers' {
        Get-DnsClientServerAddress -ErrorAction Stop | Select-Object InterfaceAlias,InterfaceIndex,AddressFamily,ServerAddresses
    }
    Invoke-LabAuditSection $state 'HostsEntries' {
        Get-Content -LiteralPath (Join-Path $env:SystemRoot 'System32\drivers\etc\hosts') -ErrorAction Stop |
            ForEach-Object { ($_ -split '#',2)[0].Trim() } | Where-Object {$_}
    } 'Noncomment lines only. Local overrides can be legitimate; no lookup or network probe is performed.'
    Invoke-LabAuditSection $state 'PortProxy' { Invoke-LabAuditNativeRead PortProxy } 'Localized netsh output is retained for manual inspection without fragile text parsing.'
    Invoke-LabAuditSection $state 'WinHttpProxy' { Invoke-LabAuditNativeRead WinHttpProxy } 'WinHTTP proxy is separate from browser/per-user proxy settings.'
    Invoke-LabAuditSection $state 'DefenderStatus' {
        Get-MpComputerStatus -ErrorAction Stop | Select-Object AMRunningMode,AMServiceEnabled,AntivirusEnabled,RealTimeProtectionEnabled,BehaviorMonitorEnabled,IoavProtectionEnabled,IsTamperProtected,AntivirusSignatureLastUpdated
    }
    foreach ($row in $state.Evidence['DefenderStatus'].Rows) {
        if ($row.AntivirusEnabled -eq $false -or $row.RealTimeProtectionEnabled -eq $false) {
            Add-LabAuditFinding $state 'High' 'NeedsReview' 'DefenderStatus' 'Protection is not active' 'Check running mode, third-party antivirus, policy and tamper protection. A successful preference write does not prove active protection.'
        }
    }
    Invoke-LabAuditSection $state 'DefenderCloud' {
        Get-MpPreference -ErrorAction Stop | Select-Object MAPSReporting,SubmitSamplesConsent,DisableBlockAtFirstSeen
    } 'Cloud/sample submission changes need scenario approval. Existing exclusions are already in before-exclusions.json; this module does not duplicate or clear them.'

    $findings = @($state.Findings.ToArray() | Sort-Object @{Expression={if ($_.Priority -eq 'High') {0} else {1}}},Area,Target)
    ConvertTo-Json -InputObject $state.Evidence -Depth 12 | Set-Content -LiteralPath (Join-Path $OutputDirectory 'advanced-evidence.json') -Encoding UTF8
    ConvertTo-Json -InputObject $findings -Depth 6 | Set-Content -LiteralPath (Join-Path $OutputDirectory 'advanced-findings.json') -Encoding UTF8
    $review = @(
        'Advanced audit: BEFORE remediation. High means review first, not confirmed malware or points.'
        'Read forensic questions and the current scenario README before acting on evidence.'
        'This is selected coverage, not a complete security/compliance verdict. No findings does not mean clean.'
        'Only loaded user hives and root/subscription WMI were inspected. Collection failures are Unknown.'
        'Registry targets are stored values, not effective policy; absent values may have secure defaults.'
        ''
        'COLLECTION STATUS (details and scope in advanced-evidence.json):'
        foreach ($section in $state.Evidence.GetEnumerator()) { '{0}: {1}; {2} rows; {3} ms' -f $section.Key,$section.Value.Status,$section.Value.Rows.Count,$section.Value.ElapsedMilliseconds }
        ''
        'PRIORITIZED REVIEW:'
        foreach ($finding in $findings) { "[$($finding.Priority)] [$($finding.Status)] $($finding.Area): $($finding.Target)`r`n$($finding.Detail)`r`n" }
        'Also inspect PortProxy, WinHttpProxy, UserPoliciesAndProxy, DnsServers, HostsEntries, BitsJobs, LogonAndDllHooks and DefenderCloud evidence. These are collected without a maliciousness verdict.'
    )
    $review | Set-Content -LiteralPath (Join-Path $OutputDirectory 'advanced-review.txt') -Encoding UTF8
    Write-Host "Advanced audit saved $($findings.Count) review items. Open advanced-review.txt; Unknown means a check could not be completed."
}

Export-ModuleMember -Function Invoke-LabAdvancedAudit
