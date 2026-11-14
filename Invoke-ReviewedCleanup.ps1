#Requires -Version 5.1
#Requires -RunAsAdministrator
[CmdletBinding(SupportsShouldProcess=$true,ConfirmImpact='Medium')]
param([Parameter(Mandatory)][string]$PlanPath,[ValidateSet('Audit','Apply')][string]$Mode='Audit')
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
if ($env:OS -ne 'Windows_NT' -or -not [Environment]::Is64BitProcess -or $PSVersionTable.PSEdition -ne 'Desktop') { throw 'Use elevated 64-bit Windows PowerShell 5.1 at the VM console.' }
if ($env:SESSIONNAME -like 'RDP*' -or (Get-Variable PSSenderInfo -ErrorAction SilentlyContinue)) { throw 'Use the VM console for reviewed cleanup.' }
$plan=Get-Content -LiteralPath $PlanPath -Raw | ConvertFrom-Json
$identity=[Security.Principal.WindowsIdentity]::GetCurrent()
$output=Join-Path $env:ProgramData ('Windows11HardeningLab\Runs\cleanup-'+(Get-Date -Format 'yyyyMMdd-HHmmss')+'-'+[guid]::NewGuid().ToString('N').Substring(0,8))
New-Item -Path $output -ItemType Directory -Force -WhatIf:$false | Out-Null
$acl=New-Object Security.AccessControl.DirectorySecurity
$acl.SetAccessRuleProtection($true,$false)
foreach ($sid in @($identity.User.Value,'S-1-5-18','S-1-5-32-544') | Select-Object -Unique) {
    $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new([Security.Principal.SecurityIdentifier]::new($sid),[Security.AccessControl.FileSystemRights]::FullControl,[Security.AccessControl.InheritanceFlags]'ContainerInherit,ObjectInherit',[Security.AccessControl.PropagationFlags]::None,[Security.AccessControl.AccessControlType]::Allow))
}
Set-Acl -LiteralPath $output -AclObject $acl -WhatIf:$false
Copy-Item -LiteralPath $PlanPath -Destination (Join-Path $output 'cleanup-plan-used.json') -WhatIf:$false
Import-Module (Join-Path $PSScriptRoot 'modules\Lab.Cleanup.psm1') -Force
$result=@(Invoke-LabReviewedCleanup -Plan $plan -OutputDirectory $output -Mode $Mode -WhatIf:$WhatIfPreference)
$result | Format-Table Action,Target,Status -AutoSize | Out-Host
Write-Host "Cleanup reports: $output"
if (@($result | Where-Object Status -eq 'Failed').Count) { $result | Where-Object Status -eq 'Failed' | Format-List | Out-Host; exit 2 }
