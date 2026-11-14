#Requires -Version 5.1
#Requires -RunAsAdministrator
# Short launcher: includes the media scan and selected extended/advanced inspection.
[CmdletBinding()]
param([string]$ConfigPath='')
$ErrorActionPreference='Stop'
& (Join-Path $PSScriptRoot 'Invoke-Windows11LabHardening.ps1') -ConfigPath $ConfigPath -Mode Audit -ExtendedReview
