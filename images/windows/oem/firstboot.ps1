# =====================================================================
# C:\OEM\firstboot.ps1
#
# Called from install.bat on first logon. Edit freely.
# Output is appended to C:\OEM\install.log.
# =====================================================================

$ErrorActionPreference = 'Continue'

Write-Host "==> First boot starting at $(Get-Date -Format o)"
Write-Host "==> Hostname: $env:COMPUTERNAME"
Write-Host "==> User:     $env:USERNAME"

# ---- put your initialization logic below --------------------------------

# Example: install Chocolatey
# Set-ExecutionPolicy Bypass -Scope Process -Force
# [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072
# iex ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))

# Example: install some apps via winget
# winget install --silent --accept-source-agreements --accept-package-agreements Git.Git
# winget install --silent --accept-source-agreements --accept-package-agreements Microsoft.VisualStudioCode

# Example: enable Developer Mode
# New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModelUnlock" `
#                  -Name "AllowDevelopmentWithoutDevLicense" -PropertyType DWord -Value 1 -Force

# Drop a marker so you can verify init ran.
"Initialized at $(Get-Date -Format o)" | Set-Content -Path "C:\OEM\firstboot.done"

# -------------------------------------------------------------------------

Write-Host "==> First boot finished at $(Get-Date -Format o)"
