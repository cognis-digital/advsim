# advsim installer for Windows PowerShell.
$ErrorActionPreference = "Stop"
Set-Location -Path $PSScriptRoot

$py = if (Get-Command python -ErrorAction SilentlyContinue) { "python" }
      elseif (Get-Command py -ErrorAction SilentlyContinue) { "py" }
      else { $null }

if (-not $py) {
    Write-Error "Python 3.9+ not found. Install it first."
    exit 1
}

Write-Host "Installing advsim with $py ..."
& $py -m pip install --upgrade pip | Out-Null
& $py -m pip install .

Write-Host ""
Write-Host "Installed. Try:  advsim list"
Write-Host "Reminder: advsim is AUTHORIZED-USE-ONLY. See SECURITY_SCOPE.md."
