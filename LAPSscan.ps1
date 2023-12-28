Import-Module ActiveDirectory

# Check if LAPS is implemented on the system

# Check for LAPS registry keys
$lapsRegistryPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy\AppMgmt"
$lapsRegistryKeys = Get-Item -LiteralPath $lapsRegistryPath -ErrorAction SilentlyContinue

# Check for LAPS DLL file
$lapsDllPath = "C:\Program Files\LAPS\CSE\AdmPwd.dll"
$lapsDllFile = Test-Path $lapsDllPath

if ($lapsRegistryKeys -ne $null -and $lapsDllFile) {
    Write-Host "LAPS is implemented on this system."
} else {
    Write-Host "LAPS is not implemented on this system."
}