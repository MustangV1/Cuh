# Define registry path for system recovery policies
$recoveryKeyPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
$recoveryValueName1 = "DisableAutomaticRestartSignOn"
$recoveryValueName2 = "DisableSystemReset"

# Ensure the registry key exists
if (!(Test-Path $recoveryKeyPath)) {
    New-Item -Path $recoveryKeyPath -Force | Out-Null
}

# Use takeown and icacls commands to gain full control temporarily
& cmd.exe /c "takeown /f C:\Windows\System32\config\SOFTWARE" | Out-Null
& cmd.exe /c "icacls C:\Windows\System32\config\SOFTWARE /grant administrators:F /t" | Out-Null

# Set the registry values to disable Reset This PC option
Set-ItemProperty -Path $recoveryKeyPath -Name $recoveryValueName1 -Value 1
Set-ItemProperty -Path $recoveryKeyPath -Name $recoveryValueName2 -Value 1

# Take ownership of the registry key and set permissions to lock it down
$identityReference = [System.Security.Principal.NTAccount]"SYSTEM"

# Retrieve and modify ACL for the Recovery key
$aclRecovery = Get-Acl -Path $recoveryKeyPath
$aclRecovery.SetOwner($identityReference)
$aclRecovery.Access | ForEach-Object { $aclRecovery.RemoveAccessRule($_) }

# Grant only SYSTEM full control to prevent any modifications
$accessRuleRecovery = New-Object System.Security.AccessControl.RegistryAccessRule($identityReference, "FullControl", "Allow")
$aclRecovery.AddAccessRule($accessRuleRecovery)

# Apply the modified ACL to the recovery policy key
Set-Acl -Path $recoveryKeyPath -AclObject $aclRecovery

Write-Output "The Reset this PC option has been disabled, and permissions are locked to prevent any changes."