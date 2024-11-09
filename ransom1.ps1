# Define registry paths and values for recovery policies
$recoveryKeyPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
$settingsKeyPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer"
$recoveryValueName1 = "DisableAutomaticRestartSignOn"
$recoveryValueName2 = "DisableSystemReset"
$settingsValueName = "NoRecovery"

# Ensure the registry keys exist
if (!(Test-Path $recoveryKeyPath)) {
    New-Item -Path $recoveryKeyPath -Force | Out-Null
}
if (!(Test-Path $settingsKeyPath)) {
    New-Item -Path $settingsKeyPath -Force | Out-Null
}

# Set registry values to disable Reset This PC and recovery options
Set-ItemProperty -Path $recoveryKeyPath -Name $recoveryValueName1 -Value 1
Set-ItemProperty -Path $recoveryKeyPath -Name $recoveryValueName2 -Value 1
Set-ItemProperty -Path $settingsKeyPath -Name $settingsValueName -Value 1

# Function to lock down permissions on registry keys
function Set-RegistryPermissions {
    param (
        [string]$registryPath,
        [string]$owner = "NT AUTHORITY\SYSTEM"
    )

    # Retrieve the ACL and set owner to SYSTEM
    $acl = Get-Acl -Path $registryPath
    $ownerSid = New-Object System.Security.Principal.NTAccount($owner)
    $acl.SetOwner($ownerSid)

    # Remove all existing permissions and grant only SYSTEM full control
    $acl.Access | ForEach-Object { $acl.RemoveAccessRule($_) }
    $accessRule = New-Object System.Security.AccessControl.RegistryAccessRule($ownerSid, "FullControl", "Allow")
    $acl.AddAccessRule($accessRule)

    # Apply the new ACL to the registry key
    Set-Acl -Path $registryPath -AclObject $acl
}

# Lock down permissions on the registry keys
Set-RegistryPermissions -registryPath $recoveryKeyPath
Set-RegistryPermissions -registryPath $settingsKeyPath

Write-Output "The Reset this PC option and recovery options have been disabled, and permissions are locked."
