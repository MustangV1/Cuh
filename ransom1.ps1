# Define registry path for system recovery policies
$recoveryKeyPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
$recoveryValueName1 = "DisableAutomaticRestartSignOn"
$recoveryValueName2 = "DisableSystemReset"

# Function to take ownership and set permissions entirely within PowerShell
function Set-RegistryPermissions {
    param (
        [string]$registryPath,
        [string]$owner = "NT AUTHORITY\SYSTEM"
    )

    # Ensure the registry path exists
    if (!(Test-Path $registryPath)) {
        New-Item -Path $registryPath -Force | Out-Null
    }

    # Retrieve the current ACL of the registry key
    $acl = Get-Acl -Path $registryPath

    # Set the owner to SYSTEM
    $ownerSid = New-Object System.Security.Principal.NTAccount($owner)
    $acl.SetOwner($ownerSid)

    # Remove all existing access rules to restrict access
    $acl.Access | ForEach-Object { $acl.RemoveAccessRule($_) }

    # Allow only SYSTEM full control
    $accessRule = New-Object System.Security.AccessControl.RegistryAccessRule($ownerSid, "FullControl", "Allow")
    $acl.AddAccessRule($accessRule)

    # Apply the modified ACL back to the registry path
    Set-Acl -Path $registryPath -AclObject $acl
}

# Set the registry values to disable Reset This PC option
Set-ItemProperty -Path $recoveryKeyPath -Name $recoveryValueName1 -Value 1
Set-ItemProperty -Path $recoveryKeyPath -Name $recoveryValueName2 -Value 1

# Take ownership of the recovery policy registry key and restrict permissions
Set-RegistryPermissions -registryPath $recoveryKeyPath

Write-Output "The Reset this PC option has been disabled, and permissions are locked to prevent any changes."
