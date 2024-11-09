# Function to check and terminate Reset processes
function Block-ResetProcess {
    $resetProcesses = @("SystemReset.exe", "SystemReset2.exe")  # Common processes for reset
    foreach ($process in $resetProcesses) {
        $processInfo = Get-Process -Name $process -ErrorAction SilentlyContinue
        if ($processInfo) {
            Write-Output "$process is running. Terminating..."
            Stop-Process -Name $process -Force
        }
    }
}

# Run the function to block the reset process
Block-ResetProcess
Write-Output "Reset process has been blocked."
