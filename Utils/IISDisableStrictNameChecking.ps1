[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [string]$ComputerName
)

# Display usage if no parameters provided
if (-not $PSBoundParameters.Count) {
    Write-Host "Usage: script.ps1 [-ComputerName <remote_computer_name>]"
    Write-Host "Description: Configures HTTP Parameters registry settings."
    Write-Host "Parameters:"
    Write-Host "  -ComputerName : Optional. The name of the remote computer to configure."
    Write-Host "Example: .\script.ps1 -ComputerName SERVER01"
    exit
}

try {
    # Build the registry path
    $registryPath = "SYSTEM\CurrentControlSet\Services\HTTP\Parameters"
    
    if ($ComputerName) {
        # For remote computer
        $fullPath = "HKLM:\\" + $registryPath
        
        # Create HTTP parameters key if it doesn't exist
        if (-not (Test-Path "\\$ComputerName\HKLM:\$registryPath")) {
            Write-Host "Creating registry key on $ComputerName..."
            Invoke-Command -ComputerName $ComputerName -ScriptBlock {
                New-Item -Path $using:fullPath -Force
            }
        }

        # Add the DisableStrictNameChecking value
        Write-Host "Setting DisableStrictNameChecking value on $ComputerName..."
        Invoke-Command -ComputerName $ComputerName -ScriptBlock {
            New-ItemProperty -Path $using:fullPath `
                -Name "DisableStrictNameChecking" `
                -Value 1 `
                -PropertyType DWORD `
                -Force
        }
    } else {
        # For local computer
        $fullPath = "HKLM:\$registryPath"
        
        # Create HTTP parameters key if it doesn't exist
        if (-not (Test-Path $fullPath)) {
            Write-Host "Creating registry key locally..."
            New-Item -Path $fullPath -Force
        }

        # Add the DisableStrictNameChecking value
        Write-Host "Setting DisableStrictNameChecking value locally..."
        New-ItemProperty -Path $fullPath `
            -Name "DisableStrictNameChecking" `
            -Value 1 `
            -PropertyType DWORD `
            -Force
    }

    Write-Host "Configuration completed successfully."
} catch {
    Write-Error "An error occurred: $_"
    exit 1
}
