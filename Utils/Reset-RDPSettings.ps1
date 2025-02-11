[CmdletBinding()]
param(
    [Parameter(Mandatory=$false,
               Position=0,
               HelpMessage="Enter the target computer name where RDP settings should be reset")]
    [string]$ComputerName
)

# Function to display usage
function Show-Usage {
    Write-Host "Reset-RDPSettings.ps1 - Resets RDP settings on a remote Windows Server 2022 machine"
    Write-Host ""
    Write-Host "Usage: Reset-RDPSettings.ps1 -ComputerName <server_name>"
    Write-Host ""
    Write-Host "Parameters:"
    Write-Host "  -ComputerName   Required. The name of the remote computer to reset RDP settings on."
    Write-Host ""
    Write-Host "Example:"
    Write-Host "  .\Reset-RDPSettings.ps1 -ComputerName SERVER01"
    exit 1
}

# Function to log actions
function Write-Log {
    param($Message)
    Write-Host "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] $Message"
}

# Show usage if no parameters or help is requested
if (-not $ComputerName -or $args -contains "-help" -or $args -contains "/?") {
    Show-Usage
}

# Validate computer name is not empty after trimming
if ([string]::IsNullOrWhiteSpace($ComputerName)) {
    Write-Error "ComputerName cannot be empty or whitespace."
    Show-Usage
}

# Main script block that contains all the RDP reset logic
$resetScript = {
    # Function to log actions (needed inside the script block)
    function Write-Log {
        param($Message)
        Write-Host "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] $Message"
    }

    Write-Log "Starting RDP settings reset to default values..."

    # 1. Reset RDP Protocol Settings
    Write-Log "Resetting RDP Protocol settings..."
    Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -Name 'SecurityLayer' -Value 2
    Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -Name 'MinEncryptionLevel' -Value 2
    Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -Name 'UserAuthentication' -Value 1

    # 2. Reset RDP Service Settings
    Write-Log "Resetting RDP Service settings..."
    Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' -Name 'fDenyTSConnections' -Value 0
    Enable-NetFirewallRule -DisplayGroup "Remote Desktop"

    # 3. Reset TLS Settings to Default
    Write-Log "Resetting TLS settings..."
    $protocols = @('TLS 1.0', 'TLS 1.1', 'TLS 1.2', 'TLS 1.3')
    $registryPaths = @(
        'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols',
        'HKLM:\SOFTWARE\Microsoft\.NETFramework\v4.0.30319',
        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\.NETFramework\v4.0.30319'
    )

    foreach ($protocol in $protocols) {
        $registryPath = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\$protocol"
        if (Test-Path $registryPath) {
            Remove-Item -Path $registryPath -Recurse -Force
        }
    }

    # 4. Reset SSL Cipher Suites to Default
    Write-Log "Resetting SSL Cipher Suites..."
    Remove-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Cryptography\Configuration\SSL\00010002' -Name 'Functions' -ErrorAction SilentlyContinue

    $defaultCiphers = @(
        'TLS_AES_256_GCM_SHA384',
        'TLS_AES_128_GCM_SHA256',
        'TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384',
        'TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256',
        'TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384',
        'TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256'
    )

    $cipherSuitesOrder = [String]::Join(',', $defaultCiphers)
    Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Cryptography\Configuration\SSL\00010002' -Name 'Functions' -Value $cipherSuitesOrder -Type String

    # 5. Enable RDP Services
    Write-Log "Enabling RDP Services..."
    $services = @(
        'TermService',          # Remote Desktop Services
        'UmRdpService',        # Remote Desktop Services UserMode Port Redirector
        'SessionEnv'           # Remote Desktop Configuration
    )

    foreach ($service in $services) {
        Set-Service -Name $service -StartupType Automatic
        Start-Service -Name $service
    }

    # 6. Reset Group Policy Settings
    Write-Log "Resetting Group Policy Settings..."
    gpupdate /force

    # 7. Restart RDP Services
    Write-Log "Restarting RDP Services..."
    Restart-Service -Name TermService -Force

    Write-Log "RDP reset script completed. Please restart the server to apply all changes."
    Write-Log "After restart, verify RDP connectivity and security settings."
}

# Main execution logic
try {
    Write-Log "Attempting to connect to remote computer: $ComputerName"
    
    # Test connection first
    if (-not (Test-Connection -ComputerName $ComputerName -Quiet -Count 1)) {
        throw "Cannot connect to remote computer: $ComputerName"
    }

    # Execute the script block remotely
    Invoke-Command -ComputerName $ComputerName -ScriptBlock $resetScript -ErrorAction Stop
    Write-Log "Successfully completed RDP reset on remote computer: $ComputerName"
}
catch {
    Write-Error "Error executing script: $_"
    exit 1
}
