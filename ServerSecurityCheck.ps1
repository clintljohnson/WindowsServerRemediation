<#
.SYNOPSIS
    Performs security checks on Windows Server and optionally fixes issues.

.DESCRIPTION
    This script runs various security checks on a Windows Server and generates a report.
    It can optionally fix detected issues with user confirmation.

.PARAMETER FixWarnings
    If specified, prompts to fix any warnings that are found.

.PARAMETER GenerateReport
    If specified, generates a CSV report of all check results.

.PARAMETER OutputPath
    Specifies the path for the CSV report. Defaults to ".\SecurityReport.csv"

.PARAMETER SkipChecks
    Specifies a comma-separated list of check numbers to skip.

.PARAMETER CheckOnly
    Specifies a comma-separated list of check numbers to run.

.PARAMETER Force
    If specified, automatically answers yes to all fix prompts.

.EXAMPLE
    .\ServerSecurityCheck.ps1
    Runs all security checks without fixing or generating a report.

.EXAMPLE
    .\ServerSecurityCheck.ps1 -FixWarnings -Verbose
    Runs checks with detailed output and prompts to fix any issues found.
    Shows verbose output during execution.

.EXAMPLE
    .\ServerSecurityCheck.ps1 -GenerateReport -OutputPath "C:\Reports\security.csv"
    Runs checks and saves results to the specified CSV file.

.EXAMPLE
    .\ServerSecurityCheck.ps1 -Verbose
    Runs all checks with detailed logging of each step in the process.
#>

[CmdletBinding()]
param (
    [Parameter(Mandatory=$false)]
    [string[]]$TargetServers,
    
    [Parameter(Mandatory=$false)]
    [switch]$ShowWarningsOnly,
    
    [Parameter(Mandatory=$false)]
    [switch]$FixWarnings,
    
    [Parameter(Mandatory=$false)]
    [string]$OutputPath = ".\SecurityReport.csv",

    [Parameter(Mandatory=$false)]
    [string]$SkipChecks,

    [Parameter(Mandatory=$false)]
    [string]$CheckOnly,

    [Parameter(Mandatory=$false)]
    [switch]$Force
)

# Add this function near the top of the script, after the param block
function Show-Help {
    $helpText = @"
USAGE:
    .\ServerSecurityCheck.ps1 -TargetServers <server1,server2,...> [-ShowWarningsOnly] [-FixWarnings] [-Force] [-OutputPath <path>] [-Verbose]

PARAMETERS:
    -TargetServers    Required. Comma-separated list of servers to check, or (Get-Content servers.txt)
    -ShowWarningsOnly Optional. Only display checks that resulted in warnings.
    -FixWarnings      Optional. Prompt to fix any warnings that are found.
    -Force            Optional. Automatically answer yes to all fix prompts.
    -OutputPath       Optional. Path to save the CSV report. Default: .\SecurityReport.csv
    -SkipChecks       Optional. Comma-separated list of check numbers to skip.
    -CheckOnly        Optional. Comma-separated list of check numbers to run exclusively.
    -Verbose          Optional. Show detailed progress information.

EXAMPLES:
    # Run all checks on multiple servers
    .\ServerSecurityCheck.ps1 -TargetServers "SERVER01","SERVER02","SERVER03"

    # Run checks and fix warnings on multiple servers
    .\ServerSecurityCheck.ps1 -TargetServers "SERVER01","SERVER02" -FixWarnings

    # Using a text file with server names
    .\ServerSecurityCheck.ps1 -TargetServers (Get-Content servers.txt)
"@

    Write-Host $helpText
    exit 0
}

# Validate mutually exclusive parameters
if ($SkipChecks -and $CheckOnly) {
    Write-Error "The parameters -SkipChecks and -CheckOnly cannot be used together. Please use only one of these parameters."
    exit 1
}

# Clear any existing variables that might interfere with the script
$scriptVars = @(
    'results', 'warningsFound', 'checks', 'skipCheckNumbers', 
    'checkCount', 'totalChecks', 'clearLine', 'session'
)
$scriptVars | ForEach-Object {
    if (Get-Variable -Name $_ -ErrorAction SilentlyContinue) {
        Remove-Variable -Name $_ -Force -ErrorAction SilentlyContinue
        Write-Verbose "Cleared variable: $_"
    }
}

# Import all check and fix functions
$functionPath = Join-Path $PSScriptRoot "functions"
Write-Verbose "Loading functions from: $functionPath"

# Ensure the functions directory exists
if (-not (Test-Path $functionPath)) {
    Write-Error "Functions directory not found at: $functionPath"
    exit 1
}

# Load all PS1 files from subdirectories, starting with utility functions
$utilityPath = Join-Path $functionPath "utils"
if (Test-Path $utilityPath) {
    Get-ChildItem -Path $utilityPath -Filter "*.ps1" | ForEach-Object {
        try {
            Write-Verbose "Loading utility function: $($_.FullName)"
            . $_.FullName
        }
        catch {
            Write-Error "Failed to load utility function $($_.FullName): $_"
            exit 1
        }
    }
}

# Then load check and fix functions
@("checks", "fixes") | ForEach-Object {
    $subPath = Join-Path $functionPath $_
    if (Test-Path $subPath) {
        Get-ChildItem -Path $subPath -Filter "*.ps1" | ForEach-Object {
            try {
                Write-Verbose "Loading function: $($_.FullName)"
                . $_.FullName
            }
            catch {
                Write-Error "Failed to load function $($_.FullName): $_"
                exit 1
            }
        }
    }
}

# Verify required functions are loaded
$requiredFunctions = @('Write-Report', 'Handle-Fixes')
foreach ($func in $requiredFunctions) {
    if (-not (Get-Command -Name $func -ErrorAction SilentlyContinue)) {
        Write-Error "Required function '$func' not found. Please ensure all utility functions are present in the functions/utils directory."
        exit 1
    }
}

# Initialize results array
$results = @()

# Define checks in numerical order based on the checklist
$global:checks = @(
    @{ Number = 1;  Function = "Check-SystemUpdates" },
    @{ Number = 2;  Function = "Check-OperatingSystemRight" },
    @{ Number = 3;  Function = "Check-RemoteRegistry" },
    @{ Number = 4;  Function = "Check-RemoteAssistance" },
    @{ Number = 5;  Function = "Check-AutorunBehavior" },
    @{ Number = 6;  Function = "Check-AnonymousPipes" },
    @{ Number = 7;  Function = "Check-AutoplayStatus" },
    @{ Number = 8;  Function = "Check-RecoveryConsoleLogon" },
    @{ Number = 9;  Function = "Check-VolumeFileSystem" },
    @{ Number = 10; Function = "Check-DebugPrograms" },
    @{ Number = 11; Function = "Check-CreateToken" },
    @{ Number = 12; Function = "Check-InstallerPrivileges" },
    @{ Number = 13; Function = "Check-AutoLogon" },
    @{ Number = 14; Function = "Check-SNMPSecurity" },
    @{ Number = 15; Function = "Check-WarningBanner" },
    @{ Number = 16; Function = "Check-AdminPasswordComplexity" },
    @{ Number = 17; Function = "Check-AdminAccountName" },
    @{ Number = 18; Function = "Check-AccountLockoutSettings" },
    @{ Number = 19; Function = "Check-GuestAccount" },
    @{ Number = 20; Function = "Check-LocalUsers" },
    @{ Number = 21; Function = "Check-AnonymousSettings" },
    @{ Number = 22; Function = "Check-LANMANHash" },
    @{ Number = 23; Function = "Check-UnnecessaryServices" },
    @{ Number = 24; Function = "Check-EventLogSettings" },
    @{ Number = 25; Function = "Check-PasswordRestrictions" },
    @{ Number = 26; Function = "Check-TLSProtocols" },
    @{ Number = 27; Function = "Check-CBCCiphers" },
    @{ Number = 28; Function = "Check-WeakCiphers" },
    @{ Number = 29; Function = "Check-SMBSigning" },
    @{ Number = 30; Function = "Check-ForwardSecrecyCiphers" },
    @{ Number = 31; Function = "Check-TCPTimestamps" },
    @{ Number = 32; Function = "Check-NTLMv1Auth" },
    @{ Number = 33; Function = "Check-StaticKeyCiphers" },
    @{ Number = 34; Function = "Check-RDPFIPSCompliance" },
    @{ Number = 35; Function = "Check-HMACAlgorithms" },
    @{ Number = 36; Function = "Check-MD5SHA1Ciphers" },
    @{ Number = 37; Function = "Check-3DESCiphers" },
    @{ Number = 38; Function = "Check-RPCAuthentication" },
    @{ Number = 39; Function = "Check-AdminShares" },
    @{ Number = 40; Function = "Check-ServiceAccounts" },
    @{ Number = 41; Function = "Check-DCERPCEndpoints" },
    @{ Number = 42; Function = "Check-WinVerifyTrust" },
    @{ Number = 43; Function = "Check-RDPCipherSuites" },
    @{ Number = 44; Function = "Check-RDPCertificate" },
    @{ Number = 45; Function = "Check-SMBv1Protocol" }
    #@{ Number = 46; Function = "Check-HTTPOptions" }
) | Sort-Object { [int]$_.Number }

# Define corresponding fixes in numerical order
$global:fixes = @(
    #@{ Number = 1;  Function = "Fix-SystemUpdates" },
    #@{ Number = 2;  Function = "Fix-OperatingSystemRight" },
    @{ Number = 3;  Function = "Fix-RemoteRegistry" },
    @{ Number = 4;  Function = "Fix-RemoteAssistance" },
    @{ Number = 5;  Function = "Fix-AutorunBehavior" },
    @{ Number = 6;  Function = "Fix-AnonymousPipes" },
    @{ Number = 7;  Function = "Fix-AutoplayStatus" },
    @{ Number = 8;  Function = "Fix-RecoveryConsoleLogon" },
    @{ Number = 9;  Function = "Fix-VolumeFileSystem" },
    @{ Number = 10; Function = "Fix-DebugPrograms" },
    @{ Number = 11; Function = "Fix-CreateToken" },
    @{ Number = 12; Function = "Fix-InstallerPrivileges" },
    @{ Number = 13; Function = "Fix-AutoLogon" },
    @{ Number = 14; Function = "Fix-SNMPSecurity" },
    @{ Number = 15; Function = "Fix-WarningBanner" },
    @{ Number = 16; Function = "Fix-AdminPasswordComplexity" },
    @{ Number = 17; Function = "Fix-AdminAccountName" },
    @{ Number = 18; Function = "Fix-AccountLockoutSettings" },
    @{ Number = 19; Function = "Fix-GuestAccount" },
    @{ Number = 20; Function = "Fix-LocalUsers" },
    @{ Number = 21; Function = "Fix-AnonymousSettings" },
    @{ Number = 22; Function = "Fix-LANMANHash" },
    @{ Number = 23; Function = "Fix-UnnecessaryServices" },
    @{ Number = 24; Function = "Fix-EventLogSettings" },
    @{ Number = 25; Function = "Fix-PasswordRestrictions" },
    @{ Number = 26; Function = "Fix-TLSProtocols" },
    @{ Number = 27; Function = "Fix-CBCCiphers" },
    @{ Number = 28; Function = "Fix-WeakCiphers" },
    @{ Number = 29; Function = "Fix-SMBSigning" },
    @{ Number = 30; Function = "Fix-ForwardSecrecyCiphers" },
    @{ Number = 31; Function = "Fix-TCPTimestamps" },
    @{ Number = 32; Function = "Fix-NTLMv1Auth" },
    @{ Number = 33; Function = "Fix-StaticKeyCiphers" },
    @{ Number = 34; Function = "Fix-RDPFIPSCompliance" },
    @{ Number = 35; Function = "Fix-HMACAlgorithms" },
    @{ Number = 36; Function = "Fix-MD5SHA1Ciphers" },
    @{ Number = 37; Function = "Fix-3DESCiphers" },
    @{ Number = 38; Function = "Fix-RPCAuthentication" },
    @{ Number = 39; Function = "Fix-AdminShares" },
    @{ Number = 40; Function = "Fix-ServiceAccounts" },
    @{ Number = 41; Function = "Fix-DCERPCEndpoints" },
    @{ Number = 42; Function = "Fix-WinVerifyTrust" },
    @{ Number = 43; Function = "Fix-RDPCipherSuites" },
    @{ Number = 44; Function = "Fix-RDPCertificate" },
    @{ Number = 45; Function = "Fix-SMBv1Protocol" } 
    #@{ Number = 46; Function = "Fix-HTTPOptions" }
) | Sort-Object { [int]$_.Number }

# Convert SkipChecks string to array of integers
$skipCheckNumbers = @()
if ($SkipChecks) {
    # Split the string and convert each number, handling potential whitespace and invalid characters
    $skipCheckNumbers = $SkipChecks -replace '[^0-9,]', '' -split ',' | 
        Where-Object { $_ -ne '' } |
        ForEach-Object { [int]$_ }
    
    Write-Verbose "Skipping checks: $($skipCheckNumbers -join ', ')"
}

# Convert CheckOnly string to array of integers (similar to SkipChecks logic)
$checkOnlyNumbers = @()
if ($CheckOnly) {
    $checkOnlyNumbers = $CheckOnly -replace '[^0-9,]', '' -split ',' | 
        Where-Object { $_ -ne '' } |
        ForEach-Object { [int]$_ }
    
    Write-Verbose "Only running checks: $($checkOnlyNumbers -join ', ')"
}

# Add this function to handle server input processing
function Convert-ServerInput {
    param (
        [Parameter(Mandatory=$true)]
        [string[]]$InputServers
    )
    
    # Initialize array for processed servers
    $processedServers = @()
    
    foreach ($input in $InputServers) {
        # Skip empty inputs
        if ([string]::IsNullOrWhiteSpace($input)) { continue }
        
        # Check if input is a file path
        if (Test-Path $input) {
            Write-Verbose "Processing server list from file: $input"
            $processedServers += Get-Content $input | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }
        }
        # Check if input contains commas
        elseif ($input.Contains(',')) {
            Write-Verbose "Processing comma-separated server list"
            $processedServers += $input.Split(',') | 
                ForEach-Object { $_.Trim() } |
                Where-Object { -not [string]::IsNullOrWhiteSpace($_) }
        }
        else {
            Write-Verbose "Adding single server: $input"
            $processedServers += $input
        }
    }
    
    # Remove duplicates and return
    return $processedServers | Select-Object -Unique
}

# Show help if no parameters are provided
if (-not $TargetServers) {
    Show-Help
}

# Process the server input
$processedServers = Convert-ServerInput -InputServers $TargetServers
Write-Verbose "Processing servers: $($processedServers -join ', ')"

if ($processedServers.Count -eq 0) {
    Write-Error "No valid server names provided. Please check your input."
    exit 1
}

# Update the foreach loop to use processed servers
foreach ($currentServer in $processedServers) {
    Write-Host "`n=================================="
    Write-Host "Processing server: $currentServer"
    Write-Host "==================================`n"

    # Modify the output path to include server name if multiple servers
    $serverOutputPath = if ($processedServers.Count -gt 1) {
        $directory = Split-Path $OutputPath -Parent
        $filename = Split-Path $OutputPath -Leaf
        $filenameNoExt = [System.IO.Path]::GetFileNameWithoutExtension($filename)
        $extension = [System.IO.Path]::GetExtension($filename)
        Join-Path $directory "$filenameNoExt`_$($currentServer)$extension"
    } else {
        $OutputPath
    }

    # Verify server connectivity
    Write-Verbose "Testing connection to $currentServer..."
    try {
        # First test basic connectivity
        if (-not (Test-Connection -ComputerName $currentServer -Count 1 -Quiet)) {
            Write-Warning "Unable to ping $currentServer. Please verify:
            - The server name is correct
            - The server is powered on
            - Network connectivity is available
            - ICMP (ping) is not blocked by firewalls"
            continue
        }

        # Test WinRM connectivity with retry logic
        $maxRetries = 3
        $retryCount = 0
        $connected = $false

        while (-not $connected -and $retryCount -lt $maxRetries) {
            try {
                $session = New-PSSession -ComputerName $currentServer -ErrorAction Stop
                $connected = $true
                Remove-PSSession $session
                Write-Verbose "Successfully connected to $currentServer"
            }
            catch {
                $retryCount++
                if ($retryCount -lt $maxRetries) {
                    Write-Verbose "Connection attempt $retryCount failed, retrying in 5 seconds..."
                    Start-Sleep -Seconds 5
                }
                else {
                    Write-Warning "WinRM connectivity issue with $currentServer. Please verify:
                    1. WinRM service is running
                    2. Firewall allows WinRM
                    3. TrustedHosts configured
                    4. Account has proper permissions
                    Detailed error: $_"
                    continue 2
                }
            }
        }

        # Reset results arrays for this server
        $results = @()
        $warningsFound = @()

        # Run checks
        Write-Host "`nRunning security checks on $currentServer..."

        $checkCount = 1
        $totalChecks = if ($CheckOnly) {
            $checkOnlyNumbers.Count
        } else {
            ($global:checks | Where-Object { $skipCheckNumbers -notcontains $_.Number }).Count
        }

        $clearLine = " " * 120

        foreach ($check in $global:checks) {
            # Skip checks based on either SkipChecks or CheckOnly
            if ($SkipChecks -and ($skipCheckNumbers -contains [int]$check.Number)) {
                Write-Verbose "Skipping check $($check.Number): $($check.Function)"
                continue
            }
            
            if ($CheckOnly -and ($checkOnlyNumbers -notcontains [int]$check.Number)) {
                Write-Verbose "Skipping check $($check.Number): $($check.Function) (not in CheckOnly list)"
                continue
            }

            $functionDisplayName = $check.Function -replace 'Check-', ''
            Write-Host ("`rRunning check $($check.Number)" + ": $functionDisplayName...$clearLine") -NoNewline
            Write-Verbose "Running check #$($check.Number): $($check.Function)"
            
            # Pass currentServer parameter to check functions that accept it
            $result = if ((Get-Command $check.Function).Parameters.ContainsKey('ComputerName')) {
                & $check.Function -ComputerName $currentServer
            } else {
                & $check.Function
            }
            $results += $result
            
            # Store warnings for later processing
            if ($result.Status -eq "WARNING") {
                $warningsFound += @{
                    Number = $check.Number
                    Function = $check.Function
                    Details = $result.Details
                }
            }
        }

        Write-Host "`rChecks completed, generating report...$clearLine" -NoNewline
        Write-Host "`n"

        # Display results using Write-Report function
        Write-Report -Results $results -ShowWarningsOnly:$ShowWarningsOnly -OutputPath $serverOutputPath

        # Handle fixes if needed
        if ($FixWarnings -and $warningsFound.Count -gt 0) {
            Write-Host "`nAttempting to fix $($warningsFound.Count) warning(s)..."
            Handle-Fixes -WarningsFound $warningsFound -ComputerName $currentServer -Force:$Force -Verbose:$VerbosePreference
        }

    } catch {
        Write-Warning "Error processing $currentServer`: $_"
        continue
    }
}

Write-Host "`nAll servers processed."