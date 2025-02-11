<#
.SYNOPSIS
    Remotely updates Chrome and Edge browsers on specified Windows Servers.

.DESCRIPTION
    This script connects to one or more remote Windows Servers and updates both Google Chrome
    and Microsoft Edge browsers using their native updater executables.

.PARAMETER ComputerName
    A comma-delimited list of computer names or IP addresses to update.

.PARAMETER Credential
    Optional credentials for connecting to the remote computers.

.PARAMETER GetVersionsOnly
    Switch parameter to get browser versions only without performing updates.

.EXAMPLE
    .\Update-Browsers.ps1 -ComputerName "Server01"
    Updates browsers on Server01 using current user's credentials.

.EXAMPLE
    .\Update-Browsers.ps1 -ComputerName "Server01,Server02,Server03"
    Updates browsers on multiple servers using current user's credentials.

.EXAMPLE
    .\Update-Browsers.ps1 -ComputerName "Server01,Server02" -Credential (Get-Credential)
    Updates browsers on multiple servers using specified credentials.
#>

[CmdletBinding()]
param(
    [Parameter(Position=0)]
    [string]$ComputerName,
    
    [Parameter(Mandatory=$false)]
    [System.Management.Automation.PSCredential]
    [System.Management.Automation.Credential()]
    $Credential = [System.Management.Automation.PSCredential]::Empty,
    
    [Parameter(Mandatory=$false)]
    [switch]$GetVersionsOnly
)

function Show-Usage {
    Write-Host "Usage: .\Update-Browsers.ps1 -ComputerName `"Server1,Server2,Server3`" [-Credential (Get-Credential)]"
    Write-Host "`nParameters:"
    Write-Host "  -ComputerName: Required. Comma-delimited list of computer names or IP addresses"
    Write-Host "  -Credential:   Optional. Credentials for remote connection"
    Write-Host "  -GetVersionsOnly: Optional. Switch to get browser versions only without performing updates"
    Write-Host "`nExamples:"
    Write-Host "  .\Update-Browsers.ps1 -ComputerName `"Server01`""
    Write-Host "  .\Update-Browsers.ps1 -ComputerName `"Server01,Server02,Server03`""
    Write-Host "  .\Update-Browsers.ps1 -ComputerName `"Server01,Server02`" -Credential (Get-Credential)"
    exit
}

# Previous parameter block and Show-Usage function remain the same

function Get-ChromeVersion {
    param([string]$Computer)
    
    try {
        $Version = Invoke-Command -ComputerName $Computer -ScriptBlock {
            if (Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\chrome.exe") {
                $ChromePath = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\chrome.exe" -ErrorAction Stop).'(Default)'
                if ($ChromePath -and (Test-Path $ChromePath)) {
                    return (Get-Item $ChromePath).VersionInfo.ProductVersion
                }
            }
            return "Not Installed"
        } -ErrorAction Stop
        return $Version
    } catch {
        Write-Verbose "Error checking Chrome version: $_"
        return "Not Installed"
    }
}

function Get-EdgeVersion {
    param([string]$Computer)
    
    try {
        $Version = Invoke-Command -ComputerName $Computer -ScriptBlock {
            if (Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\msedge.exe") {
                $EdgePath = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\msedge.exe" -ErrorAction Stop).'(Default)'
                if ($EdgePath -and (Test-Path $EdgePath)) {
                    return (Get-Item $EdgePath).VersionInfo.ProductVersion
                }
            }
            return "Not Installed"
        } -ErrorAction Stop
        return $Version
    } catch {
        Write-Verbose "Error checking Edge version: $_"
        return "Not Installed"
    }
}

function Update-Chrome {
    param([string]$Computer)
    
    Write-Host "`nChecking Chrome on $Computer..."
    $BeforeVersion = Get-ChromeVersion -Computer $Computer
    
    if ($BeforeVersion -eq "Not Installed") {
        Write-Host "Chrome is not installed on $Computer - skipping update"
        return
    }
    
    Write-Host "Current Chrome Version: $BeforeVersion"
    
    if ($GetVersionsOnly) {
        return
    }
    
    $UpdateChromeBlock = {
        # Kill any running Chrome processes
        Write-Host "Stopping all Chrome processes..."
        Get-Process chrome -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
        cmd /c "taskkill /F /IM chrome.exe 2>nul"
        Start-Sleep -Seconds 2
        
        # Enable Chrome updates in registry for both system and user levels
        Write-Host "Enabling Chrome updates in registry..."
        try {
            # System-wide update policies
            $registryUpdates = @(
                @{
                    Path = "HKLM:\SOFTWARE\Policies\Google\Update"
                    Name = "Update{8A69D345-D564-463C-AFF1-A69D9E530F96}"
                    Value = 1
                },
                @{
                    Path = "HKLM:\SOFTWARE\Policies\Google\Update"
                    Name = "UpdateDefault"
                    Value = 1
                },
                @{
                    Path = "HKLM:\SOFTWARE\Policies\Google\Chrome"
                    Name = "ChromeCleanupEnabled"
                    Value = 1
                },
                @{
                    Path = "HKLM:\SOFTWARE\Policies\Google\Chrome"
                    Name = "MetricsReportingEnabled"
                    Value = 1
                }
            )

            foreach ($update in $registryUpdates) {
                $regPath = $update.Path
                if (!(Test-Path $regPath)) {
                    New-Item -Path $regPath -Force | Out-Null
                    Write-Host "Created registry path: $regPath"
                }
                Set-ItemProperty -Path $regPath -Name $update.Name -Value $update.Value -Type DWord -Force
                Write-Host "Set $($update.Name) in $regPath"
            }

            # Also try the direct reg.exe command
            $regCommands = @(
                'reg add "HKLM\SOFTWARE\Policies\Google\Update" /v Update{8A69D345-D564-463C-AFF1-A69D9E530F96} /d 1 /t REG_DWORD /f',
                'reg add "HKLM\SOFTWARE\Policies\Google\Update" /v UpdateDefault /d 1 /t REG_DWORD /f'
            )

            foreach ($cmd in $regCommands) {
                $result = cmd /c $cmd
                Write-Host "Registry command result: $result"
            }

            # Check installation location
            $systemInstall = Test-Path "${env:ProgramFiles}\Google\Chrome\Application\chrome.exe"
            $systemX86Install = Test-Path "${env:ProgramFiles(x86)}\Google\Chrome\Application\chrome.exe"
            $userInstall = Test-Path "$env:LOCALAPPDATA\Google\Chrome\Application\chrome.exe"

            Write-Host "Chrome installation locations:"
            Write-Host "System (64-bit): $systemInstall"
            Write-Host "System (32-bit): $systemX86Install"
            Write-Host "User: $userInstall"

            # Determine correct update path based on installation
            if ($systemInstall -or $systemX86Install) {
                Write-Host "Using system-level update approach"
                $UpdaterPath = if ($systemInstall) {
                    "${env:ProgramFiles}\Google\Update\GoogleUpdate.exe"
                } else {
                    "${env:ProgramFiles(x86)}\Google\Update\GoogleUpdate.exe"
                }
            } elseif ($userInstall) {
                Write-Host "Using user-level update approach"
                $UpdaterPath = "$env:LOCALAPPDATA\Google\Update\GoogleUpdate.exe"
            }

            Write-Host "Selected updater path: $UpdaterPath"
        } catch {
            Write-Warning "Failed to update registry: $_"
        }
        
        # Get initial version from the correct location
        $ChromePath = if ($systemInstall) {
            "${env:ProgramFiles}\Google\Chrome\Application\chrome.exe"
        } elseif ($systemX86Install) {
            "${env:ProgramFiles(x86)}\Google\Chrome\Application\chrome.exe"
        } else {
            "$env:LOCALAPPDATA\Google\Chrome\Application\chrome.exe"
        }

        $initialVersion = if (Test-Path $ChromePath) { 
            (Get-Item $ChromePath).VersionInfo.ProductVersion 
        } else { 
            "Unknown" 
        }
        
        Write-Host "Starting Chrome update process from version: $initialVersion"
        
        # Function to check version
        function Test-VersionChanged {
            $currentVersion = (Get-Item $ChromePath).VersionInfo.ProductVersion
            return $currentVersion -ne $initialVersion
        }
        
        # Function to run process with timeout
        function Start-ProcessWithTimeout {
            param($FilePath, $Arguments, $Timeout = 180)
            
            $process = Start-Process -FilePath $FilePath -ArgumentList $Arguments -PassThru
            $timeoutTimer = [System.Diagnostics.Stopwatch]::StartNew()
            
            while (-not $process.HasExited -and $timeoutTimer.Elapsed.TotalSeconds -lt $Timeout) {
                Start-Sleep -Seconds 5
                # Check if version changed while waiting
                if (Test-VersionChanged) {
                    $process | Stop-Process -Force -ErrorAction SilentlyContinue
                    return $true
                }
            }
            
            if (-not $process.HasExited) {
                Write-Host "Process timed out after $Timeout seconds, killing process..."
                $process | Stop-Process -Force -ErrorAction SilentlyContinue
            }
            return $false
        }
        
        # First, ensure we're using the correct update service
        try {
            Write-Host "Configuring Chrome update service..."
            $chromeUpdateSvc = Get-Service "gupdate" -ErrorAction SilentlyContinue
            if ($chromeUpdateSvc) {
                if ($chromeUpdateSvc.Status -ne "Running") {
                    Set-Service "gupdate" -StartupType Automatic
                    Start-Service "gupdate" -ErrorAction SilentlyContinue
                    Write-Host "Started Chrome update service"
                }
            }
        } catch {
            Write-Warning "Could not configure Chrome update service: $_"
        }

        # Try direct installer first with enterprise MSI
        try {
            Write-Host "Attempting enterprise MSI download and install..."
            $tempDir = "$env:TEMP\ChromeUpdate"
            New-Item -ItemType Directory -Force -Path $tempDir | Out-Null
            $installerPath = "$tempDir\chrome_enterprise.msi"
            
            # Download enterprise MSI
            $url = "https://dl.google.com/chrome/install/GoogleChromeStandaloneEnterprise64.msi"
            [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
            Write-Host "Downloading Chrome Enterprise MSI..."
            Invoke-WebRequest -Uri $url -OutFile $installerPath
            
            if (Test-Path $installerPath) {
                Write-Host "Installing Chrome Enterprise MSI..."
                $process = Start-Process -FilePath "msiexec.exe" -ArgumentList "/i `"$installerPath`" /qn /norestart" -Wait -PassThru
                Write-Host "MSI installer completed with exit code: $($process.ExitCode)"
                Start-Sleep -Seconds 30
                
                if (Test-VersionChanged) {
                    Remove-Item -Path $tempDir -Recurse -Force -ErrorAction SilentlyContinue
                    return @{ Success = $true; InitialVersion = $initialVersion; FinalVersion = (Get-Item $ChromePath).VersionInfo.ProductVersion }
                }
            }
        } catch {
            Write-Warning "Failed to install Chrome Enterprise MSI: $_"
        } finally {
            Remove-Item -Path $tempDir -Recurse -Force -ErrorAction SilentlyContinue
        }

        # If MSI fails, try Google Update with enhanced logging
        $UpdaterPath = "${env:ProgramFiles(x86)}\Google\Update\GoogleUpdate.exe"
        if (Test-Path $UpdaterPath) {
            Write-Host "Running Google Updater with enhanced logging..."
            
            # Create log directory
            $logDir = "$env:TEMP\ChromeUpdateLogs"
            New-Item -ItemType Directory -Force -Path $logDir | Out-Null
            $logFile = "$logDir\chrome_update.log"
            
            # Run updater with logging
            $updateArgs = @(
                "/ua",
                "/installsource scheduler",
                "/log=$logFile"
            )
            
            Write-Host "Running update with arguments: $($updateArgs -join ' ')"
            $process = Start-Process -FilePath $UpdaterPath -ArgumentList $updateArgs -Wait -PassThru
            Write-Host "Update process completed with exit code: $($process.ExitCode)"
            
            if (Test-Path $logFile) {
                Write-Host "Update log contents:"
                Get-Content $logFile | ForEach-Object { Write-Host "  $_" }
            }
            
            Start-Sleep -Seconds 30
            
            if (Test-VersionChanged) {
                Remove-Item -Path $logDir -Recurse -Force -ErrorAction SilentlyContinue
                return @{ Success = $true; InitialVersion = $initialVersion; FinalVersion = (Get-Item $ChromePath).VersionInfo.ProductVersion }
            }
            
            Remove-Item -Path $logDir -Recurse -Force -ErrorAction SilentlyContinue
        }

        # If all else fails, try to download and run the latest standalone installer
        try {
            Write-Host "Attempting standalone installer download..."
            $tempDir = "$env:TEMP\ChromeUpdate"
            New-Item -ItemType Directory -Force -Path $tempDir | Out-Null
            $installerPath = "$tempDir\ChromeStandaloneSetup64.exe"
            
            $url = "https://dl.google.com/chrome/install/ChromeStandaloneSetup64.exe"
            [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
            Invoke-WebRequest -Uri $url -OutFile $installerPath
            
            if (Test-Path $installerPath) {
                Write-Host "Running standalone installer..."
                $process = Start-Process -FilePath $installerPath -ArgumentList "/silent /install" -Wait -PassThru
                Write-Host "Standalone installer completed with exit code: $($process.ExitCode)"
                Start-Sleep -Seconds 30
                
                if (Test-VersionChanged) {
                    Remove-Item -Path $tempDir -Recurse -Force -ErrorAction SilentlyContinue
                    return @{ Success = $true; InitialVersion = $initialVersion; FinalVersion = (Get-Item $ChromePath).VersionInfo.ProductVersion }
                }
            }
        } catch {
            Write-Warning "Failed to install Chrome standalone installer: $_"
        } finally {
            Remove-Item -Path $tempDir -Recurse -Force -ErrorAction SilentlyContinue
        }

        Write-Host "No version change detected after all update attempts"
        return @{
            Success = $false
            InitialVersion = $initialVersion
            FinalVersion = (Get-Item $ChromePath).VersionInfo.ProductVersion
        }
    }
    
    try {
        Write-Host "Executing update process on $Computer..."
        $result = Invoke-Command -ComputerName $Computer -ScriptBlock $UpdateChromeBlock
        
        if ($result.Success) {
            Write-Host "Chrome successfully updated from $($result.InitialVersion) to $($result.FinalVersion)" -ForegroundColor Green
        } else {
            Write-Host "Attempting final version check..." -ForegroundColor Yellow
            Start-Sleep -Seconds 10
            $FinalCheck = Get-ChromeVersion -Computer $Computer
            if ($FinalCheck -ne $BeforeVersion) {
                Write-Host "Final check shows Chrome updated to: $FinalCheck" -ForegroundColor Green
            } else {
                Write-Host "No update was applied (current version: $FinalCheck)" -ForegroundColor Yellow
                Write-Host "You may need to run the update again or check if updates are blocked by policy" -ForegroundColor Yellow
            }
        }
    } catch {
        $errorMessage = $_.Exception.Message
        Write-Error "Failed to update Chrome: $errorMessage"
    }
}

function Update-Edge {
    param([string]$Computer)
    
    Write-Host "`nChecking Edge on $Computer..."
    $BeforeVersion = Get-EdgeVersion -Computer $Computer
    
    if ($BeforeVersion -eq "Not Installed") {
        Write-Host "Edge is not installed on $Computer - skipping update"
        return
    }
    
    Write-Host "Current Edge Version: $BeforeVersion"
    
    if ($GetVersionsOnly) {
        return
    }
    
    $UpdateEdgeBlock = {
        # Kill any running Edge processes
        Write-Host "Stopping all Edge processes..."
        Get-Process msedge -ErrorAction SilentlyContinue | ForEach-Object {
            try {
                $_ | Stop-Process -Force
                Write-Host "Stopped Edge process with PID: $($_.Id)"
            } catch {
                Write-Warning "Failed to stop Edge process with PID $($_.Id): $_"
            }
        }
        Start-Sleep -Seconds 2  # Give processes time to fully stop
        
        # Double-check no Edge processes are running
        $remainingProcesses = Get-Process msedge -ErrorAction SilentlyContinue
        if ($remainingProcesses) {
            Write-Warning "Some Edge processes could not be stopped. Attempting forceful termination..."
            cmd /c "taskkill /F /IM msedge.exe 2>nul"
            Start-Sleep -Seconds 2
        }
        
        # Trigger Edge update
        $EdgePath = "${env:ProgramFiles(x86)}\Microsoft\Edge\Application\msedge.exe"
        if (Test-Path $EdgePath) {
            Write-Host "Triggering Edge update..."
            try {
                Start-Process $EdgePath -ArgumentList "--update" -Wait -NoNewWindow
                Write-Host "Edge update command completed"
                
                # Wait a bit for update to process
                Start-Sleep -Seconds 30
                
                # Check if version changed
                $newVersion = (Get-Item $EdgePath).VersionInfo.ProductVersion
                Write-Host "Edge version after update attempt: $newVersion"
            } catch {
                Write-Error "Failed to execute Edge update command: $_"
            }
        } else {
            Write-Error "Edge executable not found at expected location: $EdgePath"
        }
    }
    
    try {
        Write-Host "Executing update process on $Computer..."
        Invoke-Command -ComputerName $Computer -ScriptBlock $UpdateEdgeBlock
        
        # Final version check
        Start-Sleep -Seconds 5
        $AfterVersion = Get-EdgeVersion -Computer $Computer
        
        if ($AfterVersion -ne $BeforeVersion) {
            Write-Host "Edge successfully updated from $BeforeVersion to $AfterVersion" -ForegroundColor Green
        } else {
            Write-Host "Edge version remained at $AfterVersion - this is normal if no update was available" -ForegroundColor Yellow
        }
    } catch {
        $errorMessage = $_.Exception.Message
        Write-Error "Failed to update Edge: $errorMessage"
    }
}

# Show usage if ComputerName is not provided
if ([string]::IsNullOrEmpty($ComputerName)) {
    Show-Usage
}

# Convert comma-delimited string to array and trim whitespace
$Computers = $ComputerName.Split(',') | ForEach-Object { $_.Trim() }

# Validate computer names
$Computers | ForEach-Object {
    if ($_ -notmatch "^[a-zA-Z0-9.-]+$") {
        Write-Error "Invalid computer name format: $_"
        exit
    }
}

# Main execution
foreach ($Computer in $Computers) {
    Write-Host "`n=== Processing $Computer ===" -ForegroundColor Cyan
    
    try {
        Write-Host "Testing connection to $Computer..."
        if (Test-Connection -ComputerName $Computer -Count 1 -Quiet) {
            if ($GetVersionsOnly) {
                Write-Host "`nGetting browser versions for $Computer..." -ForegroundColor Yellow
                $ChromeVersion = Get-ChromeVersion -Computer $Computer
                $EdgeVersion = Get-EdgeVersion -Computer $Computer
                
                Write-Host ("`nBrowser Versions on {0}:" -f $Computer) -ForegroundColor Cyan
                Write-Host "Chrome: $ChromeVersion"
                Write-Host "Edge: $EdgeVersion"
                continue
            }
            
            if ($Credential -ne [System.Management.Automation.PSCredential]::Empty) {
                Update-Chrome -Computer $Computer
                Update-Edge -Computer $Computer
            } else {
                Update-Chrome -Computer $Computer
                Update-Edge -Computer $Computer
            }
        } else {
            Write-Error "Unable to connect to $Computer. Please verify the computer name and network connectivity."
            continue
        }
    } catch {
        $errorMessage = $_.Exception.Message
        Write-Error "Script execution failed for $Computer : $errorMessage"
        continue
    }
}
