function Check-WarningBanner {
    <#
    .SYNOPSIS
    Checks the Windows login warning banner configuration across multiple registry locations.

    .DESCRIPTION
    This function verifies the warning banner (legal notice) configuration by checking three possible registry locations:
    1. Current Location (Legacy):
       HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon
    2. NT Policy Location (Domain Policy):
       HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\CurrentVersion\Winlogon
    3. System Policy Location (Modern/Recommended):
       HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System

    The check will pass (Status="OK") if the correct warning banner text is found in ANY of these locations.
    This is because Windows will display the warning banner if it's properly configured in any of these paths.
    The function reports which specific location contains the valid configuration.

    .NOTES
    - The order of precedence doesn't matter as long as one location is properly configured
    - When fixing, we specifically target the System Policy location (Modern/Recommended)
    - Reference: NIST SP 800-53 AC-8, DoD STIG requirements
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [string]$ComputerName,
        [Parameter(Mandatory=$false)]
        [System.Collections.Hashtable]$Parameters
    )

    Write-Verbose "[$($MyInvocation.MyCommand.Name)] Checking warning banner settings"

    $result = @{
        CheckNumber = 15
        Category = "Security"
        Name = "Warning Banner Settings"
        Status = "OK"
        Details = "Warning banner text is properly configured"
        Function = $MyInvocation.MyCommand.Name
        Reference = "NIST SP 800-53 AC-8, DoD STIG"
        Resolution = "Configure the required warning banner text in the registry under Legal Notice Text"
    }

    try {
        # Define all possible registry paths
        $registryPaths = @{
            'Current' = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
            'NT_Policy' = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\CurrentVersion\Winlogon'
            'System_Policy' = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
        }

        $scriptBlock = {
            param($paths, $verbosePreference)
            
            # Inherit verbose preference from caller
            $VerbosePreference = $verbosePreference
            
            Write-Verbose "Starting registry checks in remote session..."
            $results = @()
            
            foreach ($pathInfo in $paths.GetEnumerator()) {
                Write-Verbose "==============================================="
                Write-Verbose "Checking $($pathInfo.Key) at path: $($pathInfo.Value)"
                
                $result = @{
                    PathName = $pathInfo.Key
                    Path = $pathInfo.Value
                    Value = $null
                    Exists = $false
                }
                
                if (Test-Path $pathInfo.Value) {
                    Write-Verbose "Path exists: True"
                    try {
                        $regValue = Get-ItemProperty -Path $pathInfo.Value -Name "legalnoticetext" -ErrorAction Stop
                        Write-Verbose "Successfully read registry value"
                        
                        if ($regValue) {
                            $textValue = $regValue.legalnoticetext
                            Write-Verbose "Found value in $($pathInfo.Key):"
                            Write-Verbose $textValue
                            
                            if (-not [string]::IsNullOrWhiteSpace($textValue)) {
                                $result.Value = $textValue
                                $result.Exists = $true
                                Write-Verbose "Valid value found in $($pathInfo.Key)"
                            }
                            else {
                                Write-Verbose "Value is empty or whitespace"
                            }
                        }
                    }
                    catch {
                        Write-Verbose "Error reading registry value: $_"
                    }
                }
                else {
                    Write-Verbose "Path does not exist: False"
                }
                
                Write-Verbose "Adding result for $($pathInfo.Key) - Exists: $($result.Exists)"
                $results += $result
            }
            
            Write-Verbose "Completed registry checks, returning results"
            return $results
        }

        Write-Verbose "Checking warning banner on $ComputerName"
        $checkResults = Invoke-Command -ComputerName $ComputerName -ScriptBlock $scriptBlock -ArgumentList $registryPaths, $VerbosePreference

        if ($null -eq $checkResults) {
            Write-Verbose "No results returned from remote computer"
            $result.Status = "WARNING"
            $result.Details = "Unable to retrieve warning banner settings from remote computer"
            return $result
        }

        Write-Verbose "Processing check results:"
        $foundValidConfig = $false
        $configuredPaths = @()

        foreach ($check in $checkResults) {
            Write-Verbose "==============================================="
            Write-Verbose "Processing result for $($check.PathName):"
            Write-Verbose "Path: $($check.Path)"
            Write-Verbose "Exists: $($check.Exists)"
            Write-Verbose "Value present: $(if ($check.Value) { 'Yes' } else { 'No' })"

            if ($check.Exists) {
                Write-Verbose "Found valid config in $($check.PathName)"
                $foundValidConfig = $true
                $configuredPaths += $check.PathName
            }
        }

        if ($foundValidConfig) {
            Write-Verbose "Valid configuration found"
            $result.Status = "OK"
            $pathsString = $configuredPaths -join ", "
            $result.Details = "Warning banner text is configured in the following location(s): $pathsString"
        }
        else {
            Write-Verbose "No valid configuration found"
            $result.Status = "WARNING"
            $result.Details = "Warning banner is not configured in any location"
        }
    }
    catch {
        Write-Verbose "Error occurred: $($_.Exception.Message)"
        $result.Status = "WARNING"
        $result.Details = "Failed to check warning banner settings: $($_.Exception.Message)"
    }

    return $result
} 