function Fix-SMBv1Protocol {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [string]$ComputerName
    )

    Write-Verbose "Starting SMBv1 protocol remediation on $ComputerName"

    try {
        # First verify current state
        $currentState = Check-SMBv1Protocol -ComputerName $ComputerName
        
        if ($currentState.Status -eq "OK") {
            Write-Verbose "SMBv1 protocol is already properly configured"
            return $true
        }

        $result = Invoke-Command -ComputerName $ComputerName -ScriptBlock {
            $success = $true
            $messages = @()
            $errors = @()

            # Function to safely set registry values
            function Set-RegistryValue {
                param (
                    [string]$Path,
                    [string]$Name,
                    [int]$Value,
                    [string]$Type
                )
                
                try {
                    if (-not (Test-Path $Path)) {
                        New-Item -Path $Path -Force | Out-Null
                        $script:messages += "Created registry path: $Path"
                    }
                    
                    Set-ItemProperty -Path $Path -Name $Name -Value $Value -Type $Type -Force -ErrorAction Stop
                    $script:messages += "Successfully set $Path\$Name to $Value"
                    return $true
                }
                catch {
                    $errorMessage = if ($_.Exception.Message) { $_.Exception.Message } else { "Unknown error occurred" }
                    $script:errors += "Failed to set $Path\$Name`: $errorMessage"
                    return $false
                }
            }

            try {
                # Disable SMBv1 Windows Feature
                Write-Verbose "Disabling SMBv1 Windows Feature..."
                try {
                    $feature = Get-WindowsOptionalFeature -Online -FeatureName "SMB1Protocol" -ErrorAction Stop
                    if ($feature.State -eq "Enabled") {
                        Disable-WindowsOptionalFeature -Online -FeatureName "SMB1Protocol" -NoRestart -ErrorAction Stop
                        $messages += "Successfully disabled SMBv1 Windows Feature"
                    }
                    else {
                        $messages += "SMBv1 Windows Feature is already disabled"
                    }
                }
                catch {
                    $errorMessage = if ($_.Exception.Message) { $_.Exception.Message } else { $_.Exception.ToString() }
                    $errors += "Error managing SMBv1 Windows Feature: $errorMessage"
                    $success = $false
                }

                # Configure registry settings
                $regSettings = @(
                    @{
                        Path = "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters"
                        Name = "SMB1"
                        Value = 0
                        Type = "DWord"
                    },
                    @{
                        Path = "HKLM:\SYSTEM\CurrentControlSet\Services\mrxsmb10"
                        Name = "Start"
                        Value = 4
                        Type = "DWord"
                    }
                )

                foreach ($setting in $regSettings) {
                    if (-not (Set-RegistryValue @setting)) {
                        $success = $false
                    }
                }
            }
            catch {
                $success = $false
                $errorMessage = if ($_.Exception.Message) { $_.Exception.Message } else { $_.Exception.ToString() }
                $errors += "Unexpected error: $errorMessage"
            }

            return @{
                Success = $success
                Messages = $messages
                Errors = $errors
            }
        }

        # Log all messages and errors
        foreach ($message in $result.Messages) {
            Write-Verbose $message
        }
        foreach ($error in $result.Errors) {
            Write-Warning $error
        }

        if ($result.Success) {
            Write-Host "Successfully configured SMBv1 protocol settings" -ForegroundColor Green
            
            # Verify the fix
            $verifyResult = Check-SMBv1Protocol -ComputerName $ComputerName
            if ($verifyResult.Status -eq "OK") {
                Write-Verbose "Verification passed"
                Write-Warning "A system restart may be required for all changes to take effect"
                return $true
            }
            else {
                Write-Warning "Fix applied but verification failed: $($verifyResult.Details)"
                return $false
            }
        }
        
        Write-Warning "Failed to fully configure SMBv1 protocol settings"
        return $false
    }
    catch {
        # Modified error handling to ensure we never pass null to Write-Error
        $errorMessage = "Error in SMBv1 protocol remediation"
        if ($_.Exception.Message) { 
            $errorMessage += ": " + $_.Exception.Message
        } elseif ($_.Exception) { 
            $errorMessage += ": " + $_.Exception.ToString()
        } else { 
            $errorMessage += " (no additional details available)"
        }
        
        # Use Write-Warning instead of Write-Error to avoid parameter binding issues
        Write-Warning $errorMessage
        return $false
    }
} 