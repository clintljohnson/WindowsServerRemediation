function Fix-AccountLockoutSettings {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [string]$ComputerName
    )

    <# 
    .SYNOPSIS
        Configures account lockout settings to meet security requirements.
    .DESCRIPTION
        Modifies the following settings:
        - Lockout duration: Set to 30 minutes
        - Lockout threshold: Set to 3 failed attempts
        - Lockout observation window: Set to 30 minutes
    #>

    Write-Verbose "Starting fix operation for Account Lockout Settings on $ComputerName"

    try {
        # First check current state
        $currentState = Check-AccountLockoutSettings -ComputerName $ComputerName
        if ($currentState.Status -eq "OK") {
            Write-Verbose "No fix needed - current settings are compliant"
            return $true
        }

        # Use Invoke-Command for remote execution
        $result = Invoke-Command -ComputerName $ComputerName -ScriptBlock {
            $success = $true
            $changes = @()

            try {
                Write-Verbose "Setting lockout duration to 30 minutes"
                $result1 = net accounts /lockoutduration:30
                if ($LASTEXITCODE -eq 0) {
                    $changes += "Lockout duration set to 30 minutes"
                } else {
                    $success = $false
                    Write-Warning "Failed to set lockout duration"
                }
                
                Write-Verbose "Setting lockout threshold to 3 attempts"
                $result2 = net accounts /lockoutthreshold:3
                if ($LASTEXITCODE -eq 0) {
                    $changes += "Lockout threshold set to 3 attempts"
                } else {
                    $success = $false
                    Write-Warning "Failed to set lockout threshold"
                }
                
                Write-Verbose "Setting lockout observation window to 30 minutes"
                $result3 = net accounts /lockoutwindow:30
                if ($LASTEXITCODE -eq 0) {
                    $changes += "Lockout window set to 30 minutes"
                } else {
                    $success = $false
                    Write-Warning "Failed to set lockout window"
                }

                return @{
                    Success = $success
                    Changes = $changes
                }
            }
            catch {
                Write-Error "Failed to apply fix: $_"
                return @{
                    Success = $false
                    Changes = $changes
                }
            }
        }

        if ($result.Success) {
            Write-Host "Successfully configured account lockout settings:" -ForegroundColor Green
            foreach ($change in $result.Changes) {
                Write-Host "- $change" -ForegroundColor Green
            }
            
            # Verify the fix
            $verifyResult = Check-AccountLockoutSettings -ComputerName $ComputerName
            
            if ($verifyResult.Status -eq "OK") {
                Write-Verbose "Verification passed"
                return $true
            }
            else {
                Write-Warning "Fix applied but verification failed: $($verifyResult.Details)"
                return $false
            }
        }
        
        Write-Warning "Failed to apply account lockout settings"
        return $false
    }
    catch {
        Write-Error "Error in fix operation: $_"
        return $false
    }
} 